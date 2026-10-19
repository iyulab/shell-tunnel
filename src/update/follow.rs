//! Following the relay's version: the orchestration on top of `state`,
//! `stage` and `swap`.
//!
//! Two halves, one per side of a restart:
//!
//! - [`on_start`] and [`probation`] run in the binary that was just swapped
//!   in. `on_start` counts the start and, if the previous one died before it
//!   could attach, puts the old binary back before anything is served.
//!   `probation` then watches the first attach and decides whether the update
//!   took.
//! - [`follow`] runs for the life of the process. When the relay announces a
//!   newer version it stages that release, waits until the server has been
//!   idle for a while, latches it shut, swaps the binary and restarts.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{info, warn};

use super::stage::{self, StageError};
use super::state::{self, Pending, ProbationObservation, UpdateState, Verdict};
use super::swap;
use crate::api::activity::{is_idle, latch_if_idle};
use crate::api::AppState;
use crate::audit::{AuditEvent, AuditSink};
use crate::relay::client::AttachEvent;
use crate::ShellTunnelError;

/// How long to wait before following a version again after a failure.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(6 * 3600);
/// How long to wait for a release the relay names but GitHub does not have yet.
const RETRY_NOT_YET_RELEASED: Duration = Duration::from_secs(3600);
/// How often idleness is sampled while waiting for it.
const IDLE_POLL: Duration = Duration::from_secs(1);

/// The timings of following an update.
#[derive(Debug, Clone)]
pub struct FollowConfig {
    /// How long the server must stay idle, continuously, before the swap.
    pub quiet: Duration,
    /// Upper bound of the random delay after that, so a fleet upgraded by one
    /// relay restart does not restart all at once.
    pub jitter_max: Duration,
    /// How long a freshly swapped-in binary has to attach before it is judged.
    pub probation: Duration,
    /// Where releases are downloaded from.
    pub base_url: String,
}

impl Default for FollowConfig {
    fn default() -> Self {
        with_test_timings(Self {
            quiet: Duration::from_secs(60),
            jitter_max: Duration::from_secs(300),
            probation: Duration::from_secs(90),
            base_url: stage::base_url(),
        })
    }
}

#[cfg(not(debug_assertions))]
fn with_test_timings(cfg: FollowConfig) -> FollowConfig {
    cfg
}

/// `SHELL_TUNNEL_UPDATE_TIMINGS=quiet_ms,jitter_ms,probation_ms` — end-to-end
/// tests only; a release build has no such variable.
#[cfg(debug_assertions)]
fn with_test_timings(mut cfg: FollowConfig) -> FollowConfig {
    if let Ok(t) = std::env::var("SHELL_TUNNEL_UPDATE_TIMINGS") {
        let ms: Vec<u64> = t.split(',').filter_map(|v| v.trim().parse().ok()).collect();
        if let [q, j, p] = ms[..] {
            cfg.quiet = Duration::from_millis(q);
            cfg.jitter_max = Duration::from_millis(j);
            cfg.probation = Duration::from_millis(p);
        }
    }
    cfg
}

/// The version this binary counts as its own when deciding whether to follow.
pub fn current_version() -> String {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var("SHELL_TUNNEL_UPDATE_PRETEND_VERSION") {
        return v;
    }
    env!("CARGO_PKG_VERSION").to_string()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn exe_dir(exe: &Path) -> &Path {
    exe.parent().unwrap_or(Path::new("."))
}

/// Load the state, treating an unreadable file as empty — and saying so. A
/// device must not refuse to start over its update bookkeeping.
fn load(dir: &Path) -> UpdateState {
    state::load(dir).unwrap_or_else(|e| {
        warn!(
            "update state in {} is unreadable ({e}); starting from none",
            dir.display()
        );
        UpdateState::default()
    })
}

fn store(dir: &Path, s: &UpdateState) {
    if let Err(e) = state::store(dir, s) {
        warn!("could not write the update state in {}: {e}", dir.display());
    }
}

/// Count this start against a pending update, before anything is served.
///
/// Returns the pending update when this binary is on probation. If a previous
/// start of the same update already died before attaching, this one would
/// too: the old binary is put back and the process restarts into it — the
/// returned error is that restart's (Windows), or its failure (Unix).
pub async fn on_start(
    exe: &Path,
    audit: &Arc<AuditSink>,
) -> Result<Option<Pending>, ShellTunnelError> {
    let dir = exe_dir(exe);
    let mut st = load(dir);
    let Some(mut pending) = st.pending.take() else {
        return Ok(None);
    };
    pending.attempts += 1;
    if pending.attempts < 2 {
        st.pending = Some(pending.clone());
        store(dir, &st);
        return Ok(Some(pending));
    }
    let verdict = state::judge(&ProbationObservation::PriorStartDied);
    roll_back(
        exe,
        &pending,
        verdict,
        "the new binary did not survive to attach",
        st,
        audit,
    )
    .await
    .map(|()| None)
}

/// Watch the first attach of a freshly swapped-in binary and settle it.
///
/// `Ok` once the update is judged applied (or not the new binary's fault),
/// carrying the enrolment it saw so [`follow`] can act on it: that attach is
/// also where the relay says its version, and a relay upgraded while this
/// binary was on probation would otherwise be followed only one re-attach
/// later. Otherwise the old binary is restored and the restart's error
/// returned.
pub async fn probation(
    exe: &Path,
    pending: Pending,
    events: &mut UnboundedReceiver<AttachEvent>,
    cfg: &FollowConfig,
    audit: &Arc<AuditSink>,
) -> Result<Option<AttachEvent>, ShellTunnelError> {
    let deadline = tokio::time::Instant::now() + cfg.probation;
    let mut refused_credential = false;
    let mut enrolment = None;
    let observation = loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(event @ AttachEvent::Enrolled { .. })) => {
                enrolment = Some(event);
                break ProbationObservation::Enrolled;
            }
            Ok(Some(AttachEvent::Rejected { code })) => {
                let obs = ProbationObservation::Rejected(code);
                if state::judge(&obs) == Verdict::KeepWaiting {
                    refused_credential = true;
                    continue;
                }
                break obs;
            }
            // The client ended, or the window closed without an attach.
            Ok(None) | Err(_) if refused_credential => {
                // The relay refused the credential over a healthy connection:
                // the new binary reached it and spoke the protocol, so rolling
                // back would change nothing.
                break ProbationObservation::Enrolled;
            }
            Ok(None) | Err(_) => break ProbationObservation::Unreachable,
        }
    };

    let dir = exe_dir(exe);
    let mut st = load(dir);
    st.pending = None;
    match state::judge(&observation) {
        Verdict::Applied | Verdict::KeepWaiting => {
            store(dir, &st);
            info!("update {} -> {} applied", pending.from, pending.to);
            audit
                .record_async(
                    AuditEvent::new("update.applied").with_update(&pending.from, &pending.to),
                )
                .await;
            Ok(enrolment)
        }
        verdict => {
            let why = match &observation {
                ProbationObservation::Rejected(code) => format!("the relay refused it: {code}"),
                _ => format!(
                    "it did not attach to the relay within {}s",
                    cfg.probation.as_secs()
                ),
            };
            roll_back(exe, &pending, verdict, &why, st, audit)
                .await
                .map(|()| None)
        }
    }
}

/// Put the previous binary back, record why, and restart into it.
///
/// The error is the restart's. `Ok` means the previous binary could not be put
/// back: there is nothing better to restart into, so this process — the one
/// that just failed its probation — keeps running, and says so.
async fn roll_back(
    exe: &Path,
    pending: &Pending,
    verdict: Verdict,
    why: &str,
    mut st: UpdateState,
    audit: &Arc<AuditSink>,
) -> Result<(), ShellTunnelError> {
    let dir = exe_dir(exe);
    st.pending = None;
    if verdict == Verdict::RollBackAndAbandon {
        if !st.abandoned.contains(&pending.to) {
            st.abandoned.push(pending.to.clone());
        }
    } else {
        st.retry_not_before_ms = Some(now_ms() + RETRY_AFTER_FAILURE.as_millis() as u64);
    }
    warn!(
        "update {} -> {} rolled back: {why}",
        pending.from, pending.to
    );
    store(dir, &st);
    if let Err(e) = swap::restore(exe, &pending.prev_path) {
        let reason = format!(
            "{why}; restoring {} failed: {e}",
            pending.prev_path.display()
        );
        warn!(
            "update {} -> {}: {reason}; keeping this binary",
            pending.from, pending.to
        );
        audit
            .record_async(
                AuditEvent::new("update.failed")
                    .with_update(&pending.from, &pending.to)
                    .with_reason(reason),
            )
            .await;
        return Ok(());
    }
    audit
        .record_async(
            AuditEvent::new("update.rolled-back")
                .with_update(&pending.from, &pending.to)
                .with_reason(why),
        )
        .await;
    Err(restart(exe))
}

/// Follow the relay's version for the life of the process.
///
/// `first` is an attach outcome already taken off `events` — the one
/// [`probation`] judged — handled before anything newer.
///
/// Returns only when the process must end: after a swap, with the restart's
/// error (Windows), or if the event stream closes for good.
pub async fn follow(
    state: AppState,
    exe: PathBuf,
    mut events: UnboundedReceiver<AttachEvent>,
    cfg: FollowConfig,
    first: Option<AttachEvent>,
) -> ShellTunnelError {
    let current = current_version();
    let dir = exe_dir(&exe).to_path_buf();
    let mut announced: Option<String> = None;
    let mut next = first;
    loop {
        let event = match next.take() {
            Some(event) => event,
            None => match events.recv().await {
                Some(event) => event,
                None => break,
            },
        };
        let AttachEvent::Enrolled {
            relay_version: Some(relay),
            ..
        } = event
        else {
            continue;
        };
        let mut st = load(&dir);
        if !state::should_follow(&current, &relay, &st, now_ms()) {
            continue;
        }
        if announced.as_deref() != Some(relay.as_str()) {
            info!("relay version {relay} is newer than this build; will update when idle");
            state
                .audit
                .record_async(AuditEvent::new("update.available").with_update(&current, &relay))
                .await;
            announced = Some(relay.clone());
        }

        let staged = match stage_on_a_thread(&relay, &exe, &cfg.base_url).await {
            Ok(staged) => staged,
            Err(e) => {
                let (retry, reason) = match &e {
                    StageError::NotYetReleased => {
                        (RETRY_NOT_YET_RELEASED, "not-yet-released".to_string())
                    }
                    other => (RETRY_AFTER_FAILURE, describe(other)),
                };
                st.retry_not_before_ms = Some(now_ms() + retry.as_millis() as u64);
                // A release still missing is reported once per version, not
                // once an hour.
                let report = !matches!(e, StageError::NotYetReleased)
                    || !st.failed_reported.contains(&relay);
                if report {
                    if matches!(e, StageError::NotYetReleased) {
                        st.failed_reported.push(relay.clone());
                    }
                    warn!("cannot update to {relay}: {reason}");
                    state
                        .audit
                        .record_async(
                            AuditEvent::new("update.failed")
                                .with_update(&current, &relay)
                                .with_reason(reason),
                        )
                        .await;
                }
                store(&dir, &st);
                continue;
            }
        };

        wait_until_latched(&state, &cfg, &current, &relay).await;
        state
            .audit
            .record_async(AuditEvent::new("update.applying").with_update(&current, &relay))
            .await;
        let prev = match swap::swap_in(&exe, &staged.binary) {
            Ok(prev) => prev,
            Err(e) => {
                state.activity.unlatch();
                let _ = std::fs::remove_file(&staged.binary);
                st.retry_not_before_ms = Some(now_ms() + RETRY_AFTER_FAILURE.as_millis() as u64);
                store(&dir, &st);
                warn!("cannot update to {relay}: swapping the binary failed: {e}");
                state
                    .audit
                    .record_async(
                        AuditEvent::new("update.failed")
                            .with_update(&current, &relay)
                            .with_reason(format!("swap: {e}")),
                    )
                    .await;
                continue;
            }
        };
        st.pending = Some(Pending {
            from: current.clone(),
            to: relay.clone(),
            prev_path: prev.clone(),
            attempts: 0,
            written_at_ms: now_ms(),
        });
        if let Err(e) = state::store(&dir, &st) {
            // Without the record a failed start could not be rolled back, so
            // the swap is undone rather than trusted.
            let _ = swap::restore(&exe, &prev);
            state.activity.unlatch();
            warn!("cannot update to {relay}: the update state could not be written: {e}");
            state
                .audit
                .record_async(
                    AuditEvent::new("update.failed")
                        .with_update(&current, &relay)
                        .with_reason(format!("state: {e}")),
                )
                .await;
            continue;
        }
        info!("updating {current} -> {relay}; restarting");
        return restart(&exe);
    }
    ShellTunnelError::Update("the relay client's event stream ended".to_string())
}

/// Wait until the server has been idle for `cfg.quiet` without a break, then
/// the random delay, then latch it. Loops until a latch succeeds.
///
/// A running background process holds this off for as long as it runs, which
/// can be days — a dev server started through `/api/v1/processes` never ends on
/// its own. That wait is deliberate (a restart would end the process), but it
/// must not be silent: the first time one is seen holding the update, an
/// `update.waiting` line says why the device is still on its old version.
async fn wait_until_latched(state: &AppState, cfg: &FollowConfig, from: &str, to: &str) {
    let mut told = false;
    loop {
        let mut idle_since: Option<tokio::time::Instant> = None;
        loop {
            let now = tokio::time::Instant::now();
            if !told && state.processes.running_count() > 0 {
                told = true;
                info!("update to {to} is waiting for background processes to end");
                state
                    .audit
                    .record_async(
                        AuditEvent::new("update.waiting")
                            .with_update(from, to)
                            .with_reason("processes-running"),
                    )
                    .await;
            }
            if is_idle(state) {
                let since = *idle_since.get_or_insert(now);
                if now - since >= cfg.quiet {
                    break;
                }
            } else {
                idle_since = None;
            }
            tokio::time::sleep(IDLE_POLL.min(cfg.quiet.max(Duration::from_millis(50)))).await;
        }
        tokio::time::sleep(jitter(cfg.jitter_max)).await;
        if latch_if_idle(state) {
            return;
        }
    }
}

fn jitter(max: Duration) -> Duration {
    let mut bytes = [0u8; 8];
    if max.is_zero() || getrandom::fill(&mut bytes).is_err() {
        return Duration::ZERO;
    }
    let ms = max.as_millis() as u64;
    Duration::from_millis(u64::from_le_bytes(bytes) % (ms + 1))
}

/// `stage` is blocking and builds a blocking HTTP client, which panics on a
/// thread that belongs to a runtime — `spawn_blocking` included — so it gets
/// a thread of its own.
async fn stage_on_a_thread(
    version: &str,
    exe: &Path,
    base_url: &str,
) -> Result<stage::Staged, StageError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (version, exe, base_url) = (version.to_string(), exe.to_path_buf(), base_url.to_string());
    std::thread::spawn(move || {
        let _ = tx.send(stage::stage(&version, &exe, &base_url));
    });
    rx.await
        .unwrap_or_else(|_| Err(StageError::Download("the staging thread panicked".into())))
}

fn describe(e: &StageError) -> String {
    match e {
        StageError::NotYetReleased => "not-yet-released".to_string(),
        StageError::Download(m) => format!("download: {m}"),
        StageError::Checksum => "checksum: the archive does not match SHA256SUMS".to_string(),
        StageError::Signature(m) => format!("signature: {m}"),
        StageError::TrialRun(m) => format!("trial run: {m}"),
    }
}

/// [`swap::restart`], after dropping what only a debug build's test set.
fn restart(exe: &Path) -> ShellTunnelError {
    // The restarted image must see its real version, or it would follow the
    // relay again forever.
    #[cfg(debug_assertions)]
    std::env::remove_var("SHELL_TUNNEL_UPDATE_PRETEND_VERSION");
    swap::restart(exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::processes::StartRequest;

    /// A running background process holds the latch off, and says so once —
    /// then the update proceeds the moment it ends.
    ///
    /// Multi-thread on purpose: the binary runs on `new_multi_thread`, and the
    /// watcher thread reaping the process is what lets the latch close.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_running_process_holds_off_the_update_and_says_so_once() {
        let trail = tempfile::NamedTempFile::new().unwrap();
        let state = AppState::new().with_audit(Arc::new(
            crate::audit::AuditSink::file(trail.path()).unwrap(),
        ));
        let long = if cfg!(windows) {
            "ping -n 120 127.0.0.1 >nul"
        } else {
            "sleep 120"
        };
        let id = state
            .processes
            .start(
                &StartRequest {
                    command: long.into(),
                    ..Default::default()
                },
                None,
            )
            .unwrap()
            .id;
        let cfg = FollowConfig {
            quiet: Duration::from_millis(20),
            jitter_max: Duration::ZERO,
            probation: Duration::from_secs(1),
            base_url: String::new(),
        };

        let waiting = {
            let state = state.clone();
            tokio::spawn(async move { wait_until_latched(&state, &cfg, "0.1.0", "0.2.0").await })
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!waiting.is_finished(), "the latch waits for the process");
        assert!(!state.activity.is_latched());

        state.processes.delete(id, None).unwrap();
        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the latch closes once the process is gone")
            .unwrap();
        assert!(state.activity.is_latched());

        let lines: Vec<serde_json::Value> = std::fs::read_to_string(trail.path())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|e: &serde_json::Value| e["kind"] == "update.waiting")
            .collect();
        assert_eq!(lines.len(), 1, "once, however long it waited: {lines:?}");
        assert_eq!(lines[0]["reason"], "processes-running");
        assert_eq!(lines[0]["to_version"], "0.2.0");
    }
}
