//! Append-only audit trail.
//!
//! A remote shell without an audit trail leaves nothing to look at after an
//! incident: the process logs are ephemeral, and the API returns results to the
//! caller rather than recording them. This writes one JSON object per line —
//! readable with `tail -f` or `jq`, appendable without a database, and never
//! rewritten.
//!
//! What is deliberately *not* recorded: the bearer token itself. Events carry a
//! per-registration `token_id` and the token's label, which identify the caller
//! across a run without putting a credential in a file that is, by design, kept
//! around and often shipped elsewhere.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::ShellTunnelError;
use crate::Result;

/// Who made a request, in terms safe to write down.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Identity {
    /// Stable-within-this-run identifier for the token used.
    pub token_id: String,
    /// The token's label (`operator`, `configured`, `legacy`, …).
    pub label: String,
}

/// One recorded event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Unix milliseconds. A number rather than a formatted string so the log
    /// stays sortable without a date parser.
    pub at_ms: u64,
    /// What happened: `execute`, `denied`, …
    pub kind: String,
    /// Caller identity, when the request was authenticated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    /// Client address as the server saw it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Request method and path, for correlating with access logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// The command line, for execution events.
    ///
    /// This is the substance of the trail — "someone called POST /execute" says
    /// almost nothing on its own. It also means a command that embeds a secret
    /// puts that secret in the log, which is the trade an audit trail makes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Session the command ran in, when it was not a one-shot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u64>,
    /// Process exit code, when the command completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Whether the command hit its timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    /// How long it took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Bytes the command's output ran to, when more than the response carried.
    ///
    /// Present only on an execution whose output was capped, so its presence
    /// *is* the signal: a trail entry without it describes a response that
    /// carried everything. Recorded because the response itself is not kept —
    /// without this, "why was that result short?" has no answer after the fact,
    /// and a short answer is indistinguishable from a short command.
    ///
    /// Separate from `bytes`, which counts what a transfer moved. Reusing it
    /// would make one field mean two things depending on `kind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
    /// HTTP status, for denial events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Why a request was refused (`missing-token`, `invalid-token`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Path a file operation touched, relative to the configured root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Bytes transferred. Present on terminal transfer events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Entries a tree operation counted or removed. Present on `fs.delete`
    /// events that acted on a directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<u64>,
    /// Whether the declared digest matched what arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_ok: Option<bool>,
    /// The upload session's id.
    ///
    /// Recorded on `upload.start` and on any event that cannot carry `file`
    /// (see `with_upload_id`'s doc comment) so the two can still be joined
    /// into one session's story.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_id: Option<String>,
}

impl AuditEvent {
    /// Start an event of the given kind, stamped now.
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            at_ms: now_ms(),
            kind: kind.into(),
            identity: None,
            client: None,
            route: None,
            command: None,
            session_id: None,
            exit_code: None,
            timed_out: None,
            duration_ms: None,
            output_bytes: None,
            status: None,
            reason: None,
            file: None,
            bytes: None,
            entries: None,
            digest_ok: None,
            upload_id: None,
        }
    }

    /// Attach the caller's identity.
    pub fn with_identity(mut self, identity: Option<Identity>) -> Self {
        self.identity = identity;
        self
    }

    /// Attach the client address.
    pub fn with_client(mut self, client: impl Into<String>) -> Self {
        self.client = Some(client.into());
        self
    }

    /// Attach the request route.
    pub fn with_route(mut self, route: impl Into<String>) -> Self {
        self.route = Some(route.into());
        self
    }

    /// Attach the command line that ran.
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Attach the session the command ran in.
    pub fn with_session(mut self, session_id: u64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Attach the outcome of an execution.
    pub fn with_outcome(
        mut self,
        exit_code: Option<i32>,
        timed_out: bool,
        duration_ms: u64,
    ) -> Self {
        self.exit_code = exit_code;
        self.timed_out = Some(timed_out);
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Record that an execution produced more output than was returned.
    ///
    /// A no-op when nothing was discarded, so callers can hand over both
    /// figures unconditionally and the field stays a truncation signal rather
    /// than a size that is present on every entry.
    pub fn with_truncated_output(mut self, truncated: bool, total_bytes: u64) -> Self {
        if truncated {
            self.output_bytes = Some(total_bytes);
        }
        self
    }

    /// Attach a refusal.
    pub fn with_denial(mut self, status: u16, reason: impl Into<String>) -> Self {
        self.status = Some(status);
        self.reason = Some(reason.into());
        self
    }

    /// Attach the file a transfer touched, and how many bytes moved.
    ///
    /// Recorded on terminal events only. A chunk-level trail would turn one
    /// gigabyte-scale transfer into hundreds of lines and bury everything else
    /// in the log.
    pub fn with_file(mut self, path: impl Into<String>, bytes: Option<u64>) -> Self {
        self.file = Some(path.into());
        self.bytes = bytes;
        self
    }

    /// Record whether the declared digest matched.
    pub fn with_digest(mut self, verified: bool) -> Self {
        self.digest_ok = Some(verified);
        self
    }

    /// Attach the upload session's id.
    ///
    /// Every terminal upload event but one can name its subject through
    /// `file` (the destination). The exception is `upload.orphaned`: a
    /// `.part` staging file found at startup carries only the id encoded in
    /// its own filename — the destination it was headed for lived in the
    /// in-memory session that a restart already discarded, so there is
    /// nothing left to attach as `file`. `upload_id` is how a reader
    /// recovers that link anyway: it is also recorded on `upload.start`
    /// (which does have `file`), so grepping the trail for one upload's id
    /// still surfaces both ends of its story.
    pub fn with_upload_id(mut self, id: impl Into<String>) -> Self {
        self.upload_id = Some(id.into());
        self
    }
}

/// Where audit events go.
///
/// Disabled unless a path is configured: writing to a file nobody asked for
/// would be a surprising side effect, and the operator is the one who knows
/// where such a file belongs.
#[derive(Debug, Default)]
pub enum AuditSink {
    /// Nothing is recorded.
    #[default]
    Disabled,
    /// Appended to a file, one JSON object per line.
    File {
        /// Path being appended to, kept for diagnostics.
        path: PathBuf,
        /// Size at which the file is rotated, if bounded.
        max_bytes: Option<u64>,
        state: Mutex<FileState>,
    },
}

/// Open file plus what has been written to it.
#[derive(Debug)]
pub struct FileState {
    writer: BufWriter<File>,
    /// Bytes in the current file, tracked rather than stat-ed so rotation costs
    /// nothing per event.
    written: u64,
}

impl AuditSink {
    /// Open `path` for appending, creating it if needed.
    pub fn file(path: impl AsRef<Path>) -> Result<Self> {
        Self::file_with_limit(path, None)
    }

    /// Open `path`, rotating to `<path>.1` once it passes `max_bytes`.
    ///
    /// One generation is kept. A trail that grows without bound eventually
    /// fills the disk it is meant to protect, and keeping several generations
    /// would be a retention policy — which belongs to whoever runs the machine,
    /// not to this process.
    pub fn file_with_limit(path: impl AsRef<Path>, max_bytes: Option<u64>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (writer, written) = open_append(&path)?;
        Ok(Self::File {
            path,
            max_bytes,
            state: Mutex::new(FileState { writer, written }),
        })
    }

    /// Whether anything is being recorded.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::File { .. })
    }

    /// Record one event from an async context, off the runtime's workers.
    ///
    /// [`record`](Self::record) opens, writes and flushes a file, which is
    /// blocking work — the filesystem handlers already thread it into the
    /// `spawn_blocking` bodies they are running in for that reason, so a slow
    /// disk cannot starve the worker pool that also runs `/health` and the
    /// accept loop. A handler that has no blocking body of its own has nowhere
    /// to put it and used to call `record` straight from the runtime thread.
    /// This is that missing half: same write, same ordering.
    ///
    /// What this buys and what it costs were both measured rather than reasoned
    /// (`tests/blocking_pool.rs`). With every blocking thread held, `/health`
    /// answered in 2.5 µs — the worker threads really are untouched. The same
    /// run had this method take 2.96 s against 1.57 ms once a thread was free:
    /// moving blocking work off the workers does not make it free, it moves it
    /// onto a pool that is shared with every command in flight. So a burst of
    /// concurrent commands does delay an audited response, and that is a
    /// deliberate trade against blocking the accept loop, not an oversight.
    ///
    /// Awaited rather than detached, deliberately. Spawning and walking away
    /// would return the response first and leave the entry to land whenever —
    /// or not at all, if the process stops in between. An audit trail that
    /// drops its last entries under load is untrustworthy exactly where it is
    /// load-bearing, which is the same reason `record` flushes per event.
    ///
    /// The hop is skipped entirely when nothing is being recorded: with no
    /// trail configured `record` returns immediately, and paying for a task
    /// dispatch to do nothing would be a cost on every request of the default
    /// configuration.
    pub async fn record_async(self: &std::sync::Arc<Self>, event: AuditEvent) {
        if !self.is_enabled() {
            return;
        }
        let sink = std::sync::Arc::clone(self);
        // A panic inside the blocking task would already have aborted the
        // process through the panic hook; the join error is not actionable
        // here and dropping it keeps this from being a second failure mode.
        let _ = tokio::task::spawn_blocking(move || sink.record(event)).await;
    }

    /// Record one event.
    ///
    /// Flushed per event rather than buffered until convenient: a trail that
    /// loses its last entries when the process dies is least trustworthy exactly
    /// when it matters most.
    ///
    /// Blocking. From an async context use
    /// [`record_async`](Self::record_async), or call this inside a
    /// `spawn_blocking` body that is already running.
    pub fn record(&self, event: AuditEvent) {
        let Self::File {
            path,
            max_bytes,
            state,
        } = self
        else {
            return;
        };

        let line = match serde_json::to_string(&event) {
            Ok(line) => line,
            Err(e) => {
                tracing::warn!(target: "audit", "cannot encode audit event: {e}");
                return;
            }
        };

        let Ok(mut state) = state.lock() else {
            tracing::warn!(target: "audit", "audit log lock poisoned; event dropped");
            return;
        };

        // Rotated before the write, so the limit bounds the file rather than
        // being the point at which it is already over.
        if let Some(limit) = max_bytes {
            if state.written + line.len() as u64 + 1 > *limit && state.written > 0 {
                if let Err(e) = rotate(path, &mut state) {
                    tracing::warn!(target: "audit", "cannot rotate audit log {}: {e}", path.display());
                }
            }
        }

        match writeln!(state.writer, "{line}").and_then(|()| state.writer.flush()) {
            Ok(()) => state.written += line.len() as u64 + 1,
            Err(e) => {
                // Logged, not fatal: losing the trail should not take the server
                // down, but it must not pass silently either.
                tracing::warn!(target: "audit", "cannot write audit log {}: {e}", path.display());
            }
        }
    }
}

/// Open a file for appending, reporting how much is already in it.
fn open_append(path: &Path) -> Result<(BufWriter<File>, u64)> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            ShellTunnelError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot open audit log {}: {e}", path.display()),
            ))
        })?;
    let written = file.metadata().map(|m| m.len()).unwrap_or(0);
    Ok((BufWriter::new(file), written))
}

/// Move the current file aside and start a fresh one.
fn rotate(path: &Path, state: &mut FileState) -> std::io::Result<()> {
    state.writer.flush()?;

    let rotated = path.with_extension(match path.extension() {
        Some(ext) => format!("{}.1", ext.to_string_lossy()),
        None => "1".to_string(),
    });
    // Replaces the previous generation: one is kept, deliberately.
    std::fs::rename(path, &rotated)?;

    let (writer, _) = open_append(path).map_err(std::io::Error::other)?;
    state.writer = writer;
    state.written = 0;
    Ok(())
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_lines(path: &Path) -> Vec<AuditEvent> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is one event"))
            .collect()
    }

    #[test]
    fn a_disabled_sink_records_nothing() {
        let sink = AuditSink::Disabled;
        assert!(!sink.is_enabled());
        sink.record(AuditEvent::new("execute"));
    }

    #[test]
    fn events_are_appended_one_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::file(&path).unwrap();

        sink.record(AuditEvent::new("execute").with_command("echo one"));
        sink.record(AuditEvent::new("execute").with_command("echo two"));

        let events = read_lines(&path);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].command.as_deref(), Some("echo one"));
        assert_eq!(events[1].command.as_deref(), Some("echo two"));
    }

    #[test]
    fn reopening_appends_rather_than_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        AuditSink::file(&path)
            .unwrap()
            .record(AuditEvent::new("execute").with_command("first run"));
        AuditSink::file(&path)
            .unwrap()
            .record(AuditEvent::new("execute").with_command("second run"));

        // A trail that restarts empty on every restart is not a trail.
        let events = read_lines(&path);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn an_execution_event_carries_who_what_and_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::file(&path).unwrap();

        sink.record(
            AuditEvent::new("execute")
                .with_identity(Some(Identity {
                    token_id: "tok-1".into(),
                    label: "operator".into(),
                }))
                .with_client("203.0.113.7:51000")
                .with_route("POST /api/v1/execute")
                .with_command("whoami")
                .with_outcome(Some(0), false, 42),
        );

        let event = read_lines(&path).remove(0);
        assert_eq!(event.kind, "execute");
        assert_eq!(event.identity.unwrap().label, "operator");
        assert_eq!(event.command.as_deref(), Some("whoami"));
        assert_eq!(event.exit_code, Some(0));
        assert_eq!(event.timed_out, Some(false));
        assert_eq!(event.duration_ms, Some(42));
        assert!(event.at_ms > 0);
    }

    #[test]
    fn a_denial_records_why_without_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::file(&path).unwrap();

        sink.record(
            AuditEvent::new("denied")
                .with_client("198.51.100.4:40000")
                .with_route("POST /api/v1/execute")
                .with_denial(401, "invalid-token"),
        );

        let raw = std::fs::read_to_string(&path).unwrap();
        let event = read_lines(&path).remove(0);
        assert_eq!(event.status, Some(401));
        assert_eq!(event.reason.as_deref(), Some("invalid-token"));
        // Probing is what these entries are for, and the credential that was
        // tried must not end up in the file.
        assert!(!raw.contains("Bearer"), "{raw}");
    }

    #[test]
    fn a_bounded_log_rotates_instead_of_growing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Small enough that the second event cannot share the file.
        let sink = AuditSink::file_with_limit(&path, Some(200)).unwrap();

        for i in 0..8 {
            sink.record(AuditEvent::new("execute").with_command(format!("command number {i}")));
        }

        let current = std::fs::metadata(&path).unwrap().len();
        assert!(
            current <= 200,
            "current file should stay under the limit: {current}"
        );

        // The previous generation is kept, so the most recent history survives
        // a rotation rather than being discarded.
        let rotated = dir.path().join("audit.jsonl.1");
        assert!(rotated.exists(), "one generation should be kept");
    }

    #[test]
    fn an_unbounded_log_never_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = AuditSink::file(&path).unwrap();

        for i in 0..20 {
            sink.record(AuditEvent::new("execute").with_command(format!("command {i}")));
        }

        assert_eq!(read_lines(&path).len(), 20);
        assert!(!dir.path().join("audit.jsonl.1").exists());
    }

    #[test]
    fn rotation_keeps_counting_from_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        // A restart must not forget how full the file already is, or the limit
        // would only apply to whatever this process wrote.
        AuditSink::file(&path)
            .unwrap()
            .record(AuditEvent::new("execute").with_command("x".repeat(150)));
        let sink = AuditSink::file_with_limit(&path, Some(200)).unwrap();
        sink.record(AuditEvent::new("execute").with_command("second"));

        assert!(dir.path().join("audit.jsonl.1").exists());
    }

    #[test]
    fn absent_fields_are_omitted_rather_than_null() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        AuditSink::file(&path)
            .unwrap()
            .record(AuditEvent::new("execute"));

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("null"), "{raw}");
    }
}
