//! The persistent update state and the probation verdict.
//!
//! Pure logic: no network, no process control. The state file sits next to the
//! executable; the verdict maps what a freshly swapped-in binary observed to
//! what should happen to the version it was swapped to.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::is_newer_version;

/// File name of the state, inside the executable's directory.
pub const STATE_FILE: &str = "shell-tunnel.update.json";

/// A swap that has not yet proved itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub from: String,
    pub to: String,
    pub prev_path: PathBuf,
    /// Incremented on each start, before attaching.
    pub attempts: u32,
    pub written_at_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateState {
    pub pending: Option<Pending>,
    /// Versions never to follow again.
    pub abandoned: Vec<String>,
    /// Do not try to follow before this time (Unix ms).
    pub retry_not_before_ms: Option<u64>,
    /// Versions whose failure has already been reported once.
    pub failed_reported: Vec<String>,
}

/// What a freshly started binary saw while on probation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbationObservation {
    /// The relay accepted the attach.
    Enrolled,
    /// The relay was reached and refused, with this reason.
    Rejected(String),
    /// The relay could not be reached within the probation window.
    Unreachable,
    /// A previous start died before it was enrolled.
    PriorStartDied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Applied,
    RollBackAndAbandon,
    RollBackAndRetry,
    KeepWaiting,
}

/// Read the state from `dir`. A missing file is the default state; a file that
/// exists but cannot be parsed is `InvalidData`, never silently defaulted.
pub fn load(dir: &Path) -> io::Result<UpdateState> {
    match std::fs::read(dir.join(STATE_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(UpdateState::default()),
        Err(e) => Err(e),
    }
}

/// Write the state to `dir` through a temporary file and a rename.
pub fn store(dir: &Path, s: &UpdateState) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(s).map_err(io::Error::other)?;
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    let result =
        std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, dir.join(STATE_FILE)));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Decide what a probation observation means for the swapped-in version.
pub fn judge(obs: &ProbationObservation) -> Verdict {
    match obs {
        ProbationObservation::Enrolled => Verdict::Applied,
        ProbationObservation::Rejected(reason) => match reason.as_str() {
            "unsupported-version" | "bad-handshake" => Verdict::RollBackAndAbandon,
            // The relay refused the credential over a healthy connection: not
            // the new build's fault, and rolling back would not change it.
            "bad-token" => Verdict::KeepWaiting,
            _ => Verdict::RollBackAndRetry,
        },
        ProbationObservation::Unreachable => Verdict::RollBackAndRetry,
        ProbationObservation::PriorStartDied => Verdict::RollBackAndAbandon,
    }
}

/// Whether to start following the version a relay announced.
pub fn should_follow(current: &str, relay: &str, state: &UpdateState, now_ms: u64) -> bool {
    is_newer_version(current, relay)
        && !state.abandoned.iter().any(|v| v == relay)
        && state.retry_not_before_ms.map_or(true, |t| t <= now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProbationObservation::*;

    fn rej(r: &str) -> ProbationObservation {
        Rejected(r.to_string())
    }

    #[test]
    fn enrolment_applies_the_update() {
        assert_eq!(judge(&Enrolled), Verdict::Applied);
    }

    #[test]
    fn an_unsupported_version_rolls_back_and_abandons() {
        assert_eq!(
            judge(&rej("unsupported-version")),
            Verdict::RollBackAndAbandon
        );
    }

    #[test]
    fn a_bad_handshake_rolls_back_and_abandons() {
        assert_eq!(judge(&rej("bad-handshake")), Verdict::RollBackAndAbandon);
    }

    #[test]
    fn a_bad_token_keeps_waiting() {
        assert_eq!(judge(&rej("bad-token")), Verdict::KeepWaiting);
    }

    #[test]
    fn any_other_rejection_rolls_back_and_retries() {
        assert_eq!(judge(&rej("something-else")), Verdict::RollBackAndRetry);
    }

    #[test]
    fn a_second_start_without_enrolment_rolls_back_and_abandons() {
        assert_eq!(judge(&PriorStartDied), Verdict::RollBackAndAbandon);
    }

    #[test]
    fn a_relay_that_cannot_be_reached_rolls_back_but_keeps_the_version() {
        assert_eq!(judge(&Unreachable), Verdict::RollBackAndRetry);
        let state = UpdateState::default();
        assert!(should_follow("0.28.0", "0.29.0", &state, 0));
    }

    #[test]
    fn never_downgrades() {
        let s = UpdateState::default();
        assert!(!should_follow("0.29.0", "0.28.0", &s, 0));
        assert!(!should_follow("0.29.0", "0.29.0", &s, 0));
        assert!(should_follow("0.28.0", "0.29.0", &s, 0));
    }

    #[test]
    fn an_abandoned_version_is_not_followed() {
        let s = UpdateState {
            abandoned: vec!["0.29.0".into()],
            ..Default::default()
        };
        assert!(!should_follow("0.28.0", "0.29.0", &s, 0));
        assert!(should_follow("0.28.0", "0.30.0", &s, 0));
    }

    #[test]
    fn a_backoff_that_has_not_passed_blocks_following() {
        let s = UpdateState {
            retry_not_before_ms: Some(1_000),
            ..Default::default()
        };
        assert!(!should_follow("0.28.0", "0.29.0", &s, 999));
        assert!(should_follow("0.28.0", "0.29.0", &s, 1_000));
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("st-update-state-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn state_survives_a_round_trip_and_a_missing_file_is_default() {
        let d = tmp("rt");
        assert_eq!(load(&d).unwrap(), UpdateState::default());
        let s = UpdateState {
            pending: Some(Pending {
                from: "0.28.0".into(),
                to: "0.29.0".into(),
                prev_path: d.join("shell-tunnel.prev"),
                attempts: 1,
                written_at_ms: 42,
            }),
            abandoned: vec!["0.27.9".into()],
            retry_not_before_ms: Some(7),
            failed_reported: vec!["0.29.0".into()],
        };
        store(&d, &s).unwrap();
        assert_eq!(load(&d).unwrap(), s);
        // Overwriting works, and no temporary file is left behind.
        store(&d, &UpdateState::default()).unwrap();
        assert_eq!(load(&d).unwrap(), UpdateState::default());
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(STATE_FILE)]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_corrupt_state_file_is_an_error_not_a_default() {
        let d = tmp("corrupt");
        std::fs::write(d.join(STATE_FILE), b"{ not json").unwrap();
        let e = load(&d).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(&d);
    }
}
