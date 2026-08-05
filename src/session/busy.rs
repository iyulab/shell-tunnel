//! Marking a session busy for the length of one command.

use std::sync::Arc;

use super::{SessionId, SessionState, SessionStore};
use crate::Result;

/// Holds a session in [`SessionState::Active`] for as long as the guard lives,
/// and returns it to [`SessionState::Idle`] when the guard is dropped.
///
/// The pair used to be written by hand — a transition to `Active` before the
/// command and one back to `Idle` after it. That is correct only for the escape
/// paths someone remembered to count, and it misses the one no branch can
/// express: an `.await` that never resumes because the future was **cancelled**.
/// A caller that hangs up before its response is written leaves axum dropping
/// the handler mid-command, and the session stayed `Active` forever — reporting
/// a command running long after it had finished, while `idle_seconds` grew
/// underneath it. Measured, not reasoned about: 44.7 s after the caller vanished
/// from a nine-second command.
///
/// A guard closes every exit through one path, including cancellation, because
/// dropping a future runs the destructors of everything it owns.
pub(crate) struct BusySession {
    store: Arc<SessionStore>,
    id: SessionId,
}

impl BusySession {
    /// Mark the session busy. The session returns to idle when the guard drops.
    ///
    /// Fails only if the session is gone, which callers check for first.
    pub(crate) fn begin(store: &Arc<SessionStore>, id: &SessionId) -> Result<Self> {
        store.update(id, |s| {
            let _ = s.state.transition_to(SessionState::Active);
            s.touch();
        })?;

        Ok(Self {
            store: Arc::clone(store),
            id: *id,
        })
    }
}

impl Drop for BusySession {
    fn drop(&mut self) {
        // A session left `Active` reports a command running forever, so this
        // must not depend on the update succeeding for the right reasons: if the
        // session was deleted while the command ran there is nothing to restore,
        // and that is the only way this errors.
        let _ = self.store.update(&self.id, |s| {
            let _ = s.state.transition_to(SessionState::Idle);
            s.touch();
        });
    }
}
