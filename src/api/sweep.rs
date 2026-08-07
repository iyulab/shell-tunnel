//! Reclaiming what a client abandoned, with a trail of what went.
//!
//! Deliberately not in `handlers.rs`. That file holds async handlers, and
//! `audit_e2e::the_async_handlers_record_without_blocking_the_runtime` holds it
//! to a rule for exactly that reason: `AuditSink::record` opens, writes and
//! flushes a file, so calling it from a runtime thread parks a worker that also
//! serves `/health` and the accept loop. The sweep below *is* blocking and is
//! meant to be — it runs inside a `spawn_blocking` body — but a blocking
//! `record` sitting in the async-handler file would either trip that guard or,
//! worse, force it to be loosened for everything else in there too. Same
//! reasoning that keeps `sweep_expired_uploads` in `fs.rs` rather than here.

use std::time::Duration;

use crate::audit::{AuditEvent, AuditSink};
use crate::session::SessionStore;

/// Drop sessions idle past `ttl`, recording a terminal event for each.
///
/// The audit-aware half of [`SessionStore::sweep_idle`], and the same split
/// [`crate::api::fs::sweep_expired_uploads`] uses: the store stays
/// audit-agnostic because it has no `AuditSink`, and the recording happens here.
///
/// Sweeping silently would make an abandoned session indistinguishable from one
/// its client deleted, which is the question the trail exists to answer — and
/// the reason [`SessionStore::sweep_idle`] returns ids rather than a count.
///
/// **Blocking.** Call it inside a `spawn_blocking` body, as the periodic sweeper
/// in `main.rs` does.
pub fn sweep_expired_sessions(store: &SessionStore, audit: &AuditSink, ttl: Duration) -> usize {
    let Ok(expired) = store.sweep_idle(ttl) else {
        // A poisoned lock is reported by the routes that need the store; a sweep
        // that cannot run this tick simply runs the next one.
        return 0;
    };
    for id in &expired {
        audit.record(AuditEvent::new("session.expired").with_session(id.as_u64()));
    }
    expired.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionState;

    /// The count reported is what was actually removed.
    #[test]
    fn the_sweep_reports_what_it_removed() {
        let store = SessionStore::new();
        let busy = store.create().expect("create");
        store.create().expect("create");
        store
            .update(&busy, |s| {
                let _ = s.state.transition_to(SessionState::Active);
            })
            .expect("busy");

        let swept = sweep_expired_sessions(&store, &AuditSink::Disabled, Duration::ZERO);

        assert_eq!(swept, 1, "only the session with no command in it may go");
        assert!(
            store.contains(&busy).expect("lock"),
            "a session running a command must survive"
        );
    }
}
