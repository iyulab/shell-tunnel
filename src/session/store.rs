//! Session storage and management.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use super::{SessionContext, SessionId, SessionState};
use crate::error::ShellTunnelError;
use crate::Result;

/// A shell session.
///
/// A session carries no execution configuration. It is an identifier the audit
/// trail records against, a place for streaming to attach, and the bookkeeping
/// in [`SessionContext`]; where a command runs and what it runs with are
/// decided per execute. It once held a `shell`, a `working_dir` and an `env`
/// that no execute ever read.
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique identifier.
    pub id: SessionId,
    /// Current state.
    pub state: SessionState,
    /// Execution bookkeeping (last command, exit code, count).
    pub context: SessionContext,
    /// Time when session was created.
    pub created_at: Instant,
    /// Time of last activity.
    pub last_activity: Instant,
}

impl Session {
    /// Create a new session with the given ID.
    pub fn new(id: SessionId) -> Self {
        let now = Instant::now();

        Self {
            id,
            state: SessionState::Created,
            context: SessionContext::new(),
            created_at: now,
            last_activity: now,
        }
    }

    /// Update the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get the idle duration since last activity.
    pub fn idle_duration(&self) -> std::time::Duration {
        self.last_activity.elapsed()
    }
}

/// Thread-safe storage for sessions.
pub struct SessionStore {
    sessions: RwLock<HashMap<SessionId, Session>>,
}

impl SessionStore {
    /// Create a new empty session store.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session.
    ///
    /// Returns the newly assigned session ID.
    pub fn create(&self) -> Result<SessionId> {
        let id = SessionId::new();
        let session = Session::new(id);

        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| ShellTunnelError::LockPoisoned)?;

        sessions.insert(id, session);
        Ok(id)
    }

    /// Get a clone of the session with the given ID.
    pub fn get(&self, id: &SessionId) -> Result<Option<Session>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| ShellTunnelError::LockPoisoned)?;
        Ok(sessions.get(id).cloned())
    }

    /// Check if a session exists.
    pub fn contains(&self, id: &SessionId) -> Result<bool> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| ShellTunnelError::LockPoisoned)?;
        Ok(sessions.contains_key(id))
    }

    /// Update a session using a closure.
    ///
    /// The closure receives a mutable reference to the session and can modify it.
    /// Returns an error if the session doesn't exist.
    pub fn update<F>(&self, id: &SessionId, f: F) -> Result<()>
    where
        F: FnOnce(&mut Session),
    {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| ShellTunnelError::LockPoisoned)?;

        let session = sessions
            .get_mut(id)
            .ok_or_else(|| ShellTunnelError::SessionNotFound(id.to_string()))?;

        f(session);
        Ok(())
    }

    /// Remove a session from the store.
    ///
    /// Returns the removed session, or None if it didn't exist.
    pub fn remove(&self, id: &SessionId) -> Result<Option<Session>> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| ShellTunnelError::LockPoisoned)?;
        Ok(sessions.remove(id))
    }

    /// Get the number of sessions in the store.
    pub fn count(&self) -> usize {
        self.sessions.read().map(|s| s.len()).unwrap_or(0)
    }

    /// List all session IDs.
    pub fn list_ids(&self) -> Result<Vec<SessionId>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| ShellTunnelError::LockPoisoned)?;
        Ok(sessions.keys().copied().collect())
    }

    /// Remove all sessions matching a predicate.
    ///
    /// Returns the number of sessions removed.
    pub fn remove_matching<F>(&self, predicate: F) -> Result<usize>
    where
        F: Fn(&Session) -> bool,
    {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| ShellTunnelError::LockPoisoned)?;

        let before = sessions.len();
        sessions.retain(|_, session| !predicate(session));
        Ok(before - sessions.len())
    }

    /// Drop sessions that have sat idle past `ttl`, returning their ids.
    ///
    /// Nothing reclaimed a shell session before this: there was no TTL, no cap
    /// and no sweeper, and [`remove_matching`](Self::remove_matching) had no
    /// caller outside tests. A client that creates sessions and never `DELETE`s
    /// them therefore accumulated them for as long as the process ran. Upload
    /// sessions have had exactly this — a periodic sweep against
    /// `fs::SESSION_TTL` — since they were introduced; shell sessions simply had
    /// no equivalent.
    ///
    /// **A session running a command is never swept, whatever its idle clock
    /// says.** That clock is only advanced when a command starts and when it
    /// ends (`BusySession`), so during a long command it does not move at all —
    /// idle time alone cannot tell "abandoned" from "busy", and a sweep keyed on
    /// it would reap a session with a command actively running in it. The state
    /// is what distinguishes them: the same guard that stops the clock also
    /// holds the session [`Active`](SessionState::Active) for the length of the
    /// command, and that guard closes every exit including a cancelled future.
    /// `Active` cannot hide an unbounded session either, since a command's
    /// deadline is now bounded (`execution::MAX_TIMEOUT`).
    ///
    /// Ids are returned rather than counted so the caller can record what went;
    /// a session vanishing with no trace is what makes an abandoned one
    /// indistinguishable from one the client deleted.
    pub fn sweep_idle(&self, ttl: std::time::Duration) -> Result<Vec<SessionId>> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| ShellTunnelError::LockPoisoned)?;

        let expired: Vec<SessionId> = sessions
            .values()
            .filter(|s| s.state != SessionState::Active && s.idle_duration() > ttl)
            .map(|s| s.id)
            .collect();

        for id in &expired {
            sessions.remove(id);
        }
        Ok(expired)
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session() {
        let store = SessionStore::new();
        let id = store.create().unwrap();

        assert!(store.contains(&id).unwrap());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_get_session() {
        let store = SessionStore::new();
        let id = store.create().unwrap();

        let session = store.get(&id).unwrap().unwrap();
        assert_eq!(session.id, id);
        assert_eq!(session.state, SessionState::Created);
    }

    #[test]
    fn test_get_nonexistent() {
        let store = SessionStore::new();
        let fake_id = SessionId::from_raw(999999);

        let result = store.get(&fake_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_update_session() {
        let store = SessionStore::new();
        let id = store.create().unwrap();

        store
            .update(&id, |s| {
                s.state = SessionState::Active;
            })
            .unwrap();

        let session = store.get(&id).unwrap().unwrap();
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn test_update_nonexistent() {
        let store = SessionStore::new();
        let fake_id = SessionId::from_raw(999999);

        let result = store.update(&fake_id, |_| {});
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_session() {
        let store = SessionStore::new();
        let id = store.create().unwrap();

        let removed = store.remove(&id).unwrap();
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, id);

        assert!(!store.contains(&id).unwrap());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_list_ids() {
        let store = SessionStore::new();
        let id1 = store.create().unwrap();
        let id2 = store.create().unwrap();
        let id3 = store.create().unwrap();

        let ids = store.list_ids().unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
        assert!(ids.contains(&id3));
    }

    #[test]
    fn test_remove_matching() {
        let store = SessionStore::new();
        store.create().unwrap();
        store.create().unwrap();

        // Mark one as terminated
        let ids = store.list_ids().unwrap();
        store
            .update(&ids[0], |s| s.state = SessionState::Terminated)
            .unwrap();

        // Remove terminated sessions
        let removed = store
            .remove_matching(|s| s.state == SessionState::Terminated)
            .unwrap();

        assert_eq!(removed, 1);
        assert_eq!(store.count(), 1);
    }

    /// A session nobody has touched past the TTL goes.
    ///
    /// Nothing reclaimed one before: no TTL, no cap, no sweeper, and
    /// `remove_matching` had no caller outside this file.
    #[test]
    fn an_idle_session_is_swept() {
        let store = SessionStore::new();
        let id = store.create().unwrap();
        store
            .update(&id, |s| {
                let _ = s.state.transition_to(SessionState::Idle);
            })
            .unwrap();

        // Every session here is older than a zero TTL.
        let swept = store.sweep_idle(std::time::Duration::ZERO).unwrap();

        assert_eq!(swept, vec![id], "the idle session must be the one reported");
        assert_eq!(store.count(), 0);
    }

    /// A session running a command is never swept, however still its clock is.
    ///
    /// This is the contract the sweep exists under, and the one that is easy to
    /// get wrong: `last_activity` is advanced when a command starts and when it
    /// ends, and *not in between*, so a session mid-command looks exactly as
    /// idle as an abandoned one. Keyed on the clock alone this sweep would reap
    /// a session with a command actively running in it; `Active` is what parts
    /// them.
    #[test]
    fn a_session_running_a_command_is_never_swept() {
        let store = SessionStore::new();
        let running = store.create().unwrap();
        let abandoned = store.create().unwrap();
        store
            .update(&running, |s| {
                let _ = s.state.transition_to(SessionState::Active);
            })
            .unwrap();
        store
            .update(&abandoned, |s| {
                let _ = s.state.transition_to(SessionState::Idle);
            })
            .unwrap();

        let swept = store.sweep_idle(std::time::Duration::ZERO).unwrap();

        assert_eq!(
            swept,
            vec![abandoned],
            "only the abandoned session may be swept"
        );
        assert!(
            store.contains(&running).unwrap(),
            "a session with a command running in it must survive a sweep"
        );
    }

    /// A session younger than the TTL stays, so the sweep is not just "remove
    /// everything that is not busy".
    #[test]
    fn a_session_within_the_ttl_stays() {
        let store = SessionStore::new();
        let id = store.create().unwrap();

        let swept = store
            .sweep_idle(std::time::Duration::from_secs(3600))
            .unwrap();

        assert!(swept.is_empty(), "nothing has been idle for an hour yet");
        assert!(store.contains(&id).unwrap());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(SessionStore::new());
        let mut handles = vec![];

        // Spawn 100 threads that each create a session
        for _ in 0..100 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || store.create().unwrap()));
        }

        let ids: Vec<SessionId> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All IDs should be unique
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 100);

        // Store should have 100 sessions
        assert_eq!(store.count(), 100);
    }
}
