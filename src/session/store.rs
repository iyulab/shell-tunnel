//! Session storage and management.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use super::{SessionContext, SessionId, SessionState};
use crate::error::ShellTunnelError;
use crate::Result;

/// Configuration for creating a new session.
#[derive(Debug, Clone, Default)]
pub struct SessionConfig {
    /// Initial shell command (e.g., "bash", "powershell.exe").
    pub shell: Option<String>,
    /// Initial working directory.
    pub working_dir: Option<String>,
    /// Environment variables to set.
    pub env: HashMap<String, String>,
}

/// A shell session.
#[derive(Debug)]
pub struct Session {
    /// Unique identifier.
    pub id: SessionId,
    /// Current state.
    pub state: SessionState,
    /// Configuration used to create this session.
    pub config: SessionConfig,
    /// Execution context (CWD, env, etc.).
    pub context: SessionContext,
    /// Time when session was created.
    pub created_at: Instant,
    /// Time of last activity.
    pub last_activity: Instant,
}

impl Session {
    /// Create a new session with the given ID and configuration.
    pub fn new(id: SessionId, config: SessionConfig) -> Self {
        let now = Instant::now();
        let context = config
            .working_dir
            .as_ref()
            .map(SessionContext::with_cwd)
            .unwrap_or_default();

        Self {
            id,
            state: SessionState::Created,
            config,
            context,
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

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            state: self.state,
            config: self.config.clone(),
            context: self.context.clone(),
            created_at: self.created_at,
            last_activity: self.last_activity,
        }
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

    /// Create a new session with the given configuration.
    ///
    /// Returns the newly assigned session ID.
    pub fn create(&self, config: SessionConfig) -> Result<SessionId> {
        let id = SessionId::new();
        let session = Session::new(id, config);

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
        let id = store.create(SessionConfig::default()).unwrap();

        assert!(store.contains(&id).unwrap());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_get_session() {
        let store = SessionStore::new();
        let id = store.create(SessionConfig::default()).unwrap();

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
        let id = store.create(SessionConfig::default()).unwrap();

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
        let id = store.create(SessionConfig::default()).unwrap();

        let removed = store.remove(&id).unwrap();
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, id);

        assert!(!store.contains(&id).unwrap());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_list_ids() {
        let store = SessionStore::new();
        let id1 = store.create(SessionConfig::default()).unwrap();
        let id2 = store.create(SessionConfig::default()).unwrap();
        let id3 = store.create(SessionConfig::default()).unwrap();

        let ids = store.list_ids().unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
        assert!(ids.contains(&id3));
    }

    #[test]
    fn test_remove_matching() {
        let store = SessionStore::new();
        store.create(SessionConfig::default()).unwrap();
        store.create(SessionConfig::default()).unwrap();

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

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(SessionStore::new());
        let mut handles = vec![];

        // Spawn 100 threads that each create a session
        for _ in 0..100 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                store.create(SessionConfig::default()).unwrap()
            }));
        }

        let ids: Vec<SessionId> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All IDs should be unique
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 100);

        // Store should have 100 sessions
        assert_eq!(store.count(), 100);
    }
}
