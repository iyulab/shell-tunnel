//! Error types for shell-tunnel.

use thiserror::Error;

/// Main error type for shell-tunnel operations.
#[derive(Error, Debug)]
pub enum ShellTunnelError {
    /// Session with the given ID was not found.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Session with the given ID already exists.
    #[error("session already exists: {0}")]
    SessionExists(String),

    /// Invalid state transition attempted.
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition {
        from: crate::session::SessionState,
        to: crate::session::SessionState,
    },

    /// PTY-related error.
    #[error("PTY error: {0}")]
    Pty(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Command execution timeout.
    #[error("command execution timeout")]
    Timeout,

    /// Session has been terminated.
    #[error("session terminated")]
    SessionTerminated,

    /// Internal lock was poisoned.
    #[error("internal lock poisoned")]
    LockPoisoned,

    /// Channel send error.
    #[error("channel send error: {0}")]
    ChannelSend(String),

    /// Channel receive error.
    #[error("channel closed")]
    ChannelClosed,

    /// Command execution failed.
    #[error("command execution failed: {0}")]
    ExecutionFailed(String),

    /// Output parsing error.
    #[error("output parse error: {0}")]
    ParseError(String),

    /// Session is not in executable state.
    #[error("session not executable: current state is {0:?}")]
    NotExecutable(crate::session::SessionState),

    /// Update error.
    #[error("update error: {0}")]
    Update(String),
}

/// Convenience Result type for shell-tunnel operations.
pub type Result<T> = std::result::Result<T, ShellTunnelError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_not_found_display() {
        let err = ShellTunnelError::SessionNotFound("sess-00000001".into());
        assert!(err.to_string().contains("sess-00000001"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_session_exists_display() {
        let err = ShellTunnelError::SessionExists("sess-00000002".into());
        assert!(err.to_string().contains("sess-00000002"));
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let shell_err: ShellTunnelError = io_err.into();
        assert!(matches!(shell_err, ShellTunnelError::Io(_)));
        assert!(shell_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_timeout_display() {
        let err = ShellTunnelError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_pty_error_display() {
        let err = ShellTunnelError::Pty("failed to spawn".into());
        assert!(err.to_string().contains("PTY error"));
        assert!(err.to_string().contains("failed to spawn"));
    }
}
