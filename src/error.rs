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

    /// TLS configuration error.
    #[cfg(feature = "tls")]
    #[error("tls error: {0}")]
    Tls(String),

    /// Tunnel (reachability) error.
    #[error("tunnel error: {0}")]
    Tunnel(String),

    /// Update error.
    #[cfg(feature = "self-update")]
    #[error("update error: {0}")]
    Update(String),
}

/// Convenience Result type for shell-tunnel operations.
pub type Result<T> = std::result::Result<T, ShellTunnelError>;

/// Report a failure to take a listening socket, in the words this program uses
/// everywhere else.
///
/// Without this the gateway and the relay both ended a failed startup with the
/// `Debug` form of an `io::Error` — `Error: Io(Os { code: 10048, kind:
/// AddrInUse, ... })` — which is the one place in the binary a Rust internal
/// leaks out. Shared because both do it: fixing one leaves the identical screen
/// on the other, confirmed by running both against a taken port.
///
/// `AddrInUse` gets the case worth naming, because "the port is taken" is by
/// far the most common way this fails and has an obvious next step. Classified
/// from [`std::io::ErrorKind`] rather than from the message, which the OS
/// writes in its own language.
pub fn explain_bind_failure(what: &str, addr: &str, error: &std::io::Error) -> String {
    let mut message = match error.kind() {
        std::io::ErrorKind::AddrInUse => {
            format!("cannot start the {what}: {addr} is already in use by another program.")
        }
        std::io::ErrorKind::PermissionDenied => {
            format!("cannot start the {what}: not allowed to bind {addr}.")
        }
        std::io::ErrorKind::AddrNotAvailable => {
            format!("cannot start the {what}: {addr} is not an address on this machine.")
        }
        _ => format!("cannot start the {what}: {addr} could not be bound."),
    };
    // The OS text is kept: it is the truth about that machine, and it is what
    // an operator searches for.
    message.push_str(&format!("\n  {error}"));
    if error.kind() == std::io::ErrorKind::AddrInUse {
        message.push_str("\n  Choose another port with -p, or stop whatever holds this one.");
        if cfg!(windows) {
            message.push_str(
                "\n  To find it: Get-NetTCPConnection -LocalPort <port> | Select OwningProcess",
            );
        } else {
            message.push_str("\n  To find it: ss -ltnp | grep :<port>");
        }
    }
    message
}

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
