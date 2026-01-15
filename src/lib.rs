//! # shell-tunnel
//!
//! Ultra-lightweight shell tunnel for AI agent integration.
//!
//! This crate provides a secure, cross-platform API for AI agents to
//! interact with system shells. It supports both Windows (ConPTY) and
//! Unix (PTY) terminals through a unified interface.
//!
//! ## Features
//!
//! - **Cross-platform PTY**: Unified interface for Windows ConPTY and Unix PTY
//! - **Async I/O**: Non-blocking operations using tokio
//! - **Session Management**: Stateful shell sessions with lifecycle tracking
//! - **Lightweight**: Minimal dependencies, small binary size
//!
//! ## Quick Start
//!
//! ```no_run
//! use shell_tunnel::{NativePty, PtySize, SessionStore, SessionConfig};
//!
//! #[tokio::main]
//! async fn main() -> shell_tunnel::Result<()> {
//!     // Initialize logging
//!     shell_tunnel::logging::try_init().ok();
//!
//!     // Create a session store
//!     let store = SessionStore::new();
//!
//!     // Create a new session
//!     let session_id = store.create(SessionConfig::default())?;
//!
//!     // Spawn a PTY
//!     let pty = NativePty::new();
//!     let handle = pty.spawn_default(PtySize::default())?;
//!
//!     println!("Session {} created with PID {}", session_id, handle.pid);
//!
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod execution;
pub mod logging;
pub mod output;
pub mod pty;
pub mod session;

// Re-export commonly used types
pub use error::{Result, ShellTunnelError};
pub use execution::{Command, CommandExecutor, ExecutionResult};
pub use output::{OutputSanitizer, VirtualScreen};
pub use pty::{AsyncPtyReader, AsyncPtyWriter, NativePty, PtyHandle, PtySize};
pub use session::{
    Session, SessionConfig, SessionContext, SessionId, SessionState, SessionStore, StateProbe,
};
