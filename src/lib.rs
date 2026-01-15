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
//! - **REST API**: HTTP endpoints for command execution
//! - **WebSocket**: Real-time streaming of command output
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
//!
//! ## API Server
//!
//! ```no_run
//! use shell_tunnel::api::{ServerConfig, serve};
//!
//! #[tokio::main]
//! async fn main() -> shell_tunnel::Result<()> {
//!     shell_tunnel::logging::try_init().ok();
//!     let config = ServerConfig::new("127.0.0.1", 3000);
//!     serve(config).await
//! }
//! ```

pub mod api;
pub mod error;
pub mod execution;
pub mod logging;
pub mod output;
pub mod pty;
pub mod security;
pub mod session;

// Re-export commonly used types
pub use error::{Result, ShellTunnelError};
pub use execution::{Command, CommandExecutor, ExecutionResult};
pub use output::{OutputSanitizer, VirtualScreen};
pub use pty::{AsyncPtyReader, AsyncPtyWriter, NativePty, PtyHandle, PtySize};
pub use session::{
    Session, SessionConfig, SessionContext, SessionId, SessionState, SessionStore, StateProbe,
};

// Re-export API types
pub use api::{AppState, ServerConfig};

// Re-export security types
pub use security::{ApiKeyStore, CommandValidator, RateLimiter};
