//! # shell-tunnel
//!
//! Ultra-lightweight remote shell gateway with a REST/WebSocket API.
//!
//! This crate provides a cross-platform API for programmatic interaction
//! with system shells. A command is run by a fresh shell — `cmd /c` on
//! Windows, `/bin/sh -c` elsewhere — and its output is captured through
//! pipes; nothing here allocates a terminal.
//!
//! ## Features
//!
//! - **Cross-platform**: One API over the platform's shell
//! - **Async I/O**: Non-blocking operations using tokio
//! - **Session Management**: Stateful shell sessions with lifecycle tracking
//! - **REST API**: HTTP endpoints for command execution
//! - **WebSocket**: Real-time streaming of command output
//! - **Lightweight**: Minimal dependencies, small binary size
//!
//! ## Quick Start
//!
//! ```no_run
//! use std::sync::Arc;
//! use shell_tunnel::{Command, CommandExecutor, SessionStore};
//!
//! #[tokio::main]
//! async fn main() -> shell_tunnel::Result<()> {
//!     // Initialize logging
//!     shell_tunnel::logging::try_init().ok();
//!
//!     // Create a session store
//!     let store = Arc::new(SessionStore::new());
//!
//!     // Create a new session
//!     let session_id = store.create()?;
//!
//!     // Run a command in it — a fresh shell per call, nothing kept between
//!     let executor = CommandExecutor::new(store);
//!     let result = executor
//!         .execute_in_session(&session_id, &Command::new("echo hello"))
//!         .await?;
//!
//!     println!("Session {} exited with {:?}", session_id, result.exit_code);
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
pub mod audit;
pub mod cli;
pub mod config;
pub mod error;
pub mod execution;
#[cfg(any(feature = "tls", feature = "relay-client"))]
pub mod fingerprint;
pub mod fs;
pub mod logging;
pub mod output;
mod process;
pub mod relay;
pub mod security;
pub mod session;
#[cfg(feature = "tls")]
pub mod tls;
pub mod tunnel;
#[cfg(feature = "self-update")]
pub mod update;

// Re-export commonly used types
pub use error::{Result, ShellTunnelError};
pub use execution::{Command, CommandExecutor, ExecutionResult};
pub use fs::{FsError, FsRoot};
pub use output::{OutputSanitizer, VirtualScreen};
pub use session::{Session, SessionContext, SessionId, SessionState, SessionStore};

// Re-export API types
pub use api::{AppState, ServerConfig};

// Re-export security types
pub use security::{
    ApiKeyStore, AuthConfig, CapabilitySet, CommandValidator, RateLimiter, TokenRecord,
    ValidationConfig,
};

// Re-export reachability types
pub use relay::{RelayConfig, RelayState};
pub use tunnel::{TunnelHandle, TunnelProvider};

// Re-export CLI and config types
pub use cli::{parse_args, print_help, print_version, Args};
pub use config::{Config, ConfigError};
