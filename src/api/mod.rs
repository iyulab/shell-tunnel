//! API layer for shell-tunnel.
//!
//! This module provides REST API and WebSocket endpoints for interacting
//! with shell sessions programmatically.
//!
//! ## Endpoints
//!
//! ### Health & Info
//! - `GET /health` - Health check
//! - `GET /api/v1/` - API information
//!
//! ### Sessions
//! - `GET /api/v1/sessions` - List all sessions
//! - `POST /api/v1/sessions` - Create a new session
//! - `GET /api/v1/sessions/{id}` - Get session status
//! - `DELETE /api/v1/sessions/{id}` - Delete a session
//! - `POST /api/v1/sessions/{id}/execute` - Execute command in session
//! - `WS /api/v1/sessions/{id}/ws` - WebSocket for streaming
//!
//! ### One-shot Execution
//! - `POST /api/v1/execute` - Execute command without session
//! - `WS /api/v1/ws` - WebSocket for one-shot streaming
//!
//! ## Example
//!
//! ```no_run
//! use shell_tunnel::api::{ServerConfig, serve};
//!
//! #[tokio::main]
//! async fn main() -> shell_tunnel::Result<()> {
//!     let config = ServerConfig::new("127.0.0.1", 3000);
//!     serve(config).await
//! }
//! ```

pub mod handlers;
pub mod router;
pub mod types;
pub mod websocket;

// Re-export commonly used types
pub use handlers::AppState;
pub use router::{create_router, create_router_with_state, serve, serve_with_state, ServerConfig};
pub use types::{
    CreateSessionRequest, CreateSessionResponse, ErrorResponse, ExecuteCommandRequest,
    ExecuteCommandResponse, ListSessionsResponse, SessionStatusResponse, WsMessage,
};
