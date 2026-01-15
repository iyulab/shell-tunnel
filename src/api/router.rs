//! API router configuration.

use axum::{
    routing::{any, get, post},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use super::handlers::{
    api_info, create_session, delete_session, execute_command, execute_oneshot, get_session,
    health, list_sessions, AppState,
};
use super::websocket::{ws_handler, ws_oneshot_handler};

/// Create the API router with all routes configured.
pub fn create_router() -> Router {
    create_router_with_state(AppState::new())
}

/// Create the API router with custom state.
pub fn create_router_with_state(state: AppState) -> Router {
    // Session routes
    let session_routes = Router::new()
        .route("/", get(list_sessions).post(create_session))
        .route("/{id}", get(get_session).delete(delete_session))
        .route("/{id}/execute", post(execute_command))
        .route("/{id}/ws", any(ws_handler));

    // API v1 routes
    let api_v1 = Router::new()
        .route("/", get(api_info))
        .route("/execute", post(execute_oneshot))
        .route("/ws", any(ws_oneshot_handler))
        .nest("/sessions", session_routes);

    // Build main router
    Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api_v1)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Host address to bind to.
    pub host: String,
    /// Port to listen on.
    pub port: u16,
}

impl ServerConfig {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
        }
    }
}

/// Start the API server.
pub async fn serve(config: ServerConfig) -> crate::Result<()> {
    let addr = config.bind_address();
    let router = create_router();

    tracing::info!("Starting shell-tunnel API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(crate::error::ShellTunnelError::Io)?;

    axum::serve(listener, router)
        .await
        .map_err(|e| crate::error::ShellTunnelError::Io(std::io::Error::other(e.to_string())))?;

    Ok(())
}

/// Start the API server with custom state.
pub async fn serve_with_state(config: ServerConfig, state: AppState) -> crate::Result<()> {
    let addr = config.bind_address();
    let router = create_router_with_state(state);

    tracing::info!("Starting shell-tunnel API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(crate::error::ShellTunnelError::Io)?;

    axum::serve(listener, router)
        .await
        .map_err(|e| crate::error::ShellTunnelError::Io(std::io::Error::other(e.to_string())))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 3000);
        assert_eq!(config.bind_address(), "127.0.0.1:3000");
    }

    #[test]
    fn test_server_config_custom() {
        let config = ServerConfig::new("0.0.0.0", 8080);
        assert_eq!(config.bind_address(), "0.0.0.0:8080");
    }

    #[test]
    fn test_router_creation() {
        let _router = create_router();
        // Router created successfully
    }
}
