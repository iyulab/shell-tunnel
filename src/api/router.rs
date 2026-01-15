//! API router configuration.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::connect_info::IntoMakeServiceWithConnectInfo,
    middleware,
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
use crate::security::{
    auth_middleware, rate_limit_middleware, ApiKeyStore, AuthConfig, RateLimitConfig, RateLimiter,
};

/// Security configuration for the server.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitConfig,
    /// API keys to pre-register.
    pub api_keys: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            auth: AuthConfig::disabled(), // Disabled by default for ease of use
            rate_limit: RateLimitConfig::default(),
            api_keys: Vec::new(),
        }
    }
}

impl SecurityConfig {
    /// Create a secure configuration.
    pub fn secure() -> Self {
        Self {
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            api_keys: Vec::new(),
        }
    }

    /// Create a development configuration (no auth, relaxed limits).
    pub fn development() -> Self {
        Self {
            auth: AuthConfig::disabled(),
            rate_limit: RateLimitConfig::relaxed(),
            api_keys: Vec::new(),
        }
    }

    /// Add an API key.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_keys.push(key.into());
        self
    }
}

/// Create the API router with all routes configured.
pub fn create_router() -> Router {
    create_router_with_state(AppState::new())
}

/// Create the API router with custom state (no security).
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

/// Create the API router with security enabled.
pub fn create_secure_router(
    state: AppState,
    security: SecurityConfig,
) -> (Router, Arc<ApiKeyStore>, Arc<RateLimiter>) {
    // Create security components
    let auth_store = Arc::new(ApiKeyStore::new(security.auth));
    let rate_limiter = Arc::new(RateLimiter::new(security.rate_limit));

    // Register API keys
    for key in &security.api_keys {
        auth_store.add_key(key);
    }

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

    // Build main router with security layers
    let router = Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api_v1)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&auth_store),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&rate_limiter),
            rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    (router, auth_store, rate_limiter)
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Host address to bind to.
    pub host: String,
    /// Port to listen on.
    pub port: u16,
    /// Security configuration.
    pub security: SecurityConfig,
    /// Enable graceful shutdown on SIGTERM/SIGINT.
    pub graceful_shutdown: bool,
}

impl ServerConfig {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            security: SecurityConfig::default(),
            graceful_shutdown: true,
        }
    }

    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Enable security with the given configuration.
    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// Disable graceful shutdown.
    pub fn without_graceful_shutdown(mut self) -> Self {
        self.graceful_shutdown = false;
        self
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            security: SecurityConfig::default(),
            graceful_shutdown: true,
        }
    }
}

/// Start the API server.
pub async fn serve(config: ServerConfig) -> crate::Result<()> {
    serve_with_state(config, AppState::new()).await
}

/// Start the API server with custom state.
pub async fn serve_with_state(config: ServerConfig, state: AppState) -> crate::Result<()> {
    let addr = config.bind_address();

    // Create router with security
    let (router, auth_store, _rate_limiter) =
        create_secure_router(state, config.security.clone());

    // Log API key if auth is enabled and keys are registered
    if auth_store.is_enabled() {
        if auth_store.count() == 0 {
            // Generate and register a key if none provided
            let key = crate::security::generate_api_key();
            auth_store.add_key(&key);
            tracing::info!("Generated API key: {}", key);
        }
        tracing::info!(
            "Authentication enabled with {} API key(s)",
            auth_store.count()
        );
    } else {
        tracing::warn!("Authentication is DISABLED - server is open to all requests");
    }

    tracing::info!("Starting shell-tunnel API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(crate::error::ShellTunnelError::Io)?;

    // Create service with connection info for rate limiting
    let service: IntoMakeServiceWithConnectInfo<Router, SocketAddr> =
        router.into_make_service_with_connect_info::<SocketAddr>();

    if config.graceful_shutdown {
        // Serve with graceful shutdown
        axum::serve(listener, service)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| {
                crate::error::ShellTunnelError::Io(std::io::Error::other(e.to_string()))
            })?;

        tracing::info!("Server shutdown complete");
    } else {
        // Serve without graceful shutdown
        axum::serve(listener, service).await.map_err(|e| {
            crate::error::ShellTunnelError::Io(std::io::Error::other(e.to_string()))
        })?;
    }

    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown...");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }
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
        assert!(config.graceful_shutdown);
    }

    #[test]
    fn test_server_config_custom() {
        let config = ServerConfig::new("0.0.0.0", 8080);
        assert_eq!(config.bind_address(), "0.0.0.0:8080");
    }

    #[test]
    fn test_server_config_with_security() {
        let config = ServerConfig::new("0.0.0.0", 8080)
            .with_security(SecurityConfig::secure().with_api_key("test-key"));

        assert!(config.security.auth.enabled);
        assert_eq!(config.security.api_keys.len(), 1);
    }

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert!(!config.auth.enabled); // Disabled by default
        assert!(config.rate_limit.enabled);
    }

    #[test]
    fn test_security_config_secure() {
        let config = SecurityConfig::secure();
        assert!(config.auth.enabled);
        assert!(config.rate_limit.enabled);
    }

    #[test]
    fn test_security_config_development() {
        let config = SecurityConfig::development();
        assert!(!config.auth.enabled);
        assert!(config.rate_limit.enabled);
    }

    #[test]
    fn test_router_creation() {
        let _router = create_router();
        // Router created successfully
    }

    #[test]
    fn test_secure_router_creation() {
        let state = AppState::new();
        let security = SecurityConfig::secure().with_api_key("test-key");
        let (router, auth_store, rate_limiter) = create_secure_router(state, security);

        assert_eq!(auth_store.count(), 1);
        assert!(auth_store.is_valid("test-key"));
        assert!(rate_limiter.is_enabled());

        // Router should be created
        drop(router);
    }
}
