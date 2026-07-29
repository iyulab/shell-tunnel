//! API router configuration.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{connect_info::IntoMakeServiceWithConnectInfo, MatchedPath, Request, State},
    http::{header::AUTHORIZATION, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
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
    rate_limit_middleware, ApiKeyStore, AuthConfig, CapabilitySet, RateLimitConfig, RateLimiter,
};

/// Cross-Origin Resource Sharing (CORS) configuration.
///
/// CORS is a browser-enforced mechanism; non-browser clients (`curl`, SDKs)
/// ignore it entirely. shell-tunnel therefore emits **no** permissive CORS headers
/// by default: this blocks a malicious web page from reading responses cross-origin
/// and, because the JSON execute endpoints require a preflight, from issuing the
/// request at all — with zero impact on the intended non-browser consumers.
///
/// Note: CORS does **not** defend against DNS-rebinding (the attacker's host is
/// rebound to `127.0.0.1`, making the request same-origin); that requires
/// Host-header validation and is tracked separately.
#[derive(Debug, Clone, Default)]
pub struct CorsConfig {
    /// Allow any origin/method/header (restores the permissive `Any` behavior).
    /// Off by default; enable only for trusted browser-based UIs.
    pub allow_any: bool,
}

/// Security configuration for the server.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitConfig,
    /// API keys to pre-register.
    pub api_keys: Vec<String>,
    /// Capabilities granted to the pre-registered keys and to the
    /// auto-generated fallback key.
    ///
    /// `None` (the default) means **full-control** (wildcard) — the backward-
    /// compatible behavior for a bare `--api-key` / `--require-auth` (spec §4).
    /// `Some(set)` issues fine-grained tokens scoped to that set (spec §9).
    pub capabilities: Option<CapabilitySet>,
    /// CORS configuration.
    pub cors: CorsConfig,
    /// Host names this server answers to, when it is worth checking.
    ///
    /// `None` disables the check. It is meant for a loopback-bound server, where
    /// DNS rebinding is the one attack CORS cannot stop: the attacker's name is
    /// rebound to `127.0.0.1`, so the browser considers the request same-origin
    /// and sends it. The `Host` header still carries the attacker's name, which
    /// is what this compares. A published server is deliberately reachable under
    /// a name we may not know, so the check does not apply there.
    pub allowed_hosts: Option<Vec<String>>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            auth: AuthConfig::disabled(), // Disabled by default for ease of use
            rate_limit: RateLimitConfig::default(),
            api_keys: Vec::new(),
            capabilities: None, // Full-control by default (legacy-compatible)
            cors: CorsConfig::default(), // Restrictive by default (no permissive CORS)
            allowed_hosts: None,
        }
    }
}

/// Build a permissive CORS layer when `allow_any` is set, otherwise `None`.
///
/// Returning `None` means no CORS headers are emitted — the secure default.
fn cors_layer(cfg: &CorsConfig) -> Option<CorsLayer> {
    cfg.allow_any.then(|| {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    })
}

impl SecurityConfig {
    /// Create a secure configuration.
    pub fn secure() -> Self {
        Self {
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            api_keys: Vec::new(),
            capabilities: None,
            cors: CorsConfig::default(),
            allowed_hosts: None,
        }
    }

    /// Create a development configuration (no auth, relaxed limits).
    pub fn development() -> Self {
        Self {
            auth: AuthConfig::disabled(),
            rate_limit: RateLimitConfig::relaxed(),
            api_keys: Vec::new(),
            capabilities: None,
            cors: CorsConfig::default(),
            allowed_hosts: None,
        }
    }

    /// Add an API key.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_keys.push(key.into());
        self
    }

    /// Scope the issued tokens to a fine-grained capability set (spec §9).
    ///
    /// Applies to the pre-registered keys and to the auto-generated fallback
    /// key. Without this, tokens are full-control (legacy-compatible).
    pub fn with_capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Answer only to these host names.
    pub fn with_allowed_hosts(mut self, hosts: Vec<String>) -> Self {
        self.allowed_hosts = Some(hosts);
        self
    }

    /// Enable permissive (`Any`) CORS. Opt-in; only for trusted browser UIs.
    pub fn with_cors_allow_any(mut self) -> Self {
        self.cors.allow_any = true;
        self
    }
}

/// Register `key` into `store` with `capabilities` (fine-grained), or as a
/// legacy full-control key when `capabilities` is `None` (spec §4/§9).
fn register_key(store: &ApiKeyStore, key: &str, capabilities: &Option<CapabilitySet>) {
    match capabilities {
        Some(caps) => store.add_key_with_capabilities(key, caps.clone(), "configured"),
        None => store.add_key(key),
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
        .nest("/fs", fs_routes())
        .nest("/sessions", session_routes);

    // Build main router. This "no security" convenience constructor uses the
    // restrictive CORS default (no permissive CORS headers emitted).
    Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api_v1)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// The capability a route requires (Phase A spec §3).
///
/// Declared here at the router layer — co-located with the route definitions,
/// which are the single source of truth for the matched-path strings this maps
/// against. Not a per-handler attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredCapability {
    /// No authentication at all (e.g. `/health`).
    Public,
    /// Authenticated only: any valid token passes, no specific capability
    /// required (spec §3 "인증만" tier, e.g. `GET /api/v1`).
    Authenticated,
    /// Requires a specific capability string (set membership, or wildcard).
    Capability(&'static str),
}

/// Map a matched route (`method` + axum [`MatchedPath`]) to its required
/// capability (spec §3 table).
///
/// Keyed on the **full nested** `MatchedPath` (confirmed against the real router
/// structure) plus the HTTP method, because one path can require different
/// capabilities per method (e.g. `GET /api/v1/sessions` = read, `POST` = manage).
///
/// Unknown routes fail **closed** to [`RequiredCapability::Authenticated`]: an
/// unmapped route still requires a valid token, never less than that.
pub fn required_capability(method: &Method, matched_path: &str) -> RequiredCapability {
    use RequiredCapability::{Authenticated, Capability, Public};

    match (method, matched_path) {
        (_, "/health") => Public,
        (&Method::GET, "/api/v1") => Authenticated,
        (&Method::POST, "/api/v1/execute") => Capability("exec"),
        (_, "/api/v1/ws") => Capability("exec"),
        (&Method::GET, "/api/v1/sessions") => Capability("session.read"),
        (&Method::POST, "/api/v1/sessions") => Capability("session.manage"),
        (&Method::GET, "/api/v1/sessions/{id}") => Capability("session.read"),
        (&Method::DELETE, "/api/v1/sessions/{id}") => Capability("session.manage"),
        (&Method::POST, "/api/v1/sessions/{id}/execute") => Capability("exec"),
        (_, "/api/v1/sessions/{id}/ws") => Capability("exec"),
        (&Method::GET, "/api/v1/fs/list") => Capability("fs.read"),
        (&Method::GET, "/api/v1/fs/stat") => Capability("fs.read"),
        (&Method::GET, "/api/v1/fs/file") => Capability("fs.read"),
        (&Method::DELETE, "/api/v1/fs/file") => Capability("fs.write"),
        (&Method::POST, "/api/v1/fs/uploads") => Capability("fs.write"),
        (&Method::GET, "/api/v1/fs/uploads/{id}") => Capability("fs.write"),
        (&Method::PATCH, "/api/v1/fs/uploads/{id}") => Capability("fs.write"),
        (&Method::POST, "/api/v1/fs/uploads/{id}/complete") => Capability("fs.write"),
        (&Method::DELETE, "/api/v1/fs/uploads/{id}") => Capability("fs.write"),
        _ => Authenticated,
    }
}

/// Scope-aware authentication + authorization middleware (spec §5).
///
/// 1. Resolve the route's required capability from `method` + `MatchedPath`.
/// 2. `Public` route or auth disabled → pass through.
/// 3. Extract the bearer token; look up its `TokenRecord` in the store.
///    Missing/invalid token → **401**.
/// 4. `Authenticated` route → any valid token passes. `Capability(c)` route →
///    the token's set must satisfy `c` (membership or wildcard), else **403**.
async fn capability_auth_middleware(
    State((store, audit)): State<(
        std::sync::Arc<ApiKeyStore>,
        std::sync::Arc<crate::audit::AuditSink>,
    )>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Auth disabled → open server (existing behavior).
    if !store.is_enabled() {
        return Ok(next.run(request).await);
    }

    let method = request.method().clone();
    // Owned so it can be used in the rejection logs after `request` is consumed.
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    let required = required_capability(&method, &matched);

    // Public routes (e.g. /health) skip auth entirely.
    if required == RequiredCapability::Public {
        return Ok(next.run(request).await);
    }

    // Extract the bearer token and resolve its capabilities.
    // Missing header, wrong prefix, or unregistered token → 401.
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|header| store.extract_key(header));

    let identity = token.as_deref().and_then(|t| store.identity(t));

    let capabilities = match token.as_deref().and_then(|t| store.capabilities(t)) {
        Some(caps) => caps,
        None => {
            // Logged at debug to avoid a log-flood amplifier under probing; the
            // token value itself is never logged. `missing-token` = no/malformed
            // Authorization header, `invalid-token` = present but unregistered.
            let reason = if token.is_none() {
                "missing-token"
            } else {
                "invalid-token"
            };
            tracing::debug!(%method, path = %matched, reason, "auth rejected (401)");
            // Probing is exactly what an audit trail is asked about afterwards,
            // so refusals are recorded as well as successes.
            audit.record(
                crate::audit::AuditEvent::new("denied")
                    .with_route(format!("{method} {matched}"))
                    .with_denial(401, reason),
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Handlers record what actually ran, and need to know who asked.
    if let Some(identity) = identity.clone() {
        request.extensions_mut().insert(identity);
    }

    match required {
        // Already handled above, but keep the match exhaustive.
        RequiredCapability::Public => Ok(next.run(request).await),
        // Any valid token satisfies an authenticated-only route.
        RequiredCapability::Authenticated => Ok(next.run(request).await),
        // Specific capability: set membership (or wildcard) required, else 403.
        RequiredCapability::Capability(cap) => {
            if capabilities.satisfies(cap) {
                Ok(next.run(request).await)
            } else {
                audit.record(
                    crate::audit::AuditEvent::new("denied")
                        .with_identity(identity)
                        .with_route(format!("{method} {matched}"))
                        .with_denial(403, format!("missing-capability:{cap}")),
                );
                tracing::debug!(
                    %method,
                    path = %matched,
                    required = cap,
                    "authorization denied (403): insufficient capability"
                );
                Err(StatusCode::FORBIDDEN)
            }
        }
    }
}

/// Whether `header` names a host this server answers to.
///
/// Compared without the port, since the port is not what an attacker controls
/// in a rebinding attack, and a legitimate caller may reach the same server
/// through different ports.
fn host_is_allowed(header: Option<&str>, allowed: &[String]) -> bool {
    let Some(value) = header else {
        // HTTP/1.1 requires a Host header; its absence is not a shape any
        // ordinary client produces.
        return false;
    };

    let host = value
        .rsplit_once(':')
        .map_or(value, |(host, port)| {
            // Only strip a trailing port, not part of a bare IPv6 address.
            if port.chars().all(|c| c.is_ascii_digit()) {
                host
            } else {
                value
            }
        })
        .trim_matches(|c| c == '[' || c == ']');

    allowed
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(host))
}

/// Reject requests carrying a `Host` this server does not answer to.
async fn host_check_middleware(
    State(allowed): State<Arc<Vec<String>>>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let header = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok());

    if host_is_allowed(header, &allowed) {
        return Ok(next.run(request).await);
    }

    // Named explicitly: an operator hitting this from a container or behind a
    // proxy needs to know which name was refused and how to permit it.
    let seen = header.unwrap_or("(none)").to_string();
    tracing::debug!(host = %seen, "request refused: host not allowed");
    Err((
        StatusCode::FORBIDDEN,
        format!(
            "host {seen} is not allowed; pass --allow-host {seen} to permit it
"
        ),
    ))
}

/// Create the API router with security enabled.
pub fn create_secure_router(
    state: AppState,
    security: SecurityConfig,
) -> (Router, Arc<ApiKeyStore>, Arc<RateLimiter>) {
    // Create security components
    let auth_store = Arc::new(ApiKeyStore::new(security.auth));
    let rate_limiter = Arc::new(RateLimiter::new(security.rate_limit));

    // Register API keys with their configured capabilities.
    for key in &security.api_keys {
        register_key(&auth_store, key, &security.capabilities);
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
        .nest("/fs", fs_routes())
        .nest("/sessions", session_routes);

    let allowed_hosts = security.allowed_hosts.clone();

    // Build main router with security layers
    let mut router = Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api_v1)
        .layer(middleware::from_fn_with_state(
            (Arc::clone(&auth_store), Arc::clone(&state.audit)),
            capability_auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&rate_limiter),
            rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http());

    // Outermost, so a rebound request is refused before it reaches the token
    // store or the rate limiter's bookkeeping.
    if let Some(hosts) = allowed_hosts {
        router = router.layer(middleware::from_fn_with_state(
            Arc::new(hosts),
            host_check_middleware,
        ));
    }

    // Permissive CORS only when explicitly opted in (default: restrictive).
    if let Some(cors) = cors_layer(&security.cors) {
        router = router.layer(cors);
    }

    let router = router.with_state(state);

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

/// Bind the API server's port without starting to serve.
///
/// Callers that need to know the port before traffic flows — anything binding
/// port 0, where the OS chooses — take the listener from here and hand it to
/// [`serve_on`]. Splitting bind from serve is what makes an ephemeral port
/// usable: the alternative is binding twice and racing whoever grabs it in
/// between.
pub async fn bind(config: &ServerConfig) -> crate::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(config.bind_address())
        .await
        .map_err(crate::error::ShellTunnelError::Io)
}

/// Start the API server with custom state.
pub async fn serve_with_state(config: ServerConfig, state: AppState) -> crate::Result<()> {
    let listener = bind(&config).await?;
    serve_on(listener, config, state).await
}

/// Serve on an already-bound listener.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    config: ServerConfig,
    state: AppState,
) -> crate::Result<()> {
    let addr = config.bind_address();

    // Create router with security
    let (router, auth_store, _rate_limiter) = create_secure_router(state, config.security.clone());

    // Log API key if auth is enabled and keys are registered
    if auth_store.is_enabled() {
        if auth_store.count() == 0 {
            // Generate and register a key if none provided, scoped to the
            // configured capabilities (full-control when unset).
            let key = crate::security::generate_api_key();
            register_key(&auth_store, &key, &config.security.capabilities);
            tracing::info!("Generated API key: {}", key);
        }
        tracing::info!(
            "Authentication enabled with {} API key(s)",
            auth_store.count()
        );
    } else {
        tracing::warn!("Authentication is DISABLED - server is open to all requests");
    }

    let _ = addr;
    tracing::info!(
        "Starting shell-tunnel API server on {}",
        listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| config.bind_address())
    );

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

/// Filesystem routes, shared by the plain and the secured router.
///
/// Built in one place so the two constructors cannot drift apart — a route
/// present in only one of them is reachable in only one deployment shape.
fn fs_routes() -> Router<AppState> {
    Router::new().route("/stat", get(super::fs::stat))
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
    fn test_cors_restrictive_by_default() {
        assert!(!SecurityConfig::default().cors.allow_any);
        assert!(!SecurityConfig::secure().cors.allow_any);
        assert!(cors_layer(&CorsConfig::default()).is_none());
    }

    #[test]
    fn test_cors_allow_any_opt_in() {
        let config = SecurityConfig::development().with_cors_allow_any();
        assert!(config.cors.allow_any);
        assert!(cors_layer(&config.cors).is_some());
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
    fn test_required_capability_mapping() {
        use RequiredCapability::{Authenticated, Capability, Public};

        // Public + authenticated-only tiers.
        assert_eq!(required_capability(&Method::GET, "/health"), Public);
        assert_eq!(required_capability(&Method::GET, "/api/v1"), Authenticated);

        // exec routes (oneshot + session-scoped + WS).
        assert_eq!(
            required_capability(&Method::POST, "/api/v1/execute"),
            Capability("exec")
        );
        assert_eq!(
            required_capability(&Method::GET, "/api/v1/ws"),
            Capability("exec")
        );
        assert_eq!(
            required_capability(&Method::POST, "/api/v1/sessions/{id}/execute"),
            Capability("exec")
        );
        assert_eq!(
            required_capability(&Method::GET, "/api/v1/sessions/{id}/ws"),
            Capability("exec")
        );

        // read vs manage split on the same path, keyed by method.
        assert_eq!(
            required_capability(&Method::GET, "/api/v1/sessions"),
            Capability("session.read")
        );
        assert_eq!(
            required_capability(&Method::POST, "/api/v1/sessions"),
            Capability("session.manage")
        );
        assert_eq!(
            required_capability(&Method::GET, "/api/v1/sessions/{id}"),
            Capability("session.read")
        );
        assert_eq!(
            required_capability(&Method::DELETE, "/api/v1/sessions/{id}"),
            Capability("session.manage")
        );
    }

    #[test]
    fn test_required_capability_unknown_fails_closed() {
        // An unmapped route requires at least a valid token (never less).
        assert_eq!(
            required_capability(&Method::GET, "/api/v1/unknown"),
            RequiredCapability::Authenticated
        );
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
