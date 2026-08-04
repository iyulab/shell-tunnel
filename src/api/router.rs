//! API router configuration.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{
        connect_info::IntoMakeServiceWithConnectInfo, DefaultBodyLimit, MatchedPath, Request, State,
    },
    http::{header::AUTHORIZATION, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{any, get, post},
    Router,
};
use tokio::sync::mpsc::UnboundedSender;
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

    // HEAD is GET without a body, and axum's `get()` serves it automatically, so
    // its authorization must equal GET's. Keyed separately below, every GET
    // route would need a twin HEAD arm — and a forgotten twin falls through to
    // the closed default `Authenticated`, which means any valid token, not the
    // capability GET requires. Normalising here is the one place it cannot be
    // forgotten. Matched as `&str` (rather than comparing `Method` values) so
    // the table below stays exactly as it reads for every other method.
    let method = match method.as_str() {
        "HEAD" => "GET",
        other => other,
    };

    match (method, matched_path) {
        (_, "/health") => Public,
        ("GET", "/api/v1") => Authenticated,
        ("POST", "/api/v1/execute") => Capability("exec"),
        (_, "/api/v1/ws") => Capability("exec"),
        ("GET", "/api/v1/sessions") => Capability("session.read"),
        ("POST", "/api/v1/sessions") => Capability("session.manage"),
        ("GET", "/api/v1/sessions/{id}") => Capability("session.read"),
        ("DELETE", "/api/v1/sessions/{id}") => Capability("session.manage"),
        ("POST", "/api/v1/sessions/{id}/execute") => Capability("exec"),
        (_, "/api/v1/sessions/{id}/ws") => Capability("exec"),
        ("GET", "/api/v1/fs/list") => Capability("fs.read"),
        ("GET", "/api/v1/fs/stat") => Capability("fs.read"),
        ("GET", "/api/v1/fs/file") => Capability("fs.read"),
        ("DELETE", "/api/v1/fs/file") => Capability("fs.write"),
        ("POST", "/api/v1/fs/uploads") => Capability("fs.write"),
        ("GET", "/api/v1/fs/uploads/{id}") => Capability("fs.write"),
        ("PATCH", "/api/v1/fs/uploads/{id}") => Capability("fs.write"),
        ("POST", "/api/v1/fs/uploads/{id}/complete") => Capability("fs.write"),
        ("DELETE", "/api/v1/fs/uploads/{id}") => Capability("fs.write"),
        _ => Authenticated,
    }
}

/// The longest raw request path an audit entry will carry, in bytes.
///
/// Only an *unmatched* path is recorded raw, and an unmatched path is whatever
/// the caller asked for — a probe can send four kilobytes of it and did, in the
/// measurement that set this number. A matched route is a router template and
/// is never truncated. The same log-flood worry already put the `tracing` line
/// beside this one at `debug`; the trail cannot be silenced by a log level, so
/// it needs the bound instead.
const MAX_AUDITED_PATH: usize = 256;

/// The `route` value for an audit entry.
///
/// A matched route is recorded as its template (`/api/v1/sessions/{id}`) so
/// that entries group rather than exploding into one bucket per id. An
/// unmatched path has no template, so the raw path is recorded: it is the only
/// thing that says *what was probed*, and probing is precisely what the trail
/// is asked about afterwards. Recording only the method left two different
/// probes with byte-identical entries — five distinct requests produced five
/// indistinguishable lines, confirmed against a running server, and a majority
/// of the `denied` entries on an internet-facing deployment were of that shape.
///
/// The caller passes `uri().path()`, never `path_and_query()`, and that is a
/// guarantee rather than a shortcut: a query string is caller-controlled too,
/// and `USAGE.md` §4 promises the trail never carries a credential. A probe of
/// `/nope?token=…` is recorded as `/nope` — confirmed by running it.
///
/// Truncation is marked with a suffix that begins with a space, which is not a
/// byte a request path can contain: a space terminates the request target, so
/// hyper answers `400` long before this function sees it. A caller therefore
/// cannot forge the marker by asking for a path that ends in it. (Raw control
/// bytes and invalid UTF-8 are refused at the same layer for the same kind of
/// reason, so this function is not where they need handling — measured, not
/// assumed, because "the parser surely rejects that" is the premise this
/// repository has been wrong about before.)
fn audited_route(method: &Method, matched: Option<&str>, raw_path: &str) -> String {
    let Some(template) = matched else {
        if raw_path.len() <= MAX_AUDITED_PATH {
            return format!("{method} {raw_path}");
        }
        // Back off to a character boundary; index 0 is always one, so this
        // terminates.
        let mut end = MAX_AUDITED_PATH;
        while !raw_path.is_char_boundary(end) {
            end -= 1;
        }
        return format!("{method} {} (truncated)", &raw_path[..end]);
    };
    format!("{method} {template}")
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
    //
    // `None` and `Some("")` are not the same thing and are no longer flattened
    // together: a path the router did not match has no template, and the raw
    // path is the only description of it that exists. Authorization still sees
    // the empty string for it (`required_capability` fails closed on it), but
    // the audit entry does not.
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned());
    let route = audited_route(&method, matched.as_deref(), request.uri().path());
    let required = required_capability(&method, matched.as_deref().unwrap_or_default());

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
            tracing::debug!(%method, path = %route, reason, "auth rejected (401)");
            // Probing is exactly what an audit trail is asked about afterwards,
            // so this layer's refusals are recorded as well as successes.
            //
            // "This layer's" is the whole claim, not modesty. Refusals that
            // happen after this middleware has let a request through — an
            // extractor turning away an unrecognised field, a malformed body, a
            // path parameter that will not parse, a body over the size limit —
            // record nothing, so the trail is not a complete list of every
            // refusal the server issued. `USAGE.md` §4 names that gap and lists
            // the measured cases; keep the two in step as the layer grows.
            audit
                .record_async(
                    crate::audit::AuditEvent::new("denied")
                        .with_route(route)
                        .with_denial(401, reason),
                )
                .await;
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
                audit
                    .record_async(
                        crate::audit::AuditEvent::new("denied")
                            .with_identity(identity)
                            .with_route(route.clone())
                            .with_denial(403, format!("missing-capability:{cap}")),
                    )
                    .await;
                tracing::debug!(
                    %method,
                    path = %route,
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

/// Headers a reverse proxy adds, in the order operators are likeliest to meet.
///
/// `Forwarded` is the standardised one; the two `X-` names predate it and are
/// what nginx, Apache, IIS and every cloud load balancer actually send.
const PROXY_HEADERS: [&str; 3] = ["x-forwarded-for", "x-real-ip", "forwarded"];

/// Say so, once, if a request arrives through a proxy while auth is off.
///
/// The posture this server picks is decided by its bind address: loopback is
/// read as "not reachable", and authentication, the `operator` scope and
/// automatic audit are all released on that reading. A reverse proxy breaks the
/// premise without changing the bind address — every request then appears to
/// come from `127.0.0.1` — so the server goes on believing it is private while
/// being as reachable as the proxy is. This product *recommends* that
/// arrangement: putting a reverse proxy in front is what its own error message
/// tells an operator to do when they ask a gateway for TLS.
///
/// Documentation already says this at each place the arrangement is suggested,
/// but documentation only protects whoever reads it. This is the observation
/// that needs no reading: a request carrying `X-Forwarded-For` is evidence,
/// arriving on the very path that matters, that something is in front.
///
/// Only ever a warning, which is what makes the forgeability of these headers
/// irrelevant: anyone who can reach an unauthenticated exec API has no use for
/// making it warn about itself. And only where auth is off — a server that
/// authenticates is behind a proxy on purpose and needs no telling.
///
/// The default is deliberately not changed. Loopback-means-no-auth is the
/// local-development experience, and trading it away is a product decision, not
/// one to slip in beside a warning.
async fn proxy_evidence_middleware(
    State((warned, audited)): State<(Arc<std::sync::atomic::AtomicBool>, bool)>,
    request: Request,
    next: Next,
) -> Response {
    use std::sync::atomic::Ordering;

    // The common case is the already-warned one; keep it to a single load.
    if !warned.load(Ordering::Relaxed) {
        if let Some(header) = PROXY_HEADERS
            .iter()
            .find(|name| request.headers().contains_key(**name))
        {
            // Whoever loses the race warned; the other stays quiet.
            if !warned.swap(true, Ordering::Relaxed) {
                // Written as separate calls, never one literal split with a
                // backslash: `cargo fmt` folds that into a line with a gap in
                // the middle, and it has shipped that way here four times.
                //
                // Each line asserts only what was checked. Whether the bind
                // address is loopback is not checked — a library consumer can
                // disable auth on any address — and whether a trail is being
                // written is read rather than assumed, because an operator who
                // passed --audit-log has one.
                tracing::warn!("A request arrived carrying {header}, which a reverse proxy adds.");
                tracing::warn!("Authentication is off on this server, so whatever reaches it can run commands — and something in front means that is wherever the proxy is reachable, not just this machine.");
                if !audited {
                    tracing::warn!(
                        "No audit trail is configured either, so none of it is being recorded."
                    );
                    tracing::warn!("Restart with --require-auth, and --audit-log <FILE> to keep a record. This warning is printed once.");
                } else {
                    tracing::warn!("Restart with --require-auth. This warning is printed once.");
                }
            }
        }
    }

    next.run(request).await
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

    // Only where there is something to warn about: a server that authenticates
    // is behind whatever is in front of it on purpose.
    if !auth_store.is_enabled() {
        router = router.layer(middleware::from_fn_with_state(
            (
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                state.audit.is_enabled(),
            ),
            proxy_evidence_middleware,
        ));
    }

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
    /// Where to report an API key this server generated for itself.
    ///
    /// [`serve_on`] generates one when authentication is on and no key was
    /// registered. It used to write that key to the log, which handed an
    /// embedding consumer a plaintext secret in whatever its logs go to. It now
    /// sends the key here instead: the library reports the fact, the caller
    /// decides where it goes — the arrangement
    /// [`crate::relay::client::RelayClientConfig`]'s `enrolled` already uses.
    ///
    /// `None` leaves the key unreported, and [`serve_on`] warns when it lands
    /// there — a key nobody can read authenticates nobody. Register a key with
    /// [`SecurityConfig::with_api_key`] if you have one; set this if you want
    /// the generated one.
    ///
    /// The send happens before the listener starts accepting, and the channel
    /// is unbounded, so the key waits in it: spawn [`serve_on`] and receive
    /// afterwards. Nothing needs to be draining it first.
    pub generated_key: Option<UnboundedSender<String>>,
}

impl ServerConfig {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            security: SecurityConfig::default(),
            graceful_shutdown: true,
            generated_key: None,
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

    /// Report a key this server generates for itself on `tx`.
    ///
    /// See [`ServerConfig::generated_key`] for when that happens and what
    /// leaving it unset costs.
    pub fn report_generated_key_to(mut self, tx: UnboundedSender<String>) -> Self {
        self.generated_key = Some(tx);
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
            generated_key: None,
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
            match &config.generated_key {
                Some(tx) => {
                    let _ = tx.send(key);
                }
                // Reported nowhere, and deliberately not logged: this used to
                // put a plaintext secret in the consumer's log. Saying so is
                // the difference between "the caller chose not to collect it"
                // and "the server is now holding a key nobody can present".
                None => tracing::warn!("authentication is on with no API key registered, so one was generated — but ServerConfig::generated_key is unset and the key is not logged, so nothing can read it. Register a key with SecurityConfig::with_api_key, or set that channel."),
            }
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
    // The chunk-upload route carries request bodies up to `MAX_CHUNK_SIZE` (8
    // MiB) — well above axum-core's own default body limit (2 MiB, axum-core
    // 0.5.6's `DEFAULT_LIMIT`), which this app otherwise never overrides. A
    // client sending a chunk at the server's own advertised `chunk_size` (4
    // MiB default) would have it rejected before `append_chunk` ever ran.
    //
    // Raised only for this one path, via a merged sub-router, rather than
    // `.layer()` on the whole `fs_routes` router: the latter would also raise
    // the limit for `/list`, `/stat`, and `/file`, none of which need an 8
    // MiB body, and a limit set any higher up would reach `/api/v1/execute`
    // too. Set at the hard ceiling (`MAX_CHUNK_SIZE`) rather than the
    // *configured* `chunk_size`, so a chunk larger than configured but still
    // under the ceiling reaches `append_chunk`'s own `TooLarge` check and
    // gets a 413 with a machine-readable body — if axum's limit cut it off
    // first, the caller would get a bodyless 413 with no way to tell why.
    let upload_session_routes = Router::new()
        .route(
            "/uploads/{id}",
            get(super::fs::upload_status)
                .patch(super::fs::append_chunk)
                .delete(super::fs::cancel_upload),
        )
        .route_layer(DefaultBodyLimit::max(crate::fs::MAX_CHUNK_SIZE));

    Router::new()
        .route("/list", get(super::fs::list))
        .route("/stat", get(super::fs::stat))
        .route(
            "/file",
            get(super::fs::download).delete(super::fs::delete_file),
        )
        .route("/uploads", post(super::fs::create_upload))
        .merge(upload_session_routes)
        .route("/uploads/{id}/complete", post(super::fs::complete_upload))
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

    // A direct unit-level check of the `HEAD` normalisation lived here once,
    // hardcoding three fs paths. It is superseded by
    // `every_get_fs_route_authorizes_head_identically` in `tests/fs_api.rs`,
    // which derives the same check from the one authoritative route table
    // (shared with `every_fs_route_declares_a_capability`) instead of a
    // second, hand-maintained list that could drift from it.

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
