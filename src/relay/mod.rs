//! Self-hosted relay: reaching a device that dialled out to you.
//!
//! The relay is the alternative to a third-party tunnel. A device opens one
//! outbound WebSocket to it — no inbound port, no NAT configuration — and the
//! relay routes public traffic back down that connection.
//!
//! It runs from the same binary (`shell-tunnel relay`), so an operator never
//! has to match versions between two programs.
//!
//! What the relay deliberately does *not* do: interpret capability tokens.
//! Enrollment decides which devices may attach; the capability token in each
//! proxied request stays end-to-end between client and device. The relay is a
//! router, not a second security boundary.

#[cfg(feature = "relay-client")]
pub mod client;
pub mod protocol;
pub mod proxy;
pub mod registry;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        FromRequestParts, Request, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use futures_util::{SinkExt, StreamExt};

use crate::error::ShellTunnelError;
use crate::security::{generate_api_key, rate_limit_middleware, RateLimitConfig, RateLimiter};
use protocol::{reject, DeviceMessage, RelayMessage, PROTOCOL_VERSION};
use proxy::{
    is_forwardable, split_device_path, ProxyRequest, ProxyResponse, POOL_WAIT, REQUEST_TIMEOUT,
};
use registry::{Device, DeviceRegistry};

pub use registry::{DeviceRegistry as Registry, POOL_TARGET};

/// How long a device may go without a heartbeat before it is considered gone.
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

/// How long to wait for the enrollment frame before dropping a connection.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Relay server settings.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Address to listen on.
    pub bind: SocketAddr,
    /// Secret a device must present to attach.
    pub enroll_token: String,
    /// Per-IP request limiting for this relay.
    ///
    /// The relay is the only place this can work for proxied traffic: a device
    /// replays requests to its own loopback listener, so *its* limiter sees
    /// 127.0.0.1 for every caller and cannot tell them apart. Here the real
    /// client address is still visible.
    pub rate_limit: RateLimitConfig,
    /// Serve HTTPS directly instead of relying on a reverse proxy.
    #[cfg(feature = "tls")]
    pub tls: Option<crate::tls::TlsFiles>,
    /// Public base URL of this relay, when the operator states it explicitly.
    ///
    /// Left unset, the relay derives it from each connection's `Host` (and
    /// `X-Forwarded-*`) headers, so a relay behind TLS termination still tells
    /// devices an address that actually works.
    pub public_base: Option<String>,
}

impl RelayConfig {
    /// Create a configuration with the given bind address and token.
    pub fn new(bind: SocketAddr, enroll_token: impl Into<String>) -> Self {
        Self {
            bind,
            enroll_token: enroll_token.into(),
            rate_limit: RateLimitConfig::default(),
            #[cfg(feature = "tls")]
            tls: None,
            public_base: None,
        }
    }

    /// Terminate TLS in-process using these files.
    #[cfg(feature = "tls")]
    pub fn with_tls(mut self, files: crate::tls::TlsFiles) -> Self {
        self.tls = Some(files);
        self
    }

    /// Turn per-IP request limiting off.
    pub fn without_rate_limit(mut self) -> Self {
        self.rate_limit.enabled = false;
        self
    }

    /// Set the public base URL advertised to devices.
    pub fn with_public_base(mut self, base: impl Into<String>) -> Self {
        self.public_base = Some(base.into().trim_end_matches('/').to_string());
        self
    }

    /// The operator-configured base with this relay's listen port filled in when
    /// the base named no port.
    ///
    /// A base written without a port (`https://relay.example.com`) means the
    /// scheme default to a browser, but an operator who bound 8443 and named no
    /// proxy meant *this* relay — so the listen port is the least-surprising
    /// fill, and every advertised URL then reaches something. An explicit port is
    /// intent and is left untouched, which is how a reverse proxy on 443 keeps a
    /// port-less base. `observed` bases are never touched here: they already name
    /// a reachable authority.
    pub fn resolved_public_base(&self) -> Option<String> {
        self.public_base.as_deref().map(|base| {
            public_base_port_hint(base, self.bind.port()).unwrap_or_else(|| base.to_string())
        })
    }

    /// The base URL to advertise, preferring what the operator configured.
    ///
    /// `observed` is what the connection itself says this relay is reachable at.
    /// Falling back to the bind address is a last resort — it is right only when
    /// nothing is in front of the relay.
    pub fn public_base_or(&self, observed: Option<String>) -> String {
        self.resolved_public_base()
            .or(observed)
            .unwrap_or_else(|| format!("http://{}", self.bind))
    }

    /// Public URL that routes to `device_id`.
    pub fn public_url_for(&self, device_id: &str, observed: Option<String>) -> String {
        format!("{}/d/{}", self.public_base_or(observed), device_id)
    }
}

/// The corrected `--public-base` to suggest when the stated base implies a
/// port nobody is listening on.
///
/// A base URL with no explicit port implies the scheme default, so when the
/// relay listens elsewhere every printed URL points at a port that only works
/// if a proxy or NAT forwards the default port to it. That setup is
/// legitimate and undetectable, so the correction is a suggestion for the
/// startup banner — the stated base is never rewritten silently. An explicit
/// port, even a mismatched one, is the operator stating intent.
pub fn public_base_port_hint(base: &str, listen_port: u16) -> Option<String> {
    let (scheme, rest) = base.split_once("://")?;
    let default_port: u16 = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    if listen_port == default_port {
        return None;
    }
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // The port separator is the colon after the host — for an IPv6 literal
    // that means after the closing bracket, not one inside it.
    let has_port = match authority.rfind(']') {
        Some(bracket) => authority[bracket..].contains(':'),
        None => authority.contains(':'),
    };
    if has_port {
        return None;
    }
    Some(format!(
        "{scheme}://{authority}:{listen_port}{}",
        &rest[authority_end..]
    ))
}

/// Shared relay state.
#[derive(Debug, Clone)]
pub struct RelayState {
    config: RelayConfig,
    devices: DeviceRegistry,
}

impl RelayState {
    /// Create state for `config`.
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            devices: DeviceRegistry::new(),
        }
    }

    /// The device registry.
    pub fn devices(&self) -> &DeviceRegistry {
        &self.devices
    }
}

/// Build the relay router.
///
/// Every route but `/health` is rate limited per client IP. Enrolment is the
/// reason: without a limit, a weak enrolment token can be guessed at line speed,
/// and the relay is the only place that sees who is asking.
pub fn relay_router(state: RelayState) -> Router {
    let limiter = Arc::new(RateLimiter::new(state.config.rate_limit.clone()));

    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/relay/v1/control", get(control_handler))
        .route("/relay/v1/data", get(data_handler))
        .route("/relay/v1/devices", get(devices_handler))
        .route("/d/{*rest}", any(proxy_handler))
        .layer(axum::middleware::from_fn_with_state(
            limiter,
            rate_limit_middleware,
        ))
        .with_state(state)
}

/// Run the relay server until shutdown.
pub async fn serve_relay(config: RelayConfig) -> crate::Result<()> {
    let bind = config.bind;
    #[cfg(feature = "tls")]
    let tls = config.tls.clone();
    let state = RelayState::new(config);
    let router = relay_router(state.clone());

    // A device that vanished without closing its socket looks identical to an
    // idle one, so entries are reaped on heartbeat staleness instead.
    let sweeper = state.devices().clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEARTBEAT_TIMEOUT / 3);
        loop {
            ticker.tick().await;
            for id in sweeper.evict_stale(HEARTBEAT_TIMEOUT) {
                tracing::info!(target: "relay", device_id = %id, "device evicted (no heartbeat)");
            }
        }
    });

    tracing::info!("relay listening on {}", bind);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(ShellTunnelError::Io)?;
    // Connection info is what the rate limiter keys on; without it every caller
    // would look identical.
    let service = router.into_make_service_with_connect_info::<SocketAddr>();

    #[cfg(feature = "tls")]
    if let Some(files) = tls {
        // Loaded before serving so a bad certificate stops startup rather than
        // failing every connection at handshake time.
        let config = crate::tls::acceptor(files.load()?);
        // Renewal should not require a restart.
        crate::tls::watch(files, config.clone());
        let std_listener = listener.into_std().map_err(ShellTunnelError::Io)?;
        return axum_server::from_tcp_rustls(std_listener, config)
            .map_err(ShellTunnelError::Io)?
            .serve(service)
            .await
            .map_err(|e| ShellTunnelError::Io(std::io::Error::other(e.to_string())));
    }

    axum::serve(listener, service)
        .await
        .map_err(|e| ShellTunnelError::Io(std::io::Error::other(e.to_string())))?;
    Ok(())
}

/// Whether `name` is usable as a routing key in `/d/<name>/…`.
///
/// Deliberately narrow: the name lands in a URL path, so anything that could
/// need escaping, traverse a path, or collide with the relay's own routes is
/// rejected rather than sanitized.
fn is_valid_device_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Work out how this relay was addressed, from the connection's own headers.
///
/// A relay behind TLS termination sees plain HTTP on a loopback port, so the
/// scheme and host it should advertise are only knowable from what the proxy
/// forwards.
fn observed_base(headers: &HeaderMap, tls: bool) -> Option<String> {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(axum::http::header::HOST))
        .and_then(|value| value.to_str().ok())?;
    if host.is_empty() {
        return None;
    }
    // A proxy's own statement wins; failing that, the relay knows whether it
    // terminated TLS itself. Guessing `http` while serving HTTPS would advertise
    // a URL that the relay itself refuses.
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(|proto| proto.split(',').next().unwrap_or(proto).trim().to_string())
        .unwrap_or_else(|| if tls { "https" } else { "http" }.to_string());
    Some(format!("{scheme}://{host}"))
}

/// Whether this relay terminates TLS itself.
fn serves_tls(_state: &RelayState) -> bool {
    #[cfg(feature = "tls")]
    {
        _state.config.tls.is_some()
    }
    #[cfg(not(feature = "tls"))]
    {
        false
    }
}

/// Upgrade a device's outbound connection into the control channel.
async fn control_handler(
    ws: WebSocketUpgrade,
    State(state): State<RelayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let observed = observed_base(&headers, serves_tls(&state));
    ws.on_upgrade(move |socket| control_session(socket, state, observed))
}

/// Enroll a device, then serve its heartbeats until the connection ends.
async fn control_session(socket: WebSocket, state: RelayState, observed: Option<String>) {
    let (mut sink, mut stream) = socket.split();

    // An unauthenticated peer must not be able to hold a connection open
    // indefinitely, so enrollment is bounded in time.
    let first = match tokio::time::timeout(ENROLL_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        _ => return,
    };

    let enroll = match serde_json::from_str::<DeviceMessage>(&first) {
        Ok(DeviceMessage::Enroll {
            enroll_token,
            version,
            label,
            device_name,
        }) => (enroll_token, version, label, device_name),
        _ => {
            reject_and_close(
                &mut sink,
                reject::BAD_HANDSHAKE,
                "expected an enroll message",
            )
            .await;
            return;
        }
    };
    let (enroll_token, version, label, device_name) = enroll;

    if version != PROTOCOL_VERSION {
        reject_and_close(
            &mut sink,
            reject::UNSUPPORTED_VERSION,
            &format!("relay speaks protocol version {PROTOCOL_VERSION}"),
        )
        .await;
        return;
    }

    if !constant_time_eq(&enroll_token, &state.config.enroll_token) {
        // No detail about *why*: a device that guessed wrong learns nothing.
        tracing::debug!(target: "relay", "enrollment rejected: bad token");
        reject_and_close(&mut sink, reject::BAD_TOKEN, "enrollment refused").await;
        return;
    }

    // A named device keeps one URL across reconnects, which is what makes the
    // relay usable when whoever calls the device cannot read its console. An
    // unnamed one gets a random id, which nobody can guess but which changes
    // every time it attaches.
    let device_id = match device_name {
        Some(name) if !is_valid_device_name(&name) => {
            reject_and_close(
                &mut sink,
                reject::BAD_DEVICE_NAME,
                "device names may use letters, digits, '-' and '_' (1-64 characters)",
            )
            .await;
            return;
        }
        // Re-attaching under an existing name replaces the old entry rather
        // than being refused: after a network drop the relay still holds a
        // connection it cannot know is dead, and refusing would lock the device
        // out until the heartbeat timeout expired. Only holders of the enrol
        // token can do this, which is the same trust level as attaching at all.
        Some(name) => name,
        None => generate_api_key(),
    };
    let public_url = state.config.public_url_for(&device_id, observed);
    let registry::DeviceHandles {
        device,
        mut refill_rx,
    } = state.devices.attach(&device_id, label.clone());
    tracing::info!(
        target: "relay",
        device_id = %device_id,
        label = label.as_deref().unwrap_or("-"),
        "device attached"
    );

    let enrolled = RelayMessage::Enrolled {
        device_id: device_id.clone(),
        public_url,
    };
    if send_json(&mut sink, &enrolled).await.is_err() {
        state.devices.detach(&device_id);
        return;
    }

    // Fill the pool up front so the first request does not pay for a handshake.
    let fill = RelayMessage::OpenData {
        count: registry::POOL_TARGET,
    };
    if send_json(&mut sink, &fill).await.is_err() {
        state.devices.detach(&device_id);
        return;
    }

    // The control channel multiplexes nothing but coordination: device
    // heartbeats one way, pool-refill requests the other.
    loop {
        tokio::select! {
            incoming = stream.next() => {
                let Some(Ok(message)) = incoming else { break };
                match message {
                    Message::Text(text) => match serde_json::from_str::<DeviceMessage>(&text) {
                        Ok(DeviceMessage::Heartbeat) => {
                            device.touch();
                            if send_json(&mut sink, &RelayMessage::HeartbeatAck).await.is_err() {
                                break;
                            }
                        }
                        // A second enrollment on an attached connection is a
                        // protocol error, not a re-key: ignore it rather than
                        // reassigning an id.
                        _ => continue,
                    },
                    Message::Close(_) => break,
                    _ => continue,
                }
            }
            refill = refill_rx.recv() => {
                if refill.is_none() {
                    break;
                }
                if send_json(&mut sink, &RelayMessage::OpenData { count: 1 }).await.is_err() {
                    break;
                }
            }
        }
    }

    state.devices.detach(&device_id);
    tracing::info!(target: "relay", device_id = %device_id, "device detached");
}

/// List the devices currently attached.
///
/// Authenticated with the enrolment token, because the answer is only useful to
/// whoever operates this relay — and anyone holding that token could attach a
/// device anyway, so listing them reveals nothing new.
async fn devices_handler(State(state): State<RelayState>, headers: HeaderMap) -> Response {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if !constant_time_eq(presented, &state.config.enroll_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let base = state
        .config
        .public_base_or(observed_base(&headers, serves_tls(&state)));
    let devices: Vec<_> = state
        .devices
        .list()
        .into_iter()
        .map(|device| {
            let url = format!("{}/d/{}", base, device.id);
            serde_json::json!({
                "id": device.id,
                "label": device.label,
                "attached_secs": device.attached_secs,
                "last_seen_secs": device.last_seen_secs,
                "public_url": url,
            })
        })
        .collect();

    axum::Json(serde_json::json!({ "devices": devices })).into_response()
}

/// Accept a data connection and park it in its device's pool.
///
/// The connection authenticates itself in its first frame rather than in the
/// URL: query strings land in the access logs of the reverse proxies this relay
/// is meant to sit behind, so a token there would be written to disk in
/// plaintext on exactly the deployments that follow our own TLS advice.
async fn data_handler(ws: WebSocketUpgrade, State(state): State<RelayState>) -> Response {
    ws.on_upgrade(move |socket| attach_data_connection(socket, state))
}

/// Read the attach frame, verify it, and hand the socket to the device's pool.
async fn attach_data_connection(mut socket: WebSocket, state: RelayState) {
    let first = tokio::time::timeout(ENROLL_TIMEOUT, socket.recv()).await;
    let Ok(Some(Ok(Message::Text(text)))) = first else {
        let _ = socket.close().await;
        return;
    };

    let Ok(DeviceMessage::Attach {
        device_id,
        enroll_token,
    }) = serde_json::from_str::<DeviceMessage>(&text)
    else {
        let _ = socket.close().await;
        return;
    };

    if !constant_time_eq(&enroll_token, &state.config.enroll_token) {
        tracing::debug!(target: "relay", "data connection rejected: bad token");
        let _ = socket.close().await;
        return;
    }

    let Some(device) = state.devices.get(&device_id) else {
        let _ = socket.close().await;
        return;
    };

    // A pool that is already full means the device over-supplied; closing the
    // extra socket is better than holding it open forever.
    if let Some(mut extra) = device.offer(socket).await {
        let _ = extra.close().await;
    }
}

/// Forward a public request to the addressed device and return its response.
async fn proxy_handler(State(state): State<RelayState>, request: Request) -> Response {
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let Some((device_id, tail)) = split_device_path(&path_and_query) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let Some(device) = state.devices.get(device_id) else {
        // The device is not attached: this is the relay reporting a missing
        // upstream, which is exactly what 502 means.
        return (StatusCode::BAD_GATEWAY, "device is not connected").into_response();
    };

    let method = request.method().to_string();
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter(|(name, _)| is_forwardable(name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();

    // A WebSocket upgrade cannot be answered by buffering: the exchange has no
    // end until one side closes. Because one request already owns one data
    // connection for its lifetime, the same socket simply becomes the pipe —
    // the connection-per-request model pays off here rather than needing a
    // second mechanism.
    if is_websocket_upgrade(request.headers()) {
        let (mut parts, _) = request.into_parts();
        let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
            Ok(upgrade) => upgrade,
            Err(rejection) => return rejection.into_response(),
        };
        let proxied = ProxyRequest {
            method,
            path: tail,
            headers,
            websocket: true,
        };
        return upgrade.on_upgrade(move |client| pipe_websocket(client, device, proxied));
    }

    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    let Some(conn) = device.take(POOL_WAIT).await else {
        // The device is attached but has no spare connection. 503 with a
        // Retry-After is the honest answer: try again shortly.
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("retry-after", "1")],
            "no data connection available",
        )
            .into_response();
    };

    match tokio::time::timeout(
        REQUEST_TIMEOUT,
        forward(
            conn,
            ProxyRequest {
                method,
                path: tail,
                headers,
                websocket: false,
            },
            body,
        ),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(reason)) => {
            tracing::debug!(target: "relay", device_id = %device.id, reason, "proxy failed");
            (StatusCode::BAD_GATEWAY, "device did not answer").into_response()
        }
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "device timed out").into_response(),
    }
}

/// Whether these headers ask to switch protocols to WebSocket.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let header_contains = |name: axum::http::HeaderName, needle: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
    };
    header_contains(axum::http::header::UPGRADE, "websocket")
        && header_contains(axum::http::header::CONNECTION, "upgrade")
}

/// Join a client's WebSocket to the device over one data connection.
///
/// The relay has already answered 101 by the time this runs — axum completes the
/// handshake before invoking the callback — so a device that then refuses simply
/// results in the client's socket closing.
async fn pipe_websocket(mut client: WebSocket, device: Arc<Device>, request: ProxyRequest) {
    let Some(mut conn) = device.take(POOL_WAIT).await else {
        tracing::debug!(target: "relay", device_id = %device.id, "no data connection for websocket");
        let _ = client.close().await;
        return;
    };

    let Ok(header) = serde_json::to_string(&request) else {
        let _ = client.close().await;
        return;
    };
    if conn.send(Message::Text(header.into())).await.is_err() {
        let _ = client.close().await;
        return;
    }

    // The device answers with the status its own server returned; anything but
    // a switch means the upgrade did not happen there.
    let switched = matches!(
        conn.recv().await,
        Some(Ok(Message::Text(ref text)))
            if serde_json::from_str::<ProxyResponse>(text)
                .map(|response| response.status == 101)
                .unwrap_or(false)
    );
    if !switched {
        let _ = client.close().await;
        let _ = conn.close().await;
        return;
    }

    // From here the two sockets are the same conversation: copy frames until
    // either end hangs up.
    loop {
        tokio::select! {
            from_client = client.recv() => {
                match from_client {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(message)) => {
                        if conn.send(message).await.is_err() {
                            break;
                        }
                    }
                }
            }
            from_device = conn.recv() => {
                match from_device {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(message)) => {
                        if client.send(message).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    let _ = client.close().await;
    let _ = conn.close().await;
}

/// Largest request body the relay will buffer before forwarding.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// Drive one request/response exchange over a dedicated data connection.
///
/// Wire shape: request header (text) → request body (binary) → response header
/// (text) → response body (binary frames) → close.
async fn forward(
    mut conn: WebSocket,
    request: ProxyRequest,
    body: Bytes,
) -> Result<Response, &'static str> {
    let header = serde_json::to_string(&request).map_err(|_| "request-encode")?;
    conn.send(Message::Text(header.into()))
        .await
        .map_err(|_| "request-header-send")?;
    conn.send(Message::Binary(body))
        .await
        .map_err(|_| "request-body-send")?;

    let head: ProxyResponse = loop {
        match conn.recv().await {
            Some(Ok(Message::Text(text))) => {
                break serde_json::from_str(&text).map_err(|_| "response-decode")?
            }
            Some(Ok(_)) => continue,
            _ => return Err("response-header-missing"),
        }
    };

    let mut body = Vec::new();
    while let Some(Ok(message)) = conn.recv().await {
        match message {
            Message::Binary(chunk) => body.extend_from_slice(&chunk),
            Message::Close(_) => break,
            _ => continue,
        }
    }

    let mut response = Response::builder().status(head.status);
    for (name, value) in head.headers {
        if is_forwardable(&name) {
            response = response.header(name, value);
        }
    }
    response
        .body(axum::body::Body::from(body))
        .map_err(|_| "response-build")
}

/// Send a rejection and close, best-effort.
async fn reject_and_close<S>(sink: &mut S, code: &str, message: &str)
where
    S: SinkExt<Message> + Unpin,
{
    let rejected = RelayMessage::Rejected {
        code: code.to_string(),
        message: message.to_string(),
    };
    let _ = send_json(sink, &rejected).await;
    let _ = sink.close().await;
}

/// Serialize and send one protocol message.
async fn send_json<S, T>(sink: &mut S, message: &T) -> Result<(), ()>
where
    S: SinkExt<Message> + Unpin,
    T: serde::Serialize,
{
    let json = serde_json::to_string(message).map_err(|_| ())?;
    sink.send(Message::Text(json.into())).await.map_err(|_| ())
}

/// Compare secrets without leaking their contents through timing.
///
/// The token is short and comparisons are rare, but an early-exit `==` on a
/// shared secret is the kind of detail that is cheap to get right and awkward
/// to retrofit.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RelayConfig {
        RelayConfig::new("127.0.0.1:0".parse().unwrap(), "secret")
    }

    #[test]
    fn a_portless_base_on_a_nondefault_port_gets_a_corrected_suggestion() {
        // The failure this pins down: `--public-base https://labs.example.com`
        // with the relay listening on 8443 printed join and device URLs that
        // imply port 443, which nobody was serving. The hint is the corrected
        // value to suggest — never applied silently, because a proxy or NAT
        // forwarding 443 -> 8443 makes the portless form legitimate.
        assert_eq!(
            public_base_port_hint("https://labs.example.com", 8443).as_deref(),
            Some("https://labs.example.com:8443")
        );
        assert_eq!(
            public_base_port_hint("http://relay.local", 8080).as_deref(),
            Some("http://relay.local:8080")
        );
    }

    #[test]
    fn a_base_matching_the_scheme_default_needs_no_hint() {
        assert_eq!(public_base_port_hint("https://labs.example.com", 443), None);
        assert_eq!(public_base_port_hint("http://relay.local", 80), None);
    }

    #[test]
    fn an_explicit_port_is_the_operator_stating_intent() {
        // Explicit ports are never second-guessed: a proxy may remap them.
        assert_eq!(
            public_base_port_hint("https://labs.example.com:8443", 8443),
            None
        );
        assert_eq!(
            public_base_port_hint("https://labs.example.com:9000", 8443),
            None
        );
        assert_eq!(
            public_base_port_hint("https://labs.example.com:443", 8443),
            None
        );
    }

    #[test]
    fn the_port_is_spliced_into_the_authority_not_the_tail() {
        // A base may carry a path prefix; the port belongs after the host.
        assert_eq!(
            public_base_port_hint("https://labs.example.com/relay", 8443).as_deref(),
            Some("https://labs.example.com:8443/relay")
        );
    }

    #[test]
    fn ipv6_literals_look_for_the_port_after_the_bracket() {
        assert_eq!(
            public_base_port_hint("https://[::1]", 8443).as_deref(),
            Some("https://[::1]:8443")
        );
        assert_eq!(public_base_port_hint("https://[::1]:8443", 8443), None);
    }

    #[test]
    fn an_unrecognized_scheme_is_left_alone() {
        assert_eq!(public_base_port_hint("ws://relay.local", 8443), None);
    }

    #[test]
    fn public_url_uses_the_device_path_prefix() {
        // Bound to the https default port, so no port is spliced in and the test
        // stays about the path prefix and the trailing-slash trim.
        let config = RelayConfig::new("127.0.0.1:443".parse().unwrap(), "secret")
            .with_public_base("https://relay.example.com/");
        assert_eq!(
            config.public_url_for("dev-1", None),
            "https://relay.example.com/d/dev-1"
        );
    }

    #[test]
    fn a_portless_base_inherits_the_listen_port() {
        // A안: the operator named the host but not the port and bound 8443 with
        // no proxy in sight, so every advertised URL uses 8443 — not the 443 a
        // bare `https://` would otherwise imply and nobody would be serving.
        let config = RelayConfig::new("0.0.0.0:8443".parse().unwrap(), "secret")
            .with_public_base("https://labs.example.com");
        assert_eq!(
            config.resolved_public_base().as_deref(),
            Some("https://labs.example.com:8443")
        );
        assert_eq!(
            config.public_url_for("dev-1", None),
            "https://labs.example.com:8443/d/dev-1"
        );
    }

    #[test]
    fn an_explicit_port_survives_resolution() {
        // A reverse proxy on 443 forwarding to 8443 keeps a base that names 443;
        // the stated port is intent and is never rewritten to the listen port.
        let config = RelayConfig::new("0.0.0.0:8443".parse().unwrap(), "secret")
            .with_public_base("https://labs.example.com:443");
        assert_eq!(
            config.resolved_public_base().as_deref(),
            Some("https://labs.example.com:443")
        );
    }

    #[test]
    fn resolution_leaves_a_default_port_base_alone() {
        // Listening on the scheme default means the bare base is already right.
        let config = RelayConfig::new("0.0.0.0:443".parse().unwrap(), "secret")
            .with_public_base("https://labs.example.com");
        assert_eq!(
            config.resolved_public_base().as_deref(),
            Some("https://labs.example.com")
        );
    }

    #[test]
    fn public_base_defaults_to_the_bind_address() {
        let config = RelayConfig::new("127.0.0.1:8443".parse().unwrap(), "secret");
        assert_eq!(
            config.public_url_for("d", None),
            "http://127.0.0.1:8443/d/d"
        );
    }

    #[test]
    fn an_observed_address_is_used_when_the_operator_configured_none() {
        let config = config();
        assert_eq!(
            config.public_url_for("dev-1", Some("https://relay.example.com".into())),
            "https://relay.example.com/d/dev-1"
        );
    }

    #[test]
    fn a_configured_base_wins_over_what_the_connection_observed() {
        let config = RelayConfig::new("127.0.0.1:443".parse().unwrap(), "secret")
            .with_public_base("https://canonical.example");
        assert_eq!(
            config.public_url_for("dev-1", Some("https://whatever.invalid".into())),
            "https://canonical.example/d/dev-1"
        );
    }

    #[test]
    fn the_forwarded_scheme_and_host_are_preferred_over_the_direct_host() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(
            observed_base(&headers, false).as_deref(),
            Some("http://127.0.0.1:8443")
        );

        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "relay.example.com".parse().unwrap());
        assert_eq!(
            observed_base(&headers, false).as_deref(),
            Some("https://relay.example.com")
        );
    }

    #[test]
    fn a_proxy_chain_scheme_takes_the_first_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            "relay.example.com".parse().unwrap(),
        );
        headers.insert("x-forwarded-proto", "https, http".parse().unwrap());
        assert_eq!(
            observed_base(&headers, false).as_deref(),
            Some("https://relay.example.com")
        );
    }

    #[test]
    fn no_host_header_means_nothing_observed() {
        assert!(observed_base(&HeaderMap::new(), false).is_none());
    }

    #[test]
    fn terminating_tls_makes_the_advertised_url_https() {
        // Advertising http:// while refusing plaintext would hand out a URL the
        // relay itself rejects.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            "relay.example.com".parse().unwrap(),
        );
        assert_eq!(
            observed_base(&headers, true).as_deref(),
            Some("https://relay.example.com")
        );
    }

    #[test]
    fn device_names_must_be_url_path_safe() {
        assert!(is_valid_device_name("build-box"));
        assert!(is_valid_device_name("laptop_2"));
        assert!(is_valid_device_name("a"));

        assert!(!is_valid_device_name(""));
        assert!(!is_valid_device_name("has space"));
        assert!(!is_valid_device_name("../escape"));
        assert!(!is_valid_device_name("slash/inside"));
        assert!(!is_valid_device_name("querylike?x=1"));
        assert!(!is_valid_device_name(&"x".repeat(65)));
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(constant_time_eq("", ""));
    }
}
