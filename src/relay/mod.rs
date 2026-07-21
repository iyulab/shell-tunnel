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
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, Request, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use futures_util::{SinkExt, StreamExt};

use crate::error::ShellTunnelError;
use crate::security::generate_api_key;
use protocol::{reject, DeviceMessage, RelayMessage, PROTOCOL_VERSION};
use proxy::{
    is_forwardable, split_device_path, ProxyRequest, ProxyResponse, POOL_WAIT, REQUEST_TIMEOUT,
};
use registry::DeviceRegistry;

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
    /// Public base URL of this relay, used to build each device's public URL.
    pub public_base: String,
}

impl RelayConfig {
    /// Create a configuration with the given bind address and token.
    pub fn new(bind: SocketAddr, enroll_token: impl Into<String>) -> Self {
        let bind_str = bind.to_string();
        Self {
            bind,
            enroll_token: enroll_token.into(),
            public_base: format!("http://{bind_str}"),
        }
    }

    /// Set the public base URL advertised to devices.
    pub fn with_public_base(mut self, base: impl Into<String>) -> Self {
        self.public_base = base.into().trim_end_matches('/').to_string();
        self
    }

    /// Public URL that routes to `device_id`.
    pub fn public_url_for(&self, device_id: &str) -> String {
        format!("{}/d/{}", self.public_base, device_id)
    }
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
pub fn relay_router(state: RelayState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/relay/v1/control", get(control_handler))
        .route("/relay/v1/data", get(data_handler))
        .route("/d/{*rest}", any(proxy_handler))
        .with_state(state)
}

/// Run the relay server until shutdown.
pub async fn serve_relay(config: RelayConfig) -> crate::Result<()> {
    let bind = config.bind;
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
    axum::serve(listener, router)
        .await
        .map_err(|e| ShellTunnelError::Io(std::io::Error::other(e.to_string())))?;
    Ok(())
}

/// Upgrade a device's outbound connection into the control channel.
async fn control_handler(
    ws: WebSocketUpgrade,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| control_session(socket, state))
}

/// Enroll a device, then serve its heartbeats until the connection ends.
async fn control_session(socket: WebSocket, state: RelayState) {
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
        }) => (enroll_token, version, label),
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
    let (enroll_token, version, label) = enroll;

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

    // Relay-assigned, never device-chosen: an attacker cannot pick or squat on
    // another device's routing key.
    let device_id = generate_api_key();
    let public_url = state.config.public_url_for(&device_id);
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

/// Query parameters a device sends when opening a data connection.
#[derive(Debug, serde::Deserialize)]
struct DataParams {
    device_id: String,
    enroll_token: String,
}

/// Accept a data connection and park it in its device's pool.
///
/// Data connections re-present the enrollment token: a socket that can serve a
/// device's traffic must prove the same thing the control channel proved.
async fn data_handler(
    ws: WebSocketUpgrade,
    State(state): State<RelayState>,
    Query(params): Query<DataParams>,
) -> Response {
    if !constant_time_eq(&params.enroll_token, &state.config.enroll_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(device) = state.devices.get(&params.device_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    ws.on_upgrade(move |socket| async move {
        // A pool that is already full means the device over-supplied; closing
        // the extra socket is better than holding it open forever.
        if let Some(mut extra) = device.offer(socket).await {
            let _ = extra.close().await;
        }
    })
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
    fn public_url_uses_the_device_path_prefix() {
        let config = config().with_public_base("https://relay.example.com/");
        assert_eq!(
            config.public_url_for("dev-1"),
            "https://relay.example.com/d/dev-1"
        );
    }

    #[test]
    fn public_base_defaults_to_the_bind_address() {
        let config = RelayConfig::new("127.0.0.1:8443".parse().unwrap(), "secret");
        assert_eq!(config.public_url_for("d"), "http://127.0.0.1:8443/d/d");
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(constant_time_eq("", ""));
    }
}
