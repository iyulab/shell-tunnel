//! Device side of the relay: dialling out and serving what comes back.
//!
//! Compiled only with the `relay-client` feature. The reason is the same one
//! that keeps `self-update` optional: a WebSocket client and a TLS stack are
//! dead weight in a build that only listens on a local port.
//!
//! The device never accepts an inbound connection. It opens a control channel
//! to the relay, then opens one data connection per unit of pool capacity the
//! relay asks for, and replays each arriving request against its own local
//! server. That is what makes a machine behind NAT reachable without touching
//! a firewall.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The device's side of a relay connection.
type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

use super::protocol::{DeviceMessage, RelayMessage, PROTOCOL_VERSION};
use super::proxy::{is_forwardable, ProxyRequest, ProxyResponse};
use crate::error::ShellTunnelError;
use crate::Result;

/// How often the device proves it is alive.
///
/// Under the 60s idle timeout that load balancers and reverse proxies commonly
/// default to, so an idle control channel is never reaped as dead.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Backoff bounds for reconnecting after the control channel drops.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Settings for attaching to a relay.
#[derive(Debug, Clone)]
pub struct RelayClientConfig {
    /// Relay base URL, e.g. `wss://relay.example.com`.
    pub relay_url: String,
    /// Secret this relay expects from attaching devices.
    pub enroll_token: String,
    /// Local address of this device's own server.
    pub local: SocketAddr,
    /// Optional label shown in relay logs.
    pub label: Option<String>,
    /// Requested stable device name; without one the relay assigns a random id
    /// that changes on every reconnect.
    pub device_name: Option<String>,
    /// Extra PEM certificate authority to trust, for a relay whose certificate
    /// is not signed by a public CA.
    ///
    /// Without this a private or self-signed relay certificate is refused —
    /// correctly, since the alternative is trusting whatever answers. Naming the
    /// authority keeps that check intact instead of disabling it.
    pub ca_file: Option<PathBuf>,
}

impl RelayClientConfig {
    /// Build the control-channel URL.
    pub fn control_url(&self) -> String {
        format!("{}/relay/v1/control", self.base())
    }

    /// Build the data-connection URL.
    ///
    /// Deliberately carries no credentials: the device authenticates in the
    /// connection's first frame instead, because URLs end up in proxy and load
    /// balancer access logs.
    pub fn data_url(&self) -> String {
        format!("{}/relay/v1/data", self.base())
    }

    /// Normalise the relay URL to a WebSocket scheme without a trailing slash.
    ///
    /// Operators paste whatever they have — the `https://` they browse to, or
    /// the `wss://` from the docs — and both mean the same relay.
    fn base(&self) -> String {
        let trimmed = self.relay_url.trim_end_matches('/');
        match trimmed.split_once("://") {
            Some(("https", rest)) => format!("wss://{rest}"),
            Some(("http", rest)) => format!("ws://{rest}"),
            Some(_) => trimmed.to_string(),
            None => format!("wss://{trimmed}"),
        }
    }
}

/// This machine's short hostname, reduced to something usable as a routing key.
///
/// Used when no `--device-name` is given, so a device gets a URL that survives
/// restarts without the operator having to name every machine by hand. Read from
/// the environment first and from `hostname` only as a fallback, because the
/// environment variable is absent when running as a service on Unix.
pub fn default_device_name() -> Option<String> {
    #[cfg(windows)]
    const HOST_VAR: &str = "COMPUTERNAME";
    #[cfg(not(windows))]
    const HOST_VAR: &str = "HOSTNAME";

    let raw = std::env::var(HOST_VAR)
        .ok()
        .filter(|v| !v.trim().is_empty());
    let raw = raw.or_else(|| {
        let output = std::process::Command::new("hostname").output().ok()?;
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (!name.is_empty()).then_some(name)
    })?;

    sanitize_device_name(&raw)
}

/// Reduce a hostname to the characters a routing key may contain.
///
/// Takes the short name (a FQDN's first label) and drops anything that would
/// need escaping in a URL path, rather than letting the relay reject a name the
/// user never chose.
fn sanitize_device_name(raw: &str) -> Option<String> {
    let short = raw.split('.').next().unwrap_or(raw);
    let cleaned: String = short
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Select the TLS backend once, before any `wss://` connection is made.
///
/// rustls 0.23 will not choose a crypto provider implicitly; without this the
/// first TLS handshake panics deep inside the library rather than returning an
/// error. Installing it explicitly (rather than relying on feature unification
/// to leave exactly one provider enabled) keeps that failure impossible no
/// matter what else ends up in the dependency graph.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // An error here means a provider was already installed, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Attach to the relay and keep serving until the process ends.
///
/// Reconnects with exponential backoff: unlike a spawned tunnel, the device's
/// public URL is stable across reconnects (the relay keeps addressing it by the
/// same id), so recovering silently is the honest behaviour here.
pub async fn run(config: RelayClientConfig) -> Result<()> {
    install_crypto_provider();
    let mut backoff = BACKOFF_MIN;
    loop {
        match attach(&config).await {
            Ok(()) => {
                tracing::warn!(target: "relay-client", "relay connection closed; reconnecting");
                backoff = BACKOFF_MIN;
            }
            Err(e) => {
                tracing::warn!(target: "relay-client", "relay connection failed: {e}");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// One attachment: enroll, then serve pool requests until the channel drops.
///
/// Returns `Ok(())` when the relay closed the channel cleanly.
pub async fn attach(config: &RelayClientConfig) -> Result<()> {
    install_crypto_provider();
    let (mut control, _) = tokio_tungstenite::connect_async_tls_with_config(
        config
            .control_url()
            .into_client_request()
            .map_err(|e| ShellTunnelError::Tunnel(format!("bad relay url: {e}")))?,
        None,
        false,
        connector(config)?,
    )
    .await
    .map_err(|e| ShellTunnelError::Tunnel(explain_dial_failure(&e, config)))?;

    let enroll = DeviceMessage::Enroll {
        enroll_token: config.enroll_token.clone(),
        version: PROTOCOL_VERSION,
        label: config.label.clone(),
        device_name: config.device_name.clone(),
    };
    send(&mut control, &enroll).await?;

    let device_id = match recv(&mut control).await? {
        RelayMessage::Enrolled {
            device_id,
            public_url,
        } => {
            println!("\nPublic URL:  {public_url}   (via relay)");
            device_id
        }
        RelayMessage::Rejected { code, message } => {
            return Err(ShellTunnelError::Tunnel(format!(
                "relay refused this device ({code}): {message}"
            )))
        }
        other => {
            return Err(ShellTunnelError::Tunnel(format!(
                "unexpected first message from relay: {other:?}"
            )))
        }
    };

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.tick().await; // the first tick is immediate

    loop {
        tokio::select! {
            incoming = control.next() => {
                let Some(Ok(message)) = incoming else { return Ok(()) };
                let Message::Text(text) = message else { continue };
                match serde_json::from_str::<RelayMessage>(&text) {
                    Ok(RelayMessage::OpenData { count }) => {
                        for _ in 0..count {
                            spawn_data_connection(config.clone(), device_id.clone());
                        }
                    }
                    Ok(RelayMessage::HeartbeatAck) => {}
                    _ => continue,
                }
            }
            _ = heartbeat.tick() => {
                send(&mut control, &DeviceMessage::Heartbeat).await?;
            }
        }
    }
}

/// Open one data connection and serve a single request on it.
fn spawn_data_connection(config: RelayClientConfig, device_id: String) {
    tokio::spawn(async move {
        if let Err(e) = serve_one(&config, &device_id).await {
            tracing::debug!(target: "relay-client", "data connection ended: {e}");
        }
    });
}

/// Wait for one proxied request, replay it locally, return the response.
async fn serve_one(config: &RelayClientConfig, device_id: &str) -> Result<()> {
    let (mut conn, _) = tokio_tungstenite::connect_async_tls_with_config(
        config
            .data_url()
            .into_client_request()
            .map_err(|e| ShellTunnelError::Tunnel(format!("bad relay url: {e}")))?,
        None,
        false,
        connector(config)?,
    )
    .await
    .map_err(|e| ShellTunnelError::Tunnel(format!("data connection refused: {e}")))?;

    let attach = DeviceMessage::Attach {
        device_id: device_id.to_string(),
        enroll_token: config.enroll_token.clone(),
    };
    send(&mut conn, &attach).await?;

    let request: ProxyRequest = loop {
        match conn.next().await {
            Some(Ok(Message::Text(text))) => {
                break serde_json::from_str(&text)
                    .map_err(|e| ShellTunnelError::Tunnel(format!("bad request header: {e}")))?
            }
            Some(Ok(_)) => continue,
            _ => return Ok(()), // relay closed an idle connection; nothing to do
        }
    };

    // A WebSocket request never gets a body frame: the relay switches the
    // connection into a pipe instead, so this branch must not wait for one.
    if request.websocket {
        return pipe_websocket(conn, config, &request).await;
    }

    let body = match conn.next().await {
        Some(Ok(Message::Binary(bytes))) => bytes.to_vec(),
        _ => Vec::new(),
    };

    let (status, headers, body) = replay_locally(config.local, &request, body).await;

    let head = ProxyResponse { status, headers };
    let json = serde_json::to_string(&head)
        .map_err(|e| ShellTunnelError::Tunnel(format!("cannot encode response: {e}")))?;
    let _ = conn.send(Message::Text(json)).await;
    let _ = conn.send(Message::Binary(body)).await;
    let _ = conn.close(None).await;
    Ok(())
}

/// Turn a dial failure into something an operator can act on.
///
/// rustls reports certificate problems in its own vocabulary — `BadSignature`
/// says nothing about the far more likely cause, which is that the file passed
/// to `--relay-ca` is not the certificate this relay is currently serving.
fn explain_dial_failure(
    error: &tokio_tungstenite::tungstenite::Error,
    config: &RelayClientConfig,
) -> String {
    let text = error.to_string();
    let mut message = format!("cannot reach relay: {text}");

    if text.contains("BadSignature") || text.contains("UnknownIssuer") {
        let ca = config
            .ca_file
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "the system trust store".to_string());
        message.push_str(&format!(
            "
  {ca} does not vouch for the certificate this relay is presenting."
        ));
        message.push_str(
            "
  A relay that regenerated its certificate, or a copy taken from a different",
        );
        message.push_str(
            "
  relay directory, both look like this. Copy the relay's current",
        );
        message.push_str(
            "
  shell-tunnel-cert.pem and pass it as --relay-ca.",
        );
    } else if text.contains("NotValidForName") {
        message.push_str(
            "
  The certificate does not cover the name being dialled.",
        );
        message.push_str(
            "
  Start the relay with --public-base for that name, after deleting",
        );
        message.push_str(
            "
  shell-tunnel-cert.pem and shell-tunnel-key.pem so it is regenerated.",
        );
    }

    message
}

/// Build the TLS connector, adding a private authority when one is configured.
///
/// Returning `None` means "use the defaults", which is what a relay with a
/// publicly-signed certificate needs.
fn connector(config: &RelayClientConfig) -> Result<Option<tokio_tungstenite::Connector>> {
    let Some(path) = &config.ca_file else {
        return Ok(None);
    };

    let pem = std::fs::read(path)
        .map_err(|e| ShellTunnelError::Tunnel(format!("cannot read CA {}: {e}", path.display())))?;
    let mut roots = rustls::RootCertStore::empty();
    let mut added = 0usize;
    for cert in rustls_pemfile_certs(&pem) {
        if roots.add(cert).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        return Err(ShellTunnelError::Tunnel(format!(
            "{} contains no usable certificate authority",
            path.display()
        )));
    }

    // Public roots stay trusted as well, so one flag does not turn a mixed fleet
    // into an all-or-nothing choice.
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Some(tokio_tungstenite::Connector::Rustls(
        std::sync::Arc::new(tls),
    )))
}

/// Parse every certificate in a PEM blob, ignoring anything that is not one.
fn rustls_pemfile_certs(pem: &[u8]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let mut cursor = pem;
    rustls_pemfile::certs(&mut cursor)
        .filter_map(|cert| cert.ok())
        .collect()
}

/// Open the local WebSocket the request is really for, then join the two.
///
/// The relay has committed to a 101 with its own client already; this side
/// reports whether the device's server agreed, and if so the data connection
/// becomes a plain two-way pipe.
async fn pipe_websocket(
    mut conn: WsStream,
    config: &RelayClientConfig,
    request: &ProxyRequest,
) -> Result<()> {
    let local_url = format!("ws://{}{}", config.local, request.path);
    let mut builder = local_url
        .into_client_request()
        .map_err(|e| ShellTunnelError::Tunnel(format!("bad local websocket url: {e}")))?;

    // The capability token lives in these headers; without replaying them the
    // device's own auth would reject its own traffic.
    for (name, value) in &request.headers {
        if !is_forwardable(name) || name.eq_ignore_ascii_case("sec-websocket-key") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder.headers_mut().insert(name, value);
        }
    }

    let local = match tokio_tungstenite::connect_async(builder).await {
        Ok((socket, _)) => socket,
        Err(e) => {
            // Report the refusal so the relay can close its client cleanly
            // instead of leaving it waiting on a pipe that will never carry.
            tracing::debug!(target: "relay-client", "local websocket refused: {e}");
            let head = ProxyResponse {
                status: 502,
                headers: Vec::new(),
            };
            if let Ok(json) = serde_json::to_string(&head) {
                let _ = conn.send(Message::Text(json)).await;
            }
            let _ = conn.close(None).await;
            return Ok(());
        }
    };

    let head = ProxyResponse {
        status: 101,
        headers: Vec::new(),
    };
    let json = serde_json::to_string(&head)
        .map_err(|e| ShellTunnelError::Tunnel(format!("cannot encode response: {e}")))?;
    conn.send(Message::Text(json))
        .await
        .map_err(|_| ShellTunnelError::Tunnel("relay connection lost".to_string()))?;

    let (mut local_tx, mut local_rx) = local.split();
    let (mut relay_tx, mut relay_rx) = conn.split();

    loop {
        tokio::select! {
            from_relay = relay_rx.next() => {
                match from_relay {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(message)) => {
                        if local_tx.send(message).await.is_err() {
                            break;
                        }
                    }
                }
            }
            from_local = local_rx.next() => {
                match from_local {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(message)) => {
                        if relay_tx.send(message).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    let _ = local_tx.close().await;
    let _ = relay_tx.close().await;
    Ok(())
}

/// Replay a proxied request against the device's own server over a plain TCP
/// connection.
///
/// Written by hand rather than with an HTTP client crate: the destination is
/// always this process's own listener on loopback, and adding a client stack for
/// one localhost request would undo the point of the feature gate.
async fn replay_locally(
    local: SocketAddr,
    request: &ProxyRequest,
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = match tokio::net::TcpStream::connect(local).await {
        Ok(stream) => stream,
        Err(e) => return bad_gateway(format!("local server unreachable: {e}")),
    };

    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\ncontent-length: {}\r\n",
        request.method,
        request.path,
        local,
        body.len()
    );
    for (name, value) in &request.headers {
        // `content-length` is recomputed above; replaying the original would
        // contradict the body actually being sent.
        if is_forwardable(name) && !name.eq_ignore_ascii_case("content-length") {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str("\r\n");

    if stream.write_all(head.as_bytes()).await.is_err() || stream.write_all(&body).await.is_err() {
        return bad_gateway("local server closed the connection".to_string());
    }

    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).await.is_err() {
        return bad_gateway("local server response was cut short".to_string());
    }

    parse_response(&raw)
}

/// Split a raw HTTP/1.1 response into status, headers, and body.
fn parse_response(raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len());
    let (head, body) = raw.split_at(split);
    let head = String::from_utf8_lossy(head);
    let mut lines = head.lines();

    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(502);

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .filter(|(name, _)| is_forwardable(name))
        .collect();

    (status, headers, body.to_vec())
}

/// The response to report when the device's own server could not answer.
fn bad_gateway(reason: String) -> (u16, Vec<(String, String)>, Vec<u8>) {
    tracing::debug!(target: "relay-client", "{reason}");
    (
        502,
        vec![("content-type".to_string(), "text/plain".to_string())],
        b"device could not reach its local server".to_vec(),
    )
}

async fn send<S>(socket: &mut S, message: &DeviceMessage) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let json = serde_json::to_string(message)
        .map_err(|e| ShellTunnelError::Tunnel(format!("cannot encode message: {e}")))?;
    socket
        .send(Message::Text(json))
        .await
        .map_err(|_| ShellTunnelError::Tunnel("relay connection lost".to_string()))
}

async fn recv<S>(socket: &mut S) -> Result<RelayMessage>
where
    S: StreamExt<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text)
                    .map_err(|e| ShellTunnelError::Tunnel(format!("bad relay message: {e}")))
            }
            Some(Ok(_)) => continue,
            _ => {
                return Err(ShellTunnelError::Tunnel(
                    "relay closed the connection".to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(relay_url: &str) -> RelayClientConfig {
        RelayClientConfig {
            relay_url: relay_url.to_string(),
            enroll_token: "secret".to_string(),
            local: "127.0.0.1:3000".parse().unwrap(),
            label: None,
            device_name: None,
            ca_file: None,
        }
    }

    #[test]
    fn a_certificate_mismatch_says_what_to_do_about_it() {
        use tokio_tungstenite::tungstenite::Error;

        let config = RelayClientConfig {
            ca_file: Some(PathBuf::from("copied-cert.pem")),
            ..config("wss://relay.example.com")
        };
        let error = Error::Io(std::io::Error::other(
            "invalid peer certificate: BadSignature",
        ));

        let message = explain_dial_failure(&error, &config);
        // "BadSignature" alone sends an operator looking at the wrong thing.
        assert!(message.contains("copied-cert.pem"), "{message}");
        assert!(message.contains("--relay-ca"), "{message}");
    }

    #[test]
    fn a_name_mismatch_points_at_public_base() {
        use tokio_tungstenite::tungstenite::Error;

        let error = Error::Io(std::io::Error::other(
            "invalid peer certificate: NotValidForName",
        ));
        let message = explain_dial_failure(&error, &config("wss://relay.example.com"));

        assert!(message.contains("--public-base"), "{message}");
    }

    #[test]
    fn an_unrelated_failure_is_left_alone() {
        use tokio_tungstenite::tungstenite::Error;

        let error = Error::Io(std::io::Error::other("connection refused"));
        let message = explain_dial_failure(&error, &config("wss://relay.example.com"));

        assert!(message.contains("connection refused"), "{message}");
        assert!(!message.contains("--relay-ca"), "{message}");
    }

    #[test]
    fn a_hostname_becomes_a_usable_routing_key() {
        assert_eq!(
            sanitize_device_name("UJ-Book3").as_deref(),
            Some("UJ-Book3")
        );
        assert_eq!(
            sanitize_device_name("build_box").as_deref(),
            Some("build_box")
        );
        // A FQDN contributes only its short name; dots are not path-safe.
        assert_eq!(
            sanitize_device_name("box.example.com").as_deref(),
            Some("box")
        );
        // Anything left unusable is reported as absent rather than mangled into
        // a name the user never chose.
        assert_eq!(sanitize_device_name("!!!").as_deref(), None);
        assert_eq!(sanitize_device_name("").as_deref(), None);
        assert_eq!(sanitize_device_name(&"x".repeat(100)).unwrap().len(), 64);
    }

    #[test]
    fn this_machine_has_a_default_device_name() {
        // Every platform the project runs on can name itself somehow; a `None`
        // here would silently fall back to a random id that changes on reconnect.
        assert!(default_device_name().is_some());
    }

    #[test]
    fn https_urls_become_websocket_urls() {
        assert_eq!(
            config("https://relay.example.com").control_url(),
            "wss://relay.example.com/relay/v1/control"
        );
        assert_eq!(
            config("http://127.0.0.1:8443").control_url(),
            "ws://127.0.0.1:8443/relay/v1/control"
        );
    }

    #[test]
    fn websocket_urls_are_left_alone() {
        assert_eq!(
            config("wss://relay.example.com/").control_url(),
            "wss://relay.example.com/relay/v1/control"
        );
    }

    #[test]
    fn a_bare_host_defaults_to_the_secure_scheme() {
        assert_eq!(
            config("relay.example.com").control_url(),
            "wss://relay.example.com/relay/v1/control"
        );
    }

    #[test]
    fn data_urls_carry_no_credentials() {
        let url = config("wss://relay.example.com").data_url();
        assert_eq!(url, "wss://relay.example.com/relay/v1/data");
        // A secret in the URL would be written to proxy access logs.
        assert!(!url.contains("secret"), "{url}");
        assert!(!url.contains('?'), "{url}");
    }

    #[test]
    fn responses_are_split_into_status_headers_and_body() {
        let raw = b"HTTP/1.1 201 Created\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{\"ok\":true}";
        let (status, headers, body) = parse_response(raw);

        assert_eq!(status, 201);
        assert_eq!(body, b"{\"ok\":true}");
        assert!(headers.contains(&("content-type".to_string(), "application/json".to_string())));
        // Hop-by-hop headers belong to the local connection, not the response.
        assert!(
            !headers.iter().any(|(n, _)| n == "connection"),
            "{headers:?}"
        );
    }

    #[test]
    fn a_malformed_response_is_reported_as_a_bad_gateway() {
        let (status, _, _) = parse_response(b"garbage");
        assert_eq!(status, 502);
    }
}
