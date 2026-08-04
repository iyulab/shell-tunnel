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
    /// Expect exactly this certificate, identified by its SHA-256 fingerprint.
    ///
    /// The alternative to naming an authority, and the better fit for a
    /// self-signed relay: nothing has to be copied to the device but the string
    /// itself, and the certificate need not name the address being dialled,
    /// because the certificate *is* what was verified.
    pub fingerprint: Option<String>,
    /// Extra PEM certificate authority to trust, for a relay whose certificate
    /// is not signed by a public CA.
    ///
    /// Without this a private or self-signed relay certificate is refused —
    /// correctly, since the alternative is trusting whatever answers. Naming the
    /// authority keeps that check intact instead of disabling it.
    pub ca_file: Option<PathBuf>,
    /// Receives this device's public URL each time it enrolls, including after
    /// a reconnect.
    ///
    /// The client used to `println!` the URL itself, which put a piece of the
    /// binary's startup banner inside the library — so a consumer embedding
    /// this client got writes to stdout it never asked for, and the phrasing of
    /// a user-facing line lived somewhere no banner test looks. Reporting the
    /// event and leaving the wording to the caller keeps both where they
    /// belong; a `None` here attaches silently.
    ///
    /// Every enrolment is reported, not only the first: distinguishing "first
    /// attach" from "re-attached after a drop" is the caller's decision, and
    /// the client cannot make it without also deciding how each should read.
    pub enrolled: Option<tokio::sync::mpsc::UnboundedSender<String>>,
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

    /// The host and port a dial actually goes to.
    ///
    /// The relay URL appears in the startup banner and nowhere else; the line
    /// that repeats on every retry never said where it was going, which left an
    /// operator with a failure and no target to check. Written out rather than
    /// parsed with a URL crate because `base` has already normalised the scheme
    /// and nothing beyond the authority is wanted here.
    pub fn dial_target(&self) -> String {
        let base = self.base();
        let (scheme, rest) = match base.split_once("://") {
            Some((scheme, rest)) => (scheme.to_string(), rest.to_string()),
            None => ("wss".to_string(), base.clone()),
        };
        let authority = rest.split('/').next().unwrap_or(&rest).to_string();
        // An IPv6 literal carries colons inside its brackets, so only a colon
        // after the closing bracket is a port.
        let has_port = match authority.rsplit_once(']') {
            Some((_, tail)) => tail.starts_with(':'),
            None => authority.contains(':'),
        };
        if has_port {
            authority
        } else {
            let implied = if scheme == "wss" { 443 } else { 80 };
            format!("{authority}:{implied}")
        }
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
    // Built before the dial so the failure path can read what the verifier
    // recorded: a rejected certificate's fingerprint is the one thing an
    // operator needs and the one thing rustls cannot carry out in its error.
    let (tls, seen) = connector(config)?;
    let (mut control, _) = tokio_tungstenite::connect_async_tls_with_config(
        config
            .control_url()
            .into_client_request()
            .map_err(|e| ShellTunnelError::Tunnel(format!("bad relay url: {e}")))?,
        None,
        false,
        tls,
    )
    .await
    .map_err(|e| {
        let presented = seen.lock().ok().and_then(|s| s.clone());
        ShellTunnelError::Tunnel(explain_dial_failure(&e, config, presented.as_deref()))
    })?;

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
            if let Some(enrolled) = &config.enrolled {
                // A closed receiver means the caller stopped listening, which
                // is not this connection's problem: the device is enrolled and
                // has work to do either way.
                let _ = enrolled.send(public_url.clone());
            }
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
        // The recorded certificate is not read here: a data connection only
        // opens after the control channel enrolled over the same TLS
        // configuration, so a pin that failed has already been reported once
        // by `attach` with both fingerprints in it.
        connector(config)?.0,
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

    // A failed read is not an empty body. Treating the two alike would replay
    // the request locally without whatever it was carrying — a `PATCH` writing
    // an upload chunk would append nothing and answer as though it had. The
    // relay's own receive loop had the mirror image of this on the response
    // side, where it returned a truncated body under `200 OK`.
    //
    // The relay caps a request body at 8 MiB before forwarding, so nothing
    // reaching here should be large enough to fail the read. Correctness that
    // rests on an upstream limit is not a contract, and the cost of not relying
    // on it is one match arm.
    let body = match conn.next().await {
        Some(Ok(Message::Binary(bytes))) => bytes.to_vec(),
        // No body frame at all: a GET, or the relay closed an idle connection.
        None | Some(Ok(Message::Close(_))) => Vec::new(),
        Some(Err(e)) => {
            return Err(ShellTunnelError::Tunnel(format!(
                "could not read the request body: {e}"
            )))
        }
        Some(Ok(_)) => Vec::new(),
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

/// Append one advice line, indented to sit under the failure text.
///
/// A helper rather than newlines inside each literal: `cargo fmt` folds a
/// backslash continuation into a run of spaces, and user-facing text in this
/// repository has shipped broken that way four times.
fn advise(message: &mut String, line: &str) {
    message.push_str("\n  ");
    message.push_str(line);
}

/// Proxy environment variables that are set on this machine.
///
/// Read only to *report* them. This client dials the relay directly and honours
/// none of these, which on a network that mandates a proxy is the whole reason
/// nothing connects — and the screen said nothing about it.
/// Both casings are checked because Unix tools disagree about which to use, and
/// the result is de-duplicated case-insensitively because Windows does not
/// distinguish them at all — without that, a single variable is reported as
/// `HTTPS_PROXY, https_proxy`, which reads as two problems. Found by running it.
fn proxy_env_set() -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        if !std::env::var_os(name).is_some_and(|value| !value.is_empty()) {
            continue;
        }
        if found.iter().any(|seen| seen.eq_ignore_ascii_case(name)) {
            continue;
        }
        found.push(name);
    }
    found
}

/// Turn a dial failure into something an operator can act on.
///
/// rustls reports certificate problems in its own vocabulary — `BadSignature`
/// says nothing about the far more likely cause, which is that the file passed
/// to `--relay-ca` is not the certificate this relay is currently serving.
///
/// Reaching the relay at all is the other half, and for a long time it was the
/// missing half: a device on a network that blocks outbound TCP repeated one
/// raw OS error forever, with no target, no classification, and no next step.
/// Certificate confusion happens once, when the configuration is first wrong;
/// failing to reach the relay happens every time a device is placed on a
/// constrained network, which is what this product is for.
///
/// An HTTP refusal is separated from both: the relay answered, so neither the
/// certificate advice nor the reachability advice applies, and the prefix says
/// refused rather than unreachable.
///
/// Reachability is classified from [`std::io::ErrorKind`], never from the
/// message: an OS error string is translated into the machine's own language,
/// so matching on its text works on the machine it was written on and nowhere
/// else. (The certificate branches below do match on text, but rustls writes
/// that text itself and does not localise it.)
fn explain_dial_failure(
    error: &tokio_tungstenite::tungstenite::Error,
    config: &RelayClientConfig,
    presented: Option<&str>,
) -> String {
    let text = error.to_string();
    let target = config.dial_target();

    // A refusal is not a failure to reach: the relay answered, and saying
    // "cannot reach relay" here sends an operator to firewalls and DNS for a
    // relay that is up and talking. Rate limiting is the case that matters,
    // because the device then retries in backoff and, without this, says
    // nothing about why or whether it will recover — four enrolments were
    // refused this way in the field and the console showed only the retries.
    if let tokio_tungstenite::tungstenite::Error::Http(response) = error {
        let status = response.status();
        let mut message = format!("relay refused this connection: HTTP {status}");
        if status == 429 {
            advise(
                &mut message,
                &format!("{target} is rate limiting this address, not rejecting this device."),
            );
            advise(
                &mut message,
                "This is transient and the device keeps retrying in backoff; it attaches",
            );
            advise(&mut message, "once the address is under the limit again.");
            advise(
                &mut message,
                "If it persists, something else is sharing this machine's outbound address",
            );
            advise(
                &mut message,
                "and spending the relay's per-address budget. Raise the relay's limit, or",
            );
            advise(&mut message, "give the device an address of its own.");
        } else {
            advise(&mut message, &format!("Dialling {target}."));
        }
        return message;
    }

    // A pin that did not match is neither a failure to reach nor a certificate
    // problem in the ordinary sense: the relay answered and the handshake got
    // as far as its certificate. Left to the branches below it surfaced as
    // `cannot reach relay: IO error: invalid peer certificate:
    // ApplicationVerificationFailure` — four wrappings ending in a rustls enum
    // name, never once saying `fingerprint`, and opening with a phrase that
    // sends an operator to firewalls and DNS. The value they typed is the
    // cause; both values belong in the message.
    if let Some(expected) = &config.fingerprint {
        if text.contains("ApplicationVerificationFailure") {
            let mut message = "relay certificate does not match --relay-fingerprint".to_string();
            advise(&mut message, &format!("pinned:      {expected}"));
            match presented {
                Some(actual) => advise(&mut message, &format!("relay sent:  {actual}")),
                None => advise(
                    &mut message,
                    "The certificate the relay sent could not be fingerprinted here.",
                ),
            }
            advise(
                &mut message,
                "The relay prints its own on the `Devices join with:` line of its banner.",
            );
            advise(
                &mut message,
                "A relay that regenerated its certificate has a new one, so a value copied",
            );
            advise(
                &mut message,
                "before that no longer matches. Retrying changes nothing until the pin or",
            );
            advise(&mut message, "that certificate does.");
            return message;
        }
    }

    let mut message = format!("cannot reach relay: {text}");

    if text.contains("BadSignature") || text.contains("UnknownIssuer") {
        let ca = config
            .ca_file
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "the system trust store".to_string());
        advise(
            &mut message,
            &format!("{ca} does not vouch for the certificate this relay is presenting."),
        );
        advise(
            &mut message,
            "A relay that regenerated its certificate, or a copy taken from a different",
        );
        advise(
            &mut message,
            "relay directory, both look like this. Copy the relay's current",
        );
        advise(
            &mut message,
            "shell-tunnel-cert.pem and pass it as --relay-ca.",
        );
    } else if text.contains("NotValidForName") {
        advise(
            &mut message,
            "The certificate does not cover the name being dialled.",
        );
        advise(
            &mut message,
            "Start the relay with --public-base for that name, after deleting",
        );
        advise(
            &mut message,
            "shell-tunnel-cert.pem and shell-tunnel-key.pem so it is regenerated.",
        );
    } else if let tokio_tungstenite::tungstenite::Error::Io(io) = error {
        match io.kind() {
            std::io::ErrorKind::TimedOut => {
                advise(&mut message, &format!("Nothing answered at {target}."));
                advise(
                    &mut message,
                    "The connection was not refused, it was swallowed — something between",
                );
                advise(
                    &mut message,
                    "this machine and that address is dropping it: a firewall, a route, or",
                );
                advise(&mut message, "an outbound policy.");
                advise(
                    &mut message,
                    "No shell-tunnel flag changes this. The next thing to check is whether",
                );
                advise(
                    &mut message,
                    "this machine can open *any* outbound connection to that port; if the",
                );
                advise(
                    &mut message,
                    "relay can be moved to a port the network already allows out, try that.",
                );
            }
            std::io::ErrorKind::ConnectionRefused => {
                advise(
                    &mut message,
                    &format!("{target} was reached, and nothing is listening on it."),
                );
                advise(
                    &mut message,
                    "The address and the route to it are fine, so this is the relay's end:",
                );
                advise(
                    &mut message,
                    "check that it is running, and that it bound the port being dialled.",
                );
            }
            // Everything else — name resolution among them, which has no
            // portable `ErrorKind` — still gets the target, which is the part
            // no failure used to carry.
            _ => advise(&mut message, &format!("Dialling {target}.")),
        }
    } else {
        advise(&mut message, &format!("Dialling {target}."));
    }

    let proxies = proxy_env_set();
    if !proxies.is_empty() {
        let (verb, pronoun) = if proxies.len() == 1 {
            ("is", "it")
        } else {
            ("are", "them")
        };
        advise(
            &mut message,
            &format!(
                "{} {verb} set, and this client does not use {pronoun}:",
                proxies.join(", ")
            ),
        );
        advise(
            &mut message,
            &format!("the relay at {target} is dialled directly. On a network that requires"),
        );
        advise(
            &mut message,
            "a proxy for outbound connections, that alone explains this.",
        );
    }

    message
}

/// Accepts one exact certificate and nothing else.
///
/// Deliberately the whole of the check: the presented certificate either has the
/// fingerprint the operator pinned or it does not. Name validity and chain
/// building are not consulted, because pinning already answers the question they
/// exist to answer — is this the peer I meant? A mistake here fails closed: an
/// unexpected certificate is rejected, never waved through.
#[derive(Debug)]
struct PinnedCertificate {
    expected: Vec<u8>,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
    /// The fingerprint of whatever was presented, when it was not the pinned
    /// one.
    ///
    /// rustls answers a rejected certificate with one of its own enum variants
    /// and gives a custom verifier nowhere to attach a reason, so the value an
    /// operator needs — the one to copy if the relay is the one that changed —
    /// would otherwise be computed here and thrown away. Recording it beside
    /// the connector is what lets the dial failure name both numbers.
    seen: SeenCertificate,
}

/// Where a rejected certificate's fingerprint is left for the error message.
type SeenCertificate = std::sync::Arc<std::sync::Mutex<Option<String>>>;

impl rustls::client::danger::ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let presented = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if presented.as_ref() == self.expected.as_slice() {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(crate::fingerprint::of_certificate(end_entity.as_ref()));
        }
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build the TLS connector this configuration calls for.
///
/// Returning `None` means "use the defaults", which is what a relay with a
/// publicly-signed certificate needs.
fn connector(
    config: &RelayClientConfig,
) -> Result<(Option<tokio_tungstenite::Connector>, SeenCertificate)> {
    let seen: SeenCertificate = std::sync::Arc::new(std::sync::Mutex::new(None));
    if let Some(fingerprint) = &config.fingerprint {
        let expected = crate::fingerprint::parse(fingerprint)
            .map_err(|e| ShellTunnelError::Tunnel(format!("bad --relay-fingerprint: {e}")))?;
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::ring::default_provider()));

        let tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(PinnedCertificate {
                expected,
                provider,
                seen: std::sync::Arc::clone(&seen),
            }))
            .with_no_client_auth();
        return Ok((
            Some(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
                tls,
            ))),
            seen,
        ));
    }

    let Some(path) = &config.ca_file else {
        return Ok((None, seen));
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
    Ok((
        Some(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
            tls,
        ))),
        seen,
    ))
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

    let stream = match tokio::net::TcpStream::connect(local).await {
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

    // Write and read at the same time, and stop writing the moment an answer
    // starts arriving.
    //
    // A server that refuses a request on its body length answers *before* the
    // body has finished arriving and then closes. Writing on into a closed peer
    // draws a RST, and a RST discards whatever is still sitting unread in the
    // receive buffer — so a client that writes to completion and only then
    // reads loses the answer the server did send. That is how the device's
    // `413` reached callers as a synthetic `502`, sending an operator to check
    // whether the device was alive when what they needed was "split the
    // request". It reproduced as a race, not a constant: on loopback the write
    // usually finishes first, so roughly one attempt in ten lost it, while the
    // first attempt across a relay lost it outright.
    //
    // Two halves of one fix, and neither alone is enough. Reading concurrently
    // gets the bytes into memory, where a later RST cannot reach them. Stopping
    // the write as soon as any arrive is what keeps the RST from being provoked
    // in the first place — with the write left running, the reader is racing a
    // reset that erases exactly what it came for.
    //
    // Chunked so the check happens more than once, and so each chunk boundary
    // is a scheduling point where the reader can actually run.
    let (mut read_half, mut write_half) = stream.into_split();
    let answered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_answered = std::sync::Arc::clone(&answered);
    let reader = tokio::spawn(async move {
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        let ok = loop {
            match read_half.read(&mut buf).await {
                Ok(0) => break true,
                Ok(n) => {
                    // Published before the bytes are appended so the writer
                    // stops at the earliest possible point; `raw` is read only
                    // after this task is joined, so no ordering is owed to it.
                    reader_answered.store(true, std::sync::atomic::Ordering::Release);
                    raw.extend_from_slice(&buf[..n]);
                }
                Err(_) => break false,
            }
        };
        (raw, ok)
    });

    let mut write_failed = write_half.write_all(head.as_bytes()).await.is_err();
    if !write_failed {
        for chunk in body.chunks(64 * 1024) {
            // Hand the runtime a scheduling point. `write_all` into a socket
            // with room in its send buffer completes without ever yielding, so
            // without this the reader is not polled until the whole body is
            // out — which is the very thing being fixed, and on a
            // current-thread runtime it does not get polled at all.
            tokio::task::yield_now().await;
            if answered.load(std::sync::atomic::Ordering::Acquire) {
                // The server has already answered. Everything still unwritten
                // would only provoke the reset that erases that answer.
                break;
            }
            if write_half.write_all(chunk).await.is_err() {
                write_failed = true;
                break;
            }
        }
    }

    // Deliberately *not* half-closed. The reader reaches EOF anyway, because
    // the request above asks for `Connection: close` and the server closes once
    // it has answered. Shutting the write side down instead makes every request
    // fail: hyper does not serve a half-closed connection — it reads EOF from
    // the client and abandons the response in progress, so the reader sees a
    // clean close with zero bytes. Verified: with the shutdown in place
    // `/health` answered an empty-bodied 502 on every call.
    let (raw, read_ok) = reader.await.unwrap_or_else(|_| (Vec::new(), false));
    drop(write_half);

    // Whatever arrived wins over either failure: an answer the server actually
    // sent is more informative than this function's guess at why it stopped.
    if !raw.is_empty() {
        return parse_response(&raw);
    }
    if write_failed {
        return bad_gateway("local server closed the connection".to_string());
    }
    if !read_ok {
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
            fingerprint: None,
            ca_file: None,
            enrolled: None,
        }
    }

    #[test]
    fn a_fingerprint_is_what_the_connector_uses_when_given() {
        // Both configured: pinning is the stronger statement — it names the
        // certificate itself rather than something allowed to issue one.
        let config = RelayClientConfig {
            fingerprint: Some(crate::fingerprint::of_certificate(b"whatever")),
            ca_file: Some(PathBuf::from("unused.pem")),
            ..config("wss://relay.example.com")
        };
        // The CA file does not exist; reaching for it would fail here.
        assert!(matches!(connector(&config), Ok((Some(_), _))));
    }

    #[test]
    fn a_malformed_fingerprint_is_refused_before_dialling() {
        let config = RelayClientConfig {
            fingerprint: Some("sha256:not-a-real-digest".to_string()),
            ..config("wss://relay.example.com")
        };
        let err = match connector(&config) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a malformed fingerprint must not produce a connector"),
        };
        assert!(err.contains("--relay-fingerprint"), "{err}");
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

        let message = explain_dial_failure(&error, &config, None);
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
        let message = explain_dial_failure(&error, &config("wss://relay.example.com"), None);

        assert!(message.contains("--public-base"), "{message}");
    }

    /// A timeout must be classified from the error's *kind*, whatever language
    /// the operating system wrote its message in.
    ///
    /// This is the assertion that dies if anyone reaches for `text.contains`
    /// again. The message below is the one a Korean-locale Windows machine
    /// produced in the incident that prompted this branch — matching on the
    /// English words that are not in it would leave exactly the operators this
    /// message exists for reading a raw OS error and nothing else.
    #[test]
    fn a_timeout_is_recognised_from_its_kind_not_its_language() {
        use tokio_tungstenite::tungstenite::Error;

        // One line on purpose: a `\` continuation inside a string literal is
        // what has broken user-facing text here four times, and a test fixture
        // that silently loses a space is no better.
        let localised = "연결된 구성원으로부터 응답이 없어 연결하지 못했거나, 호스트로부터 응답이 없어 연결이 끊어 졌습니다. (os error 10060)";
        let error = Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            localised.to_string(),
        ));
        let message = explain_dial_failure(&error, &config("wss://relay.example.com:8443"), None);

        // Where it was going. The URL was only ever in the startup banner.
        assert!(message.contains("relay.example.com:8443"), "{message}");
        // And that the flags are not where to look next — the point the
        // incident turned on. An operator stares at their own arguments
        // because those are the only variable on screen.
        assert!(message.contains("No shell-tunnel flag"), "{message}");
        // The OS text is still there: it is the truth about that machine.
        assert!(message.contains("os error 10060"), "{message}");
        // Not mistaken for a certificate problem.
        assert!(!message.contains("--relay-ca"), "{message}");
    }

    /// Windows reports a connect timeout as `10060`, and the incident's console
    /// showed exactly that. Pinning the raw code proves the branch is reachable
    /// from what the OS actually produces, not only from a hand-made `ErrorKind`.
    #[test]
    #[cfg(windows)]
    fn the_os_code_from_the_incident_reaches_the_timeout_branch() {
        use tokio_tungstenite::tungstenite::Error;

        let error = Error::Io(std::io::Error::from_raw_os_error(10060));
        let message = explain_dial_failure(&error, &config("wss://relay.example.com:8443"), None);
        assert!(message.contains("Nothing answered at"), "{message}");
    }

    /// A pin that did not match must say `--relay-fingerprint`, and both values.
    ///
    /// Pinning works — a wrong value is refused and the right one attaches,
    /// verified with a live relay either way. The diagnostic was the part that
    /// said nothing: `cannot reach relay: IO error: invalid peer certificate:
    /// ApplicationVerificationFailure`, four wrappings ending in a rustls enum
    /// name, never once naming the flag whose value caused it — and opening
    /// with a phrase that sends an operator to firewalls and DNS for a relay
    /// that answered and offered its certificate.
    #[test]
    fn a_mismatched_fingerprint_names_the_flag_and_both_values() {
        use tokio_tungstenite::tungstenite::Error;

        let pinned = crate::fingerprint::of_certificate(b"the one that was pinned");
        let served = crate::fingerprint::of_certificate(b"the one the relay sent");
        let config = RelayClientConfig {
            fingerprint: Some(pinned.clone()),
            ..config("wss://relay.example.com:8443")
        };
        let error = Error::Io(std::io::Error::other(
            "invalid peer certificate: ApplicationVerificationFailure",
        ));

        let message = explain_dial_failure(&error, &config, Some(&served));

        assert!(
            message.contains("--relay-fingerprint"),
            "the value an operator typed is the cause and must be named: {message}"
        );
        assert!(
            !message.contains("cannot reach relay"),
            "the relay was reached and offered a certificate: {message}"
        );
        assert!(message.contains(&pinned), "the pinned value: {message}");
        assert!(
            message.contains(&served),
            "the value to copy if the relay is what changed: {message}"
        );
        assert!(
            message.contains("Retrying changes nothing"),
            "the retry loop is silent, so the line has to say the wait is not the fix: {message}"
        );
    }

    /// The same rustls variant without a pin in force is somebody else's error.
    ///
    /// `--relay-ca` can produce it too, and blaming `--relay-fingerprint` for a
    /// flag the operator never passed would be its own wrong turn.
    #[test]
    fn a_verification_failure_without_a_pin_is_not_blamed_on_the_pin() {
        use tokio_tungstenite::tungstenite::Error;

        let error = Error::Io(std::io::Error::other(
            "invalid peer certificate: ApplicationVerificationFailure",
        ));
        let message = explain_dial_failure(&error, &config("wss://relay.example.com:8443"), None);

        assert!(
            !message.contains("--relay-fingerprint"),
            "no fingerprint was pinned, so it cannot be the cause: {message}"
        );
    }

    /// Being rate limited is not being unreachable, and must not read like it.
    ///
    /// The relay answered — it answered `429`. The device then retries in
    /// backoff and recovers on its own, so the console line has to say both
    /// that this is the relay's doing and that it is temporary. It used to say
    /// `cannot reach relay`, which sends an operator to firewalls and DNS for
    /// a relay that is up and talking to them.
    #[test]
    fn being_rate_limited_does_not_read_as_being_unreachable() {
        use tokio_tungstenite::tungstenite::{http::Response, Error};

        let response = Response::builder().status(429).body(None).unwrap();
        let message = explain_dial_failure(
            &Error::Http(response),
            &config("wss://relay.example.com:8443"),
            None,
        );

        assert!(
            !message.contains("cannot reach relay"),
            "the relay was reached: {message}"
        );
        assert!(message.contains("rate limiting"), "{message}");
        assert!(
            message.contains("transient") || message.contains("retrying"),
            "an operator must learn this recovers on its own: {message}"
        );
        assert!(
            message.contains("relay.example.com:8443"),
            "the target belongs in every dial failure: {message}"
        );
    }

    /// Refused and timed out mean different things and must not read the same.
    /// One says the relay is not there; the other says nothing between here and
    /// there will let a connection through.
    #[test]
    fn a_refusal_and_a_timeout_do_not_say_the_same_thing() {
        use tokio_tungstenite::tungstenite::Error;

        let refused = Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        let refused = explain_dial_failure(&refused, &config("wss://relay.example.com:8443"), None);
        let timed_out = Error::Io(std::io::Error::from(std::io::ErrorKind::TimedOut));
        let timed_out =
            explain_dial_failure(&timed_out, &config("wss://relay.example.com:8443"), None);

        assert!(refused.contains("nothing is listening"), "{refused}");
        assert!(timed_out.contains("swallowed"), "{timed_out}");
        assert_ne!(
            refused, timed_out,
            "the two must not collapse into one message"
        );
    }

    /// A relay URL with no port still names the port that will be dialled —
    /// the operator did not write it, so telling them the host alone leaves out
    /// the half that outbound policies act on.
    #[test]
    fn an_implied_port_is_spelled_out() {
        assert_eq!(
            config("wss://relay.example.com").dial_target(),
            "relay.example.com:443"
        );
        assert_eq!(
            config("http://relay.example.com").dial_target(),
            "relay.example.com:80"
        );
        assert_eq!(
            config("https://relay.example.com:8443/").dial_target(),
            "relay.example.com:8443"
        );
        // An IPv6 literal's own colons are not a port.
        assert_eq!(config("wss://[::1]").dial_target(), "[::1]:443");
        assert_eq!(config("wss://[::1]:9000").dial_target(), "[::1]:9000");
    }

    #[test]
    fn an_unrelated_failure_is_left_alone() {
        use tokio_tungstenite::tungstenite::Error;

        let error = Error::Io(std::io::Error::other("connection refused"));
        let message = explain_dial_failure(&error, &config("wss://relay.example.com"), None);

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
