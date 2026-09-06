//! Phase 3: the in-memory identity a device presents on a direct socket.
//!
//! A direct connection's trust has nothing to do with a name or an authority
//! — it is exactly the fingerprint exchanged over the control channel
//! (`DeviceMessage::DirectReady` / `RelayMessage::PeerReady`), the same model
//! `--relay-fingerprint` already uses for the control connection itself
//! (`crate::tls`'s file-backed certificate is a different thing: a stable
//! identity meant to survive restarts for other devices dialling a fixed
//! join line, gated behind the `tls` feature this crate does not need here).
//! One certificate is generated once per process, kept only in memory, and
//! never written to disk: nothing else in this product depends on it staying
//! the same across a restart, since every direct session re-exchanges the
//! fingerprint fresh.

use std::sync::Arc;

use crate::error::ShellTunnelError;
use crate::Result;

/// A self-signed identity for this process's direct-connect sockets: the
/// server-side TLS configuration to accept with, and the fingerprint every
/// `DirectReady` this process sends carries.
pub(crate) struct DirectIdentity {
    server_config: Arc<rustls::ServerConfig>,
    fingerprint: String,
}

impl DirectIdentity {
    /// Generate a fresh identity. Called once from [`super::client::run`]'s
    /// startup, before the first `DirectRequested` can arrive — the
    /// fingerprint must already exist to answer with, not be generated on
    /// demand (see the module doc on `client.rs`'s response-then-punch
    /// ordering).
    pub(crate) fn generate() -> Result<Self> {
        super::client::install_crypto_provider();

        // The name is a placeholder: nothing here ever checks it, because
        // pinning verifies the certificate itself (see
        // `super::client::pinned_client_config`), the same trust model
        // `crate::tls` already documents for the control connection's
        // certificate. A name is required syntactically by `rcgen` and by
        // `rustls::pki_types::ServerName` on the dialling side, not
        // semantically by anything that reads it.
        let issued = rcgen::generate_simple_self_signed(vec!["shell-tunnel-direct".to_string()])
            .map_err(|e| {
                ShellTunnelError::Tunnel(format!(
                    "cannot generate a direct-connect certificate: {e}"
                ))
            })?;
        let cert_der = issued.cert.der().clone();
        let key_der = issued.signing_key.serialize_der();
        let fingerprint = crate::fingerprint::of_certificate(cert_der.as_ref());

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
            )
            .map_err(|e| {
                ShellTunnelError::Tunnel(format!(
                    "generated direct-connect certificate does not load: {e}"
                ))
            })?;

        Ok(Self {
            server_config: Arc::new(server_config),
            fingerprint,
        })
    }

    /// The fingerprint to send in `DirectReady`.
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The configuration to accept an incoming direct socket with.
    pub(crate) fn server_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.server_config)
    }
}

/// The hostname placeholder passed to `rustls::pki_types::ServerName` on the
/// dialling side of a direct connection. Syntactically required, semantically
/// ignored — see [`DirectIdentity::generate`].
pub(crate) const DIRECT_SERVER_NAME: &str = "shell-tunnel-direct";

/// The whole budget for a direct-connect attempt, signal to socket:
/// `RequestDirect` sent → `PeerReady`/`DirectRequested` received → punch
/// succeeded. One budget, not two stacked ones (plan §4.5) — applying it
/// separately to "wait for the signal" and "wait for the socket" would let a
/// slow relay round trip and a slow punch each spend the full window,
/// doubling the worst-case wait before falling back to the relay path for
/// no benefit (the signal round trip is normally one relay hop, not a
/// meaningful fraction of this).
pub(crate) const PUNCH_DEADLINE: Duration = Duration::from_secs(5);

/// How long a single `connect()` attempt is allowed to hang before this loop
/// gives up on it and tries again.
///
/// Loopback never needs this — a refused connection returns immediately. A
/// real NAT can silently drop the SYN, and without a bound `connect()` would
/// not return until the OS's own SYN-retransmit timeout (about 20s on
/// Linux), which alone would blow through [`PUNCH_DEADLINE`] on the first
/// attempt. Spike evidence (`hd_p2p3_port_reuse_spike.py`, cycle-132) never
/// needed longer than ~150ms per attempt on loopback; 1s leaves headroom
/// without eating the whole deadline on one hung attempt.
const PUNCH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

/// Delay between attempts. Loopback attempts fail instantly (see above), so
/// this exists only to keep a busy-loop from spinning the CPU between them —
/// it does not trade off discriminating power the way the deadline does.
const PUNCH_ATTEMPT_INTERVAL: Duration = Duration::from_millis(10);

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

/// Bind a fresh outbound socket to `local_port` (reusing the port an
/// already-`ESTABLISHED` control connection holds — validated viable on
/// Windows and Linux, cycle-132's spike, §0 of the Phase 3 plan) and try to
/// connect to `target`, retrying on a new socket each time until `deadline`
/// elapses.
///
/// A failed `connect()` leaves the socket unusable for another attempt (both
/// platforms, confirmed by the same spike), so each retry rebuilds the
/// socket rather than reusing it.
pub(crate) async fn punch(
    local_port: u16,
    target: SocketAddr,
    deadline: Duration,
) -> std::io::Result<TcpStream> {
    let started = tokio::time::Instant::now();
    let local: SocketAddr = if target.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, local_port).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, local_port).into()
    };

    loop {
        let socket = if target.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(local)?;

        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no direct connection to {target} within {deadline:?}"),
            ));
        }

        match tokio::time::timeout(remaining.min(PUNCH_ATTEMPT_TIMEOUT), socket.connect(target))
            .await
        {
            Ok(Ok(stream)) => return Ok(stream),
            // A timed-out single attempt or a refused/unreachable one are the
            // same case here: try again on a fresh socket, same port, until
            // the deadline. Only the deadline itself is a real failure.
            Ok(Err(_)) | Err(_) => {
                tokio::time::sleep(PUNCH_ATTEMPT_INTERVAL).await;
            }
        }
    }
}

/// Resolve `target` (a `host:port` string, as
/// [`super::client::RelayClientConfig::dial_target`] produces) and open an
/// outbound `TcpStream` to it from an OS-chosen local port, reporting that
/// port back.
///
/// Used once per `attach()` cycle for the control connection itself — the
/// port this returns is what every direct-connect punch during that cycle
/// reuses (plan §4.5: `run()` is the only thing that knows this port).
pub(crate) async fn dial_with_local_port(target: &str) -> std::io::Result<(TcpStream, u16)> {
    let mut addrs = tokio::net::lookup_host(target).await?;
    let remote = addrs.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{target} did not resolve to any address"),
        )
    })?;

    let socket = if remote.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Bind port 0 (OS-assigned) rather than a port this process picks:
    // nothing about this address needs to be predictable ahead of time, only
    // known *after* the bind so it can be reused (see `punch` above).
    let local: SocketAddr = if remote.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    socket.set_reuseaddr(true)?;
    socket.bind(local)?;
    let stream = socket.connect(remote).await?;
    let port = stream.local_addr()?.port();
    Ok((stream, port))
}

/// What a direct-connect attempt produced, delivered to whichever caller
/// asked `run()` to try one (`connect.rs`, via
/// `RelayClientConfig::direct_events`).
///
/// Always the **client role**'s outcome — `connect.rs` is always the
/// requester (plan §5-5's role assignment: the local proxy dials, the target
/// device accepts), so the only stream this carries is a TLS client stream
/// already pinned to the peer's fingerprint and ready for HTTP/1.1 requests.
pub enum DirectEvent {
    /// A direct socket to the requested peer is up and pinned. Boxed: the
    /// `Failed` variant is a `String`, and clippy's own measurement put the
    /// unboxed stream at 1112 bytes — every `DirectEvent` (including a
    /// `Failed` one) would otherwise pay that size.
    Connected(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// Signalling or the punch itself failed; the caller should fall back to
    /// the relay path and enter a cooldown before trying this peer again.
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_identity_is_immediately_usable_as_a_server_config() {
        let identity = DirectIdentity::generate().unwrap();
        assert!(identity.fingerprint().starts_with("sha256:"));
        // `server_config()` returning at all (no panic building it) is the
        // property worth pinning here; an actual handshake is exercised by
        // the higher-level punch test once `client.rs` wires this in.
        let _ = identity.server_config();
    }

    #[test]
    fn two_generated_identities_have_different_fingerprints() {
        // Each process generates its own — nothing should make two runs
        // collide, which would be the sign of an accidentally deterministic
        // key.
        let a = DirectIdentity::generate().unwrap();
        let b = DirectIdentity::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[tokio::test]
    async fn dial_with_local_port_reaches_a_real_listener_and_reports_its_own_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });

        let (_stream, local_port) = dial_with_local_port(&addr.to_string()).await.unwrap();
        assert_ne!(local_port, 0, "the OS must have assigned a real port");
        accepted.await.unwrap();
    }

    #[tokio::test]
    async fn punch_succeeds_against_a_real_listener_on_the_first_or_a_later_attempt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // Port 0 here (not a real reused port): this test is about the retry
        // loop reaching a listener at all, not about port reuse itself —
        // that is what cycle-132's spike already validated empirically on
        // both platforms.
        let result = punch(0, target, Duration::from_secs(5)).await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn punch_gives_up_at_the_deadline_when_nothing_answers() {
        // A bound-but-not-listening port refuses immediately on loopback —
        // exactly the `ECONNREFUSED` case the retry loop must keep retrying
        // through until the deadline, not return early on.
        let dead_end = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        drop(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap()); // hold nothing; just to vary the port
        let started = tokio::time::Instant::now();
        let result = punch(0, dead_end, Duration::from_millis(200)).await;
        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "must not hang far past its own deadline: {:?}",
            started.elapsed()
        );
    }
}
