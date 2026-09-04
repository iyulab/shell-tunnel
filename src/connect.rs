//! `shell-tunnel connect`: a local reverse-proxy to one relay-attached device.
//!
//! Unlike the gateway, this process serves no fs/session API of its own —
//! its one route forwards to the relay's existing public `/d/<device>/...`
//! path (`relay::client::send_to_relay`), the same path an ordinary HTTP
//! client could already reach directly. See
//! `claudedocs/plans/2026-09-04-p2p-direct-transfer-phase2-plan.md`.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::relay::client::{send_to_relay, RelayClientConfig};

#[derive(Clone)]
struct ConnectState {
    config: std::sync::Arc<RelayClientConfig>,
    peer: std::sync::Arc<str>,
}

/// Build the router: one catch-all route, forwarding only requests addressed
/// to `peer` and rejecting a WebSocket upgrade (Phase 3 territory — direct
/// connectivity is what makes a long-lived upgrade worth piping through this
/// process; forwarding it over the relay path today would just be another
/// name for the fallback the design already has).
///
/// A bare async function is already a `Handler` for every HTTP method at
/// once, which is what a catch-all needs — `Router::fallback(forward)`
/// directly, no `axum::routing::any(...)` wrapper needed.
pub(crate) fn router(config: RelayClientConfig, peer: String) -> Router {
    let state = ConnectState {
        config: std::sync::Arc::new(config),
        peer: std::sync::Arc::from(peer.as_str()),
    };
    Router::new().fallback(forward).with_state(state)
}

async fn forward(State(state): State<ConnectState>, request: Request) -> Response {
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let Some((device_id, _tail)) = crate::relay::proxy::split_device_path(&path_and_query) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if device_id != &*state.peer {
        return StatusCode::NOT_FOUND.into_response();
    }

    if crate::relay::is_websocket_upgrade(request.headers()) {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "WebSocket forwarding needs direct connectivity (Phase 3); this build only relays plain HTTP",
        )
            .into_response();
    }

    let method = request.method().to_string();
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();

    let body = match axum::body::to_bytes(request.into_body(), crate::relay::MAX_RELAY_FRAME).await
    {
        Ok(body) => body.to_vec(),
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    let (status, resp_headers, resp_body) =
        send_to_relay(&state.config, &method, &path_and_query, &headers, body).await;

    let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers {
        builder = builder.header(name, value);
    }
    builder
        .body(axum::body::Body::from(resp_body))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

/// Run `connect` mode until it is told to stop: bind a local listener,
/// forward everything on it to `peer` via the relay, and attach to the same
/// relay as an ephemeral, unnamed device.
///
/// The ephemeral attach carries no traffic in this phase — nothing addresses
/// this device's URL, since nobody but this process itself knows its
/// identity. It exists now so Phase 3's direct-connectivity signalling has a
/// control channel to run over without this process's lifecycle needing to
/// change shape later. Confirmed safe to leave inert: the relay strips the
/// `/d/<id>` prefix before forwarding anything to an attached device, and
/// this device's own local listener at `config.local` never receives
/// anything but Phase 3 candidate-exchange traffic once that exists — Task
/// 1-3 send it none.
///
/// `bound` reports the address actually bound, once it is known — `None`
/// means nobody's listening, matching `RelayClientConfig::enrolled`'s own
/// "the client used to `println!` the URL itself, which put a piece of the
/// binary's startup banner inside the library" reasoning (`src/relay/client.rs`):
/// `outln!`/`errln!` are defined in `src/main.rs`, not exported from this
/// library crate, so this function cannot print the banner itself even if it
/// wanted to — reporting the event and leaving the wording to the caller is
/// not a style choice here, it is the only option, and it is also what keeps
/// this function callable from a test with no banner at all.
///
/// Returns when the local server task ends (it does not, until the process
/// is asked to stop — see Task 4) or the relay attach loop returns an error.
pub async fn serve(
    mut config: RelayClientConfig,
    peer: String,
    local_port: u16,
    bound: Option<tokio::sync::oneshot::Sender<std::net::SocketAddr>>,
) -> crate::Result<()> {
    // `relay::client::run` already installs this once it reaches its own
    // first `wss://` dial (`src/relay/client.rs:193`), but `send_to_relay`'s
    // TLS path (Task 2) can be reached by an incoming request the instant the
    // local listener starts serving — which races that dial, not follows it,
    // since both run concurrently in the `tokio::select!` below. Installing
    // it here, before either starts, removes the race rather than hoping the
    // relay attach wins it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(crate::ShellTunnelError::Io)?;
    let local_addr = listener.local_addr().map_err(crate::ShellTunnelError::Io)?;
    config.local = local_addr;

    if let Some(tx) = bound {
        let _ = tx.send(local_addr);
    }

    let router = router(config.clone(), peer);
    let server = tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .await
            .map_err(|e| crate::ShellTunnelError::Io(std::io::Error::other(e.to_string())))
    });

    tokio::select! {
        result = server => result.expect("connect server task panicked"),
        result = crate::relay::client::run(config) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::client::RelayClientConfig;

    fn test_config(relay_url: &str) -> RelayClientConfig {
        RelayClientConfig {
            relay_url: relay_url.to_string(),
            enroll_token: "secret".to_string(),
            local: "127.0.0.1:1".parse().unwrap(),
            label: None,
            device_name: None,
            fingerprint: None,
            ca_file: None,
            enrolled: None,
        }
    }

    #[tokio::test]
    async fn a_request_for_a_different_device_is_404() {
        let router = router(test_config("http://127.0.0.1:1"), "box1".to_string());
        let response = axum::http::Request::builder()
            .uri("/d/other-device/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tower::ServiceExt::oneshot(router, response).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_request_for_the_configured_peer_is_forwarded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = tokio::io::AsyncReadExt::read(&mut socket, &mut buf)
                .await
                .unwrap();
            let head = String::from_utf8_lossy(&buf[..n]);
            assert!(
                head.starts_with("GET /d/box1/health HTTP/1.1\r\n"),
                "{head}"
            );
            tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nOK",
            )
            .await
            .unwrap();
        });

        let router = router(test_config(&format!("http://{addr}")), "box1".to_string());
        let response = axum::http::Request::builder()
            .uri("/d/box1/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tower::ServiceExt::oneshot(router, response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn a_websocket_upgrade_is_refused_not_implemented() {
        let router = router(test_config("http://127.0.0.1:1"), "box1".to_string());
        let response = axum::http::Request::builder()
            .uri("/d/box1/ws")
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tower::ServiceExt::oneshot(router, response).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
