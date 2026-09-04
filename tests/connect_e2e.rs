//! `shell-tunnel connect` end-to-end: a real relay, a real device attached
//! to it, and a real connect-mode process forwarding a caller's plain HTTP
//! request through to that device — proving the whole chain the unit tests
//! in `src/connect.rs` and `src/relay/client.rs` only cover piecewise.

#![cfg(feature = "relay-client")]

use std::net::SocketAddr;
use std::time::Duration;

use shell_tunnel::api;
use shell_tunnel::relay::client::{run, RelayClientConfig};
use shell_tunnel::relay::{relay_router, RelayConfig, RelayState};
use shell_tunnel::{AppState, ServerConfig};

/// Mirrors `tests/fs_relay_e2e.rs::start_relay` — duplicated per this
/// project's convention for these small per-file test harnesses.
async fn start_relay() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig::new(addr, "secret");
    let router = relay_router(RelayState::new(config));
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

async fn start_peer_device() -> SocketAddr {
    let state = AppState::new();
    let config = ServerConfig::new("127.0.0.1", 0).without_graceful_shutdown();
    let listener = api::bind(&config).await.expect("bind local server");
    let local_addr = listener.local_addr().expect("local addr");
    tokio::spawn(api::serve_on(listener, config, state));
    local_addr
}

fn attach_peer(relay_addr: SocketAddr, local_addr: SocketAddr, device_name: &str) {
    let config = RelayClientConfig {
        relay_url: format!("ws://{relay_addr}"),
        enroll_token: "secret".to_string(),
        local: local_addr,
        label: None,
        device_name: Some(device_name.to_string()),
        fingerprint: None,
        ca_file: None,
        enrolled: None,
    };
    tokio::spawn(run(config));
}

/// Minimal HTTP/1.1 client, same shape as `tests/fs_relay_e2e.rs::http_request`.
async fn http_get(url: &str) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("connect proxy should answer")
        .unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len());
    let (head, body) = raw.split_at(split);
    let status = String::from_utf8_lossy(head)
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, body.to_vec())
}

#[tokio::test]
async fn a_caller_reaches_the_peer_device_through_connect_mode() {
    let relay_addr = start_relay().await;
    let peer_addr = start_peer_device().await;
    attach_peer(relay_addr, peer_addr, "box1");

    let connect_config = RelayClientConfig {
        relay_url: format!("ws://{relay_addr}"),
        enroll_token: "secret".to_string(),
        local: "127.0.0.1:1".parse().unwrap(), // overwritten by serve()
        label: None,
        device_name: None,
        fingerprint: None,
        ca_file: None,
        enrolled: None,
    };
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(shell_tunnel::connect::serve(
        connect_config,
        "box1".to_string(),
        0,
        Some(bound_tx),
    ));
    let connect_addr = tokio::time::timeout(Duration::from_secs(5), bound_rx)
        .await
        .expect("connect should bind promptly")
        .expect("connect should report its bound address");

    // The peer device's relay attach still needs a moment even though
    // connect's own listener is already known to be bound; poll rather than
    // sleep a fixed amount, matching fs_relay_e2e.rs::wait_until_attached's
    // reasoning.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let (status, body) = loop {
        let (status, body) = http_get(&format!("http://{connect_addr}/d/box1/health")).await;
        if status == 200 || tokio::time::Instant::now() > deadline {
            break (status, body);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(status, 200, "body: {}", String::from_utf8_lossy(&body));
    assert_eq!(&body[..], b"OK");
}

#[tokio::test]
async fn a_request_for_a_device_other_than_the_configured_peer_is_404() {
    let relay_addr = start_relay().await;
    let peer_addr = start_peer_device().await;
    attach_peer(relay_addr, peer_addr, "box1");

    let connect_config = RelayClientConfig {
        relay_url: format!("ws://{relay_addr}"),
        enroll_token: "secret".to_string(),
        local: "127.0.0.1:1".parse().unwrap(),
        label: None,
        device_name: None,
        fingerprint: None,
        ca_file: None,
        enrolled: None,
    };
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(shell_tunnel::connect::serve(
        connect_config,
        "box1".to_string(),
        0,
        Some(bound_tx),
    ));
    let connect_addr = tokio::time::timeout(Duration::from_secs(5), bound_rx)
        .await
        .expect("connect should bind promptly")
        .expect("connect should report its bound address");

    let (status, _body) =
        http_get(&format!("http://{connect_addr}/d/some-other-device/health")).await;
    assert_eq!(status, 404);
}
