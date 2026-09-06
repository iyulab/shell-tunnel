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
use shell_tunnel::{AppState, FsRoot, ServerConfig};

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

/// Mirrors `tests/fs_relay_e2e.rs::start_device_server` — a peer with a real
/// `--fs-root`, for the fs-endpoint test below (the only path Phase 3's
/// direct connect is eligible for at all, `connect.rs::is_direct_eligible`).
async fn start_peer_device_with_fs_root() -> (tempfile::TempDir, SocketAddr) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = FsRoot::new(dir.path()).expect("fs root");
    std::fs::write(dir.path().join("hello.txt"), b"hi from the peer").unwrap();
    let state = AppState::new().with_fs_root(root);
    let config = ServerConfig::new("127.0.0.1", 0).without_graceful_shutdown();
    let listener = api::bind(&config).await.expect("bind local server");
    let local_addr = listener.local_addr().expect("local addr");
    tokio::spawn(api::serve_on(listener, config, state));
    (dir, local_addr)
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
        serve_direct_requests: true,
        direct_events: None,
    };
    tokio::spawn(run(config, None));
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

/// Minimal HTTP/1.1 client with a JSON body, same shape as `http_get` above.
async fn http_post_json(url: &str, body: &str) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
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
        serve_direct_requests: false,
        direct_events: None,
    };
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(shell_tunnel::connect::serve(
        connect_config,
        "box1".to_string(),
        0,
        Duration::from_secs(3600),
        Some(bound_tx),
        std::future::pending(),
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

/// The one path family Phase 3 ever attempts direct for
/// (`connect.rs::is_direct_eligible`) — `/health` above never exercises
/// `try_direct`/`send_keepalive` at all. Two requests in a row: the second
/// proves the cached-stream reuse path (`send_keepalive`, not a fresh
/// `write_and_read_http1` per call) actually answers correctly, not just the
/// first-request punch-and-connect path.
#[tokio::test]
async fn a_caller_reaches_an_fs_endpoint_through_connect_mode_twice() {
    let relay_addr = start_relay().await;
    let (_dir, peer_addr) = start_peer_device_with_fs_root().await;
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
        serve_direct_requests: false,
        direct_events: None,
    };
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(shell_tunnel::connect::serve(
        connect_config,
        "box1".to_string(),
        0,
        Duration::from_secs(3600),
        Some(bound_tx),
        std::future::pending(),
    ));
    let connect_addr = tokio::time::timeout(Duration::from_secs(5), bound_rx)
        .await
        .expect("connect should bind promptly")
        .expect("connect should report its bound address");

    let list_url = format!("http://{connect_addr}/d/box1/api/v1/fs/list?path=.");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let (status, body) = loop {
        let (status, body) = http_get(&list_url).await;
        if status == 200 || tokio::time::Instant::now() > deadline {
            break (status, body);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(status, 200, "body: {}", String::from_utf8_lossy(&body));
    assert!(
        String::from_utf8_lossy(&body).contains("hello.txt"),
        "the peer's real fs root must be what answered: {}",
        String::from_utf8_lossy(&body)
    );

    // Second request: whether this went direct or fell back, it must still
    // answer correctly — a cached stream that broke would fail every request
    // after the first, not just intermittently.
    let (status2, body2) = http_get(&list_url).await;
    assert_eq!(status2, 200, "body: {}", String::from_utf8_lossy(&body2));
    assert!(String::from_utf8_lossy(&body2).contains("hello.txt"));
}

/// `chunk_size` is a property of the request that reached the peer, not of
/// `connect`'s own relay attach — a request that punched a direct socket to
/// the peer must be told the peer's *direct* default (4 MiB), because that
/// leg is never bound by the relay's deadline. 262144 here would mean the
/// relay's marker header leaked onto a request that never actually crossed
/// the relay (`api::fs::via_relay`, `fs::UploadStore::chunk_size`).
#[tokio::test]
async fn a_direct_connect_upload_session_gets_the_direct_chunk_size() {
    let relay_addr = start_relay().await;
    let (_dir, peer_addr) = start_peer_device_with_fs_root().await;
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
        serve_direct_requests: false,
        direct_events: None,
    };
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(shell_tunnel::connect::serve(
        connect_config,
        "box1".to_string(),
        0,
        Duration::from_secs(3600),
        Some(bound_tx),
        std::future::pending(),
    ));
    let connect_addr = tokio::time::timeout(Duration::from_secs(5), bound_rx)
        .await
        .expect("connect should bind promptly")
        .expect("connect should report its bound address");

    let create_url = format!("http://{connect_addr}/d/box1/api/v1/fs/uploads");
    // SHA-256 of b"hello world", matching `fs::transfer`'s own test fixture.
    let create_body = serde_json::json!({
        "path": "direct-chunk-check.bin",
        "size": 11,
        "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    })
    .to_string();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (status, body) = loop {
        let (status, body) = http_post_json(&create_url, &create_body).await;
        if status == 201 || tokio::time::Instant::now() > deadline {
            break (status, body);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(status, 201, "body: {}", String::from_utf8_lossy(&body));
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("upload creation returns json");
    assert_eq!(
        json["chunk_size"], 4_194_304,
        "the peer never joined a relay itself, so its direct default (4 MiB) is what a \
         direct-connect socket must be told: {json}"
    );
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
        serve_direct_requests: false,
        direct_events: None,
    };
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(shell_tunnel::connect::serve(
        connect_config,
        "box1".to_string(),
        0,
        Duration::from_secs(3600),
        Some(bound_tx),
        std::future::pending(),
    ));
    let connect_addr = tokio::time::timeout(Duration::from_secs(5), bound_rx)
        .await
        .expect("connect should bind promptly")
        .expect("connect should report its bound address");

    let (status, _body) =
        http_get(&format!("http://{connect_addr}/d/some-other-device/health")).await;
    assert_eq!(status, 404);
}

/// New in Task 4, not a Task-3 carryover: proves the idle-timeout wiring did
/// not change what an unattached peer looks like to a caller (still the
/// relay's own 502, unaffected by connect's own idle clock).
#[tokio::test]
async fn a_request_for_an_unattached_peer_gets_the_relays_own_502() {
    let relay_addr = start_relay().await;
    let connect_config = RelayClientConfig {
        relay_url: format!("ws://{relay_addr}"),
        enroll_token: "secret".to_string(),
        local: "127.0.0.1:1".parse().unwrap(),
        label: None,
        device_name: None,
        fingerprint: None,
        ca_file: None,
        enrolled: None,
        serve_direct_requests: false,
        direct_events: None,
    };
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(shell_tunnel::connect::serve(
        connect_config,
        "nobody-attached".to_string(),
        0,
        Duration::from_secs(3600),
        Some(bound_tx),
        std::future::pending(),
    ));
    let connect_addr = tokio::time::timeout(Duration::from_secs(5), bound_rx)
        .await
        .unwrap()
        .unwrap();

    let (status, _body) =
        http_get(&format!("http://{connect_addr}/d/nobody-attached/health")).await;
    assert_eq!(status, 502);
}

/// Every path that puts the direct route on cooldown says so at a level the
/// default filter shows.
///
/// The gap this pins was measured, not imagined: `connect` dispatches with
/// `RUST_LOG` set to a bare `info` (`main.rs`), which is a global level
/// directive — so a `debug!` on any target is dropped, and three of the four
/// ways a connect-mode request can lose its fast path announced nothing an
/// operator would ever see. Two were `debug!`; the third (a cached direct
/// connection breaking mid-request) had no log at all, which made the failure
/// that appears *after* everything looked healthy the quietest of the set.
///
/// Structural rather than behavioural, and deliberately so. Observing these
/// lines for real needs a relay, a peer, a direct negotiation that fails on
/// purpose, and a subscriber installed process-wide — the last of which fights
/// every other test in the binary, since a `tracing` subscriber is global. The
/// repo already has this trade in
/// `executor_integration::execution_takes_its_deadline_from_one_bounded_place`,
/// and this follows its shape.
///
/// Lives in this feature-gated file because it is about `connect`; the check
/// itself needs no feature (it reads text), so it runs under `cargo test-all`,
/// which this project treats as the complete command.
#[test]
fn every_direct_cooldown_path_announces_itself_at_the_default_log_level() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let connect = std::fs::read_to_string(root.join("src/connect.rs")).expect("readable");
    let client = std::fs::read_to_string(root.join("src/relay/client.rs")).expect("readable");

    let cooldowns = connect.matches("cooldown_until = Some(").count();
    let announcements = connect
        .matches("tracing::info!(target: \"connect\"")
        .count();
    assert_eq!(
        cooldowns, announcements,
        "src/connect.rs puts the direct route on cooldown {cooldowns} time(s) but announces \
         it {announcements} time(s). A cooldown an operator cannot see is the whole defect \
         this guards: the request still succeeds over the relay, so nothing else in the \
         system reports that the fast path was dropped"
    );
    assert_eq!(
        cooldowns, 3,
        "the three cooldown paths are: negotiation reported a failure, negotiation timed \
         out, and a reused connection broke mid-request. A fourth means a new way to lose \
         the direct route — give it a line too, and update this count"
    );

    assert!(
        client.contains("tracing::warn!(target: \"connect\", \"{reason}\")"),
        "relay_unreachable's 502 body is generic on purpose, so this log line is the only \
         place the actual cause (bad host name, TLS handshake, refused connection) is \
         named. Demoted below the default level, an operator sees the failure and never \
         the reason for it. `warn!` rather than the `info!` above because this request \
         failed, while those describe one that succeeded over the other route"
    );

    // What this does not cover, stated rather than implied.
    //
    // Both halves count text, so a doc comment that quotes one of these
    // literals will break them. That direction is loud rather than silent,
    // which is the acceptable one, and it is the same trade the executor's
    // deadline guard makes.
    //
    // The first pair proves that as many announcements exist as cooldowns —
    // not that each announcement sits next to the cooldown it describes. A
    // rearrangement that logged one path twice and another not at all would
    // still pass. Pairing them positionally would mean parsing Rust, and the
    // failure it would catch has never happened here; the demotion this
    // catches is the one that did.
}
