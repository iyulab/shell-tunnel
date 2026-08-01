//! Filesystem transfer over the relay path.
//!
//! Every other filesystem test drives the handlers directly (`tests/fs_api.rs`)
//! or through an in-process router. Neither exercises the seam this feature was
//! actually designed around: the relay buffers a whole request body with an
//! 8 MiB ceiling (`relay::mod::MAX_BODY`, private to that module — hardcoded
//! here as `8 * 1024 * 1024`), which is why `chunk_size` defaults to 4 MiB and
//! why `list` is paginated at all. This test runs a real relay, a real
//! `AppState` with `--fs-root` wired in, and a real `relay::client::run` device
//! process between them, so an upload session's create/append/complete actually
//! crosses the relay rather than being asserted about it.
//!
//! It is also the only test that exercises `relay::client::replay_locally`
//! reconstructing a `PATCH` with a binary body and a `Content-Range` header —
//! every other relay test only ever sends a `GET`.

#![cfg(feature = "relay-client")]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use shell_tunnel::api;
use shell_tunnel::fs::sha256::Hasher;
use shell_tunnel::relay::client::{run, RelayClientConfig};
use shell_tunnel::relay::{relay_router, RelayConfig, RelayState};
use shell_tunnel::{AppState, FsRoot, ServerConfig};

/// Start a relay on an ephemeral port; returns its address.
///
/// Mirrors `tests/relay_data_e2e.rs::start_relay` — same shape, duplicated
/// rather than shared, matching how the existing relay test files each carry
/// their own copy of this helper.
async fn start_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

/// Start a real API server, `--fs-root` confined to a fresh temp directory.
///
/// No auth: this test is about the relay carrying fs traffic intact, not about
/// the capability layer, which every fs handler test already covers directly.
/// `without_graceful_shutdown` skips installing a process-wide Ctrl+C handler,
/// which a test process must not do.
async fn start_device_server() -> (tempfile::TempDir, SocketAddr) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = FsRoot::new(dir.path()).expect("fs root");
    let state = AppState::new().with_fs_root(root);

    let config = ServerConfig::new("127.0.0.1", 0).without_graceful_shutdown();
    let listener = api::bind(&config).await.expect("bind local server");
    let local_addr = listener.local_addr().expect("local addr");
    tokio::spawn(api::serve_on(listener, config, state));

    (dir, local_addr)
}

/// Dial the relay as a real device would, serving `local_addr` behind it.
fn spawn_device(relay_addr: SocketAddr, local_addr: SocketAddr, device_name: &str) {
    let config = RelayClientConfig {
        relay_url: format!("ws://{relay_addr}"),
        enroll_token: "secret".to_string(),
        local: local_addr,
        label: None,
        device_name: Some(device_name.to_string()),
        fingerprint: None,
        ca_file: None,
    };
    tokio::spawn(run(config));
}

/// A minimal hand-rolled HTTP/1.1 client — the crate deliberately has no HTTP
/// client dependency, and this is the same trade `tests/relay_data_e2e.rs`'s
/// `http_get` already makes, generalised to any method/headers/body.
async fn http_request(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("relay should answer")
        .unwrap();

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len());
    let (head, resp_body) = raw.split_at(split);
    let head = String::from_utf8_lossy(head);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, resp_body.to_vec())
}

async fn http_json(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, serde_json::Value) {
    let (status, body) = http_request(url, method, headers, body).await;
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or_else(|e| panic!("expected json, got {e}: {body:?}"))
    };
    (status, json)
}

/// Poll the device's own `/health` through the relay until it answers.
///
/// Enrollment and the first data-connection pool fill both happen
/// concurrently with the spawned client task, and — unlike an empty pool,
/// which the relay itself retries for `POOL_WAIT` — an unattached device is
/// an immediate `502` from `proxy_handler`. A fixed sleep would be the
/// flaky part of this test; polling a route that needs neither `--fs-root`
/// nor auth is the cheapest proof the whole chain (relay, device, its data
/// connections) is actually live before any upload assertion runs.
async fn wait_until_attached(base: &str) {
    for _ in 0..50 {
        let (status, _) = http_request(&format!("{base}/health"), "GET", &[], &[]).await;
        if status == 200 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("device never became reachable through the relay");
}

/// Like `http_request`, but reads past any interim `1xx` block to the final
/// response, the way a client that sent `Expect: 100-continue` must.
///
/// `http_request` takes the first status line it sees, which is the whole
/// reason the defect this covers survived: with `Expect` in play the first
/// status line *is* `100 Continue`, so a test parsing naively would either
/// assert on the interim status or read a `500` and not know which layer
/// produced it.
async fn http_request_final_status(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> u16 {
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    // Sent without waiting for the interim response. A client is allowed to do
    // this, and it keeps the test from hanging if the server never sends one —
    // the point here is which *final* status comes back, not the handshake's
    // timing.
    stream.write_all(body).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("relay should answer")
        .unwrap();

    let text = String::from_utf8_lossy(&raw);
    text.split("\r\n\r\n")
        .filter_map(|block| block.split_whitespace().nth(1))
        .filter_map(|code| code.parse::<u16>().ok())
        .find(|code| !(100..200).contains(code))
        .unwrap_or(0)
}

/// A body-carrying request with `Expect: 100-continue` must reach the device
/// and come back with the device's own status.
///
/// It came back `500` while the device answered `200`. The relay replayed the
/// `Expect` header onto the device's local HTTP call, that server answered with
/// an interim `100 Continue`, the device reported the interim response as *the*
/// response, and the relay tried to return `100` as a final status — which
/// hyper cannot write, so it substituted an empty `500`.
///
/// The request always succeeded. Only the status the caller saw was wrong,
/// which is the worst shape available here: a non-idempotent `execute`
/// reported as failed after it had already run, and an upload chunk written
/// but reported lost. `curl` adds the header automatically above roughly a
/// kilobyte, so this hit every real upload while the suite — which never sent
/// it — stayed green.
#[tokio::test]
async fn a_request_with_expect_100_continue_is_answered_by_the_device() {
    let relay_addr = start_relay().await;
    let (_dir, local_addr) = start_device_server().await;
    let device_name = "expect-device";
    spawn_device(relay_addr, local_addr, device_name);
    let base = format!("http://{relay_addr}/d/{device_name}");
    wait_until_attached(&base).await;

    let create_body = serde_json::json!({
        "path": "expect.bin",
        "size": 11,
        "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    })
    .to_string();

    let status = http_request_final_status(
        &format!("{base}/api/v1/fs/uploads"),
        "POST",
        &[
            ("content-type", "application/json"),
            ("expect", "100-continue"),
        ],
        create_body.as_bytes(),
    )
    .await;

    assert_eq!(
        status, 201,
        "the device answers 201; a 500 here means the relay returned its own \
         status instead of the device's"
    );
}

#[tokio::test]
async fn a_download_too_large_for_one_frame_is_not_reported_as_success() {
    // The device returns a response body as a single binary frame, so a file
    // over the WebSocket message limit (16 MiB by default on both ends) fails
    // the relay's *read* of that frame. That failure used to be indistinguishable
    // from a clean close: the receive loop was `while let Some(Ok(_))`, so it
    // simply stopped, and the status — already taken from the header frame that
    // arrived before the body — went out as the device's `200`. A caller asking
    // for a 20 MiB file got `200 OK`, `content-type: application/json`,
    // `content-length: 0`, and no way to tell the file had not been delivered.
    //
    // Live-verified before the fix, over a real relay: 16,777,100 bytes came
    // back whole, 16,777,216 came back as `200` with an empty body. The same
    // threshold hit `/execute` output.
    //
    // What this pins is the *honesty* of the answer, not a particular limit: a
    // body that cannot be carried must not arrive wearing a success status.
    let relay_addr = start_relay().await;
    let (dir, local_addr) = start_device_server().await;

    let device_name = "oversize-device";
    spawn_device(relay_addr, local_addr, device_name);
    let base = format!("http://{relay_addr}/d/{device_name}");
    wait_until_attached(&base).await;

    // Comfortably over the 16 MiB frame limit, so the read fails rather than
    // landing near a boundary this test would then be asserting about.
    let payload = vec![b'x'; 20 * 1024 * 1024];
    std::fs::write(dir.path().join("oversize.bin"), &payload).expect("write");

    let (status, body) = http_request(
        &format!("{base}/api/v1/fs/file?path=oversize.bin"),
        "GET",
        &[],
        &[],
    )
    .await;

    if status == 200 {
        assert_eq!(
            body.len(),
            payload.len(),
            "a 200 must carry the whole file; a short body under 200 is the \
             silent truncation this test exists to catch"
        );
    } else {
        assert_eq!(
            status, 502,
            "a body the relay cannot carry is a failed upstream read, which is \
             what 502 means; got {status}"
        );
    }
}

#[tokio::test]
async fn an_upload_completes_over_the_relay() {
    let relay_addr = start_relay().await;
    let (dir, local_addr) = start_device_server().await;

    let device_name = "fs-e2e-device";
    spawn_device(relay_addr, local_addr, device_name);

    let base = format!("http://{relay_addr}/d/{device_name}");
    wait_until_attached(&base).await;

    // Deliberately not chunk-aligned: one full 4 MiB chunk plus a short final
    // one, so the loop below exercises more than a single round trip.
    let payload_len = 5 * 1024 * 1024 + 777;
    let payload = vec![0xAB_u8; payload_len];
    let mut hasher = Hasher::new();
    hasher.update(&payload);
    let digest = hasher.finish();

    let create_body = serde_json::json!({
        "path": "out.bin",
        "size": payload.len(),
        "sha256": digest,
    })
    .to_string();

    let (status, created) = http_json(
        &format!("{base}/api/v1/fs/uploads"),
        "POST",
        &[("content-type", "application/json")],
        create_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 201, "{created}");

    let upload_id = created["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();
    let chunk_size = created["chunk_size"].as_u64().expect("chunk_size") as usize;

    // The assertion that catches a future chunk-size change breaking every
    // relayed transfer: the advertised size must fit inside a relayed body.
    // `relay::mod::MAX_BODY` is private and not reachable from an integration
    // test, so its value (8 MiB) is restated here rather than imported.
    const RELAY_MAX_BODY: usize = 8 * 1024 * 1024;
    assert!(chunk_size < RELAY_MAX_BODY, "chunk_size={chunk_size}");

    let mut offset = 0usize;
    while offset < payload.len() {
        let end = (offset + chunk_size).min(payload.len());
        let chunk = &payload[offset..end];
        let range = format!("bytes {offset}-{}/{}", end - 1, payload.len());

        let (status, state) = http_json(
            &format!("{base}/api/v1/fs/uploads/{upload_id}"),
            "PATCH",
            &[("content-range", &range)],
            chunk,
        )
        .await;
        assert_eq!(status, 200, "{state}");
        // Pins the forwarded `Content-Range` value, not just its presence:
        // the server's reported offset must match what this chunk actually
        // carried across the relay.
        assert_eq!(state["offset"].as_u64(), Some(end as u64));

        offset = end;
    }

    let (status, completed) = http_json(
        &format!("{base}/api/v1/fs/uploads/{upload_id}/complete"),
        "POST",
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{completed}");
    assert_eq!(completed["sha256"].as_str(), Some(digest.as_str()));

    // The bytes that arrived are the bytes that were sent.
    let destination = dir.path().join("out.bin");
    assert_eq!(std::fs::read(&destination).expect("read"), payload);
}

/// A body the device's own route limit refuses must arrive as the device's
/// `413`, not as a relay-invented `502`.
///
/// The gap this covers sits between two ceilings that are easy to conflate: the
/// relay refuses a body over its own 8 MiB `MAX_BODY` and never forwards it,
/// while a body under that but over the route's limit (axum's 2 MiB default on
/// every route that does not set its own) is forwarded and refused by the
/// device. The device answers `413` *before* the body has finished arriving and
/// closes, which breaks `replay_locally`'s write mid-send — and a client that
/// treats a write failure as "no response" throws away the `413` already sitting
/// in the receive buffer.
///
/// It reproduced as a race rather than a constant: on loopback the write usually
/// wins, so roughly one attempt in ten answered `502`. This test therefore
/// repeats — a single pass proves nothing here, and a single pass is exactly
/// what let the defect ship. Found in live verification across a relay, where
/// the loser of that race is the common case.
#[tokio::test]
async fn a_body_over_the_route_limit_answers_413_not_502() {
    let relay_addr = start_relay().await;
    let (_dir, local_addr) = start_device_server().await;
    let device_name = "toobig-device";
    spawn_device(relay_addr, local_addr, device_name);
    let base = format!("http://{relay_addr}/d/{device_name}");
    wait_until_attached(&base).await;

    // Over axum's 2 MiB `DefaultBodyLimit`, under the relay's 8 MiB `MAX_BODY`,
    // so the relay forwards it and the device is the one that says no.
    let body = vec![b'x'; 7 * 1024 * 1024];

    for attempt in 0..12 {
        let (status, reason) = http_request(
            &format!("{base}/api/v1/fs/uploads"),
            "POST",
            &[("content-type", "application/json")],
            &body,
        )
        .await;
        assert_eq!(
            status,
            413,
            "attempt {attempt} answered {status} ({}): a 502 here means the \
             device's own refusal was discarded and replaced with a guess \
             about the connection",
            String::from_utf8_lossy(&reason)
        );
    }
}
