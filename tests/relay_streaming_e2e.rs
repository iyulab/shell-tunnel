//! A device's response crosses the relay as it is produced, not once it is
//! complete — and a response that breaks after its status went out is
//! delivered broken, never as a short success.
//!
//! A fake device drives the data connection directly, so the relay's side is
//! tested on its own: how many frames, when, and how the exchange ends are the
//! device's choice here.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use shell_tunnel::relay::protocol::{DeviceMessage, RelayMessage, PROTOCOL_VERSION};
use shell_tunnel::relay::proxy::{ProxyRequest, ProxyResponse};
use shell_tunnel::relay::{relay_router, RelayConfig, RelayState};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig::new(addr, "secret").with_public_base("https://relay.test");
    let router = relay_router(RelayState::new(config));
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

async fn enroll(addr: SocketAddr) -> (String, Socket) {
    let (mut control, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/control"))
            .await
            .unwrap();
    let message = DeviceMessage::Enroll {
        enroll_token: "secret".to_string(),
        version: PROTOCOL_VERSION,
        label: None,
        device_name: None,
    };
    control
        .send(Message::Text(serde_json::to_string(&message).unwrap()))
        .await
        .unwrap();
    loop {
        if let Some(Ok(Message::Text(text))) = control.next().await {
            if let Ok(RelayMessage::Enrolled { device_id, .. }) = serde_json::from_str(&text) {
                return (device_id, control);
            }
        }
    }
}

/// A data connection, attached, with the request read off it.
async fn take_request(addr: SocketAddr, device_id: &str) -> Socket {
    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .unwrap();
    let attach = DeviceMessage::Attach {
        device_id: device_id.to_string(),
        enroll_token: "secret".to_string(),
        attach_id: None,
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();
    conn
}

async fn read_request(conn: &mut Socket) {
    loop {
        match conn.next().await {
            Some(Ok(Message::Text(text))) => {
                let _: ProxyRequest = serde_json::from_str(&text).unwrap();
                break;
            }
            Some(Ok(_)) => continue,
            other => panic!("expected a request header, got {other:?}"),
        }
    }
    let _ = conn.next().await; // the request body frame
}

async fn send_head(conn: &mut Socket) {
    let head = ProxyResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "text/event-stream".to_string())],
    };
    conn.send(Message::Text(serde_json::to_string(&head).unwrap()))
        .await
        .unwrap();
}

/// Open a request to the device and return the socket, the request written.
async fn open_request(addr: SocketAddr, device_id: &str) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request =
        format!("GET /d/{device_id}/events HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream
}

/// Read until `needle` has arrived, or panic after `limit`.
async fn read_until(stream: &mut tokio::net::TcpStream, raw: &mut Vec<u8>, needle: &str) {
    let mut buf = [0u8; 4096];
    let found = tokio::time::timeout(Duration::from_secs(10), async {
        while !String::from_utf8_lossy(raw).contains(needle) {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "the relay closed before {needle:?} arrived");
            raw.extend_from_slice(&buf[..n]);
        }
    })
    .await;
    assert!(
        found.is_ok(),
        "{needle:?} never arrived; got {:?}",
        String::from_utf8_lossy(raw)
    );
}

/// The caller holds the first event while the device has not yet sent the
/// second — which a relay that buffered the body until the device closed could
/// never do: this test would wait on itself and time out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_response_reaches_the_caller_as_the_device_sends_it() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;
    let mut conn = take_request(addr, &device_id).await;

    let (first_seen_tx, first_seen_rx) = tokio::sync::oneshot::channel::<()>();
    let device = tokio::spawn(async move {
        read_request(&mut conn).await;
        send_head(&mut conn).await;
        conn.send(Message::Binary(b"data: first\n\n".to_vec()))
            .await
            .unwrap();
        // Only once the caller has the first event does the second exist.
        first_seen_rx.await.unwrap();
        conn.send(Message::Binary(b"data: second\n\n".to_vec()))
            .await
            .unwrap();
        conn.close(None).await.unwrap();
    });

    let mut stream = open_request(addr, &device_id).await;
    let mut raw = Vec::new();
    read_until(&mut stream, &mut raw, "data: first").await;
    first_seen_tx.send(()).unwrap();
    read_until(&mut stream, &mut raw, "data: second").await;
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    raw.extend_from_slice(&rest);
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(
        text.ends_with("0\r\n\r\n"),
        "a body the device ended cleanly ends cleanly: {text:?}"
    );
    device.await.unwrap();
}

/// A device that vanishes after its first frame leaves the caller with a body
/// that is visibly unfinished — no terminating chunk — never a clean `200`
/// holding half the data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_response_broken_midway_is_delivered_broken() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;
    let mut conn = take_request(addr, &device_id).await;

    let (first_seen_tx, first_seen_rx) = tokio::sync::oneshot::channel::<()>();
    let device = tokio::spawn(async move {
        read_request(&mut conn).await;
        send_head(&mut conn).await;
        conn.send(Message::Binary(b"partial".to_vec()))
            .await
            .unwrap();
        first_seen_rx.await.unwrap();
        // Gone without a closing handshake, the way a crashed device goes.
        drop(conn);
    });

    let mut stream = open_request(addr, &device_id).await;
    let mut raw = Vec::new();
    read_until(&mut stream, &mut raw, "partial").await;
    first_seen_tx.send(()).unwrap();
    device.await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest)).await;
    raw.extend_from_slice(&rest);
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(
        !text.ends_with("0\r\n\r\n"),
        "a broken body must not be completed: {text:?}"
    );
}

/// Decode an HTTP/1.1 chunked body; panics on anything malformed.
fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("size line");
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..line_end]).unwrap().trim(), 16)
                .expect("hex size");
        body = &body[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// End to end with the real device client: a local server answering
/// `chunked`, a little at a time, reaches the caller a little at a time — and
/// decoded. The device used to read its local server's whole answer before
/// replying, and to pass a chunked body on still chunk-encoded, which the
/// caller would have read with the chunk sizes as data.
#[cfg(feature = "relay-client")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_streams_its_local_servers_answer_through_the_relay() {
    use shell_tunnel::relay::client::{run, AttachEvent, RelayClientConfig};

    let relay = start_relay().await;
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = local_listener.local_addr().unwrap();
    let (first_seen_tx, first_seen_rx) = tokio::sync::oneshot::channel::<()>();
    let local_server = tokio::spawn(async move {
        let (mut socket, _) = local_listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap();
            head.extend_from_slice(&buf[..n]);
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\nd\r\ndata: first\n\n\r\n",
            )
            .await
            .unwrap();
        first_seen_rx.await.unwrap();
        socket
            .write_all(b"e\r\ndata: second\n\n\r\n0\r\n\r\n")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run(
        RelayClientConfig {
            relay_url: format!("ws://{relay}"),
            enroll_token: "secret".to_string(),
            local,
            label: None,
            device_name: Some("streamer".to_string()),
            fingerprint: None,
            ca_file: None,
            events: Some(tx),
            serve_direct_requests: false,
            direct_events: None,
            local_hop_token: None,
            activity: None,
        },
        None,
    ));
    let event = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, AttachEvent::Enrolled { .. }), "{event:?}");
    // The pool fills right after enrolment; give it a moment rather than
    // racing the first request against an empty pool.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut stream = open_request(relay, "streamer").await;
    let mut raw = Vec::new();
    read_until(&mut stream, &mut raw, "data: first").await;
    first_seen_tx.send(()).unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    raw.extend_from_slice(&rest);
    local_server.await.unwrap();

    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("transfer-encoding: chunked"), "{head}");
    assert_eq!(
        String::from_utf8(dechunk(&raw[split + 4..])).unwrap(),
        "data: first\n\ndata: second\n\n",
        "decoded once by the device, framed once by the relay"
    );
}

/// While the device is still streaming an answer to the relay, it counts as
/// busy — after the local server's handler has long returned — and stops
/// counting once the answer is through.
///
/// An update latches only when nothing is in flight. The local server's own
/// count ends when its handler hands back the response; the relay leg runs on
/// after that. Uncounted, a device could restart under a response a caller is
/// still receiving — a server-sent event stream, which a device exposing a
/// local service would carry for minutes.
#[cfg(feature = "relay-client")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_response_still_streaming_to_the_relay_counts_as_work() {
    use shell_tunnel::api::activity::Activity;
    use shell_tunnel::relay::client::{run, AttachEvent, RelayClientConfig};
    use std::sync::Arc;

    let relay = start_relay().await;
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = local_listener.local_addr().unwrap();
    let (first_seen_tx, first_seen_rx) = tokio::sync::oneshot::channel::<()>();
    let local_server = tokio::spawn(async move {
        let (mut socket, _) = local_listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap();
            head.extend_from_slice(&buf[..n]);
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\nd\r\ndata: first\n\n\r\n",
            )
            .await
            .unwrap();
        first_seen_rx.await.unwrap();
        socket
            .write_all(b"e\r\ndata: second\n\n\r\n0\r\n\r\n")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });

    let activity = Arc::new(Activity::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run(
        RelayClientConfig {
            relay_url: format!("ws://{relay}"),
            enroll_token: "secret".to_string(),
            local,
            label: None,
            device_name: Some("busy".to_string()),
            fingerprint: None,
            ca_file: None,
            events: Some(tx),
            serve_direct_requests: false,
            direct_events: None,
            local_hop_token: None,
            activity: Some(Arc::clone(&activity)),
        },
        None,
    ));
    let event = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, AttachEvent::Enrolled { .. }), "{event:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(activity.in_flight(), 0, "an idle pool is not work");

    let mut stream = open_request(relay, "busy").await;
    let mut raw = Vec::new();
    read_until(&mut stream, &mut raw, "data: first").await;
    // The caller holds the first event; the device holds the rest of the
    // answer open. This fake local server has no count of its own, so the one
    // unit in flight is the relay leg's.
    assert_eq!(
        activity.in_flight(),
        1,
        "a response still going out through the relay must hold an update off"
    );
    assert!(!activity.latch(), "nothing may latch while it streams");

    first_seen_tx.send(()).unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    local_server.await.unwrap();

    // Delivered: the count falls back, shortly after the last frame.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while activity.in_flight() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the relay leg's count was never released"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
