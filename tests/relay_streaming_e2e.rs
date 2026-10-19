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
