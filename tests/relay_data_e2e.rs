//! End-to-end tests for the relay's data path.
//!
//! A fake device dials out, enrolls, opens data connections, and answers
//! proxied requests — so routing, header handling, and pool behaviour are
//! verified against a running relay rather than against handlers in isolation.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use shell_tunnel::relay::protocol::{DeviceMessage, RelayMessage, PROTOCOL_VERSION};
use shell_tunnel::relay::proxy::{ProxyRequest, ProxyResponse};
use shell_tunnel::relay::{relay_router, RelayConfig, RelayState, POOL_TARGET};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig::new(addr, "secret").with_public_base("https://relay.test");
    let router = relay_router(RelayState::new(config));
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

async fn recv(socket: &mut Socket) -> RelayMessage {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("relay should answer")
            .expect("stream should stay open")
            .expect("frame should be readable");
        if let Message::Text(text) = message {
            return serde_json::from_str(&text).expect("relay frames are protocol messages");
        }
    }
}

/// Enroll a device; returns its id and the live control connection.
async fn enroll(addr: SocketAddr) -> (String, Socket) {
    let (mut control, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/control"))
            .await
            .expect("control endpoint should accept the upgrade");

    let message = DeviceMessage::Enroll {
        enroll_token: "secret".to_string(),
        version: PROTOCOL_VERSION,
        label: Some("fake-device".to_string()),
    };
    control
        .send(Message::Text(serde_json::to_string(&message).unwrap()))
        .await
        .unwrap();

    let RelayMessage::Enrolled { device_id, .. } = recv(&mut control).await else {
        panic!("expected an enrolled message");
    };
    (device_id, control)
}

/// Open one data connection and serve exactly one proxied request on it.
///
/// This is what a real device does: dial out, read the request header and body,
/// reply with a response header, body, then close.
async fn serve_one_request(
    addr: SocketAddr,
    device_id: &str,
    token: &str,
    status: u16,
    reply: &'static str,
) -> tokio::task::JoinHandle<ProxyRequest> {
    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .expect("data connection should be accepted");

    // Credentials go in the first frame, never in the URL.
    let attach = DeviceMessage::Attach {
        device_id: device_id.to_string(),
        enroll_token: token.to_string(),
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();

    tokio::spawn(async move {
        let request: ProxyRequest = loop {
            match conn.next().await {
                Some(Ok(Message::Text(text))) => break serde_json::from_str(&text).unwrap(),
                Some(Ok(_)) => continue,
                other => panic!("expected a request header, got {other:?}"),
            }
        };
        // Request body frame; always sent, empty for GETs.
        let _ = conn.next().await;

        let head = ProxyResponse {
            status,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
        };
        conn.send(Message::Text(serde_json::to_string(&head).unwrap()))
            .await
            .unwrap();
        conn.send(Message::Binary(reply.as_bytes().to_vec()))
            .await
            .unwrap();
        conn.close(None).await.unwrap();
        request
    })
}

/// Minimal HTTP GET — the crate deliberately has no HTTP client dependency.
async fn http_get(url: &str, header: Option<(&str, &str)>) -> (u16, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let extra = header
        .map(|(n, v)| format!("{n}: {v}\r\n"))
        .unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n{extra}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("relay should answer")
        .unwrap();

    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[tokio::test]
async fn a_request_is_proxied_to_the_device_and_answered() {
    let addr = start_relay().await;
    let (device_id, mut control) = enroll(addr).await;

    // The relay asks the device to fill its pool as soon as it enrolls.
    assert_eq!(
        recv(&mut control).await,
        RelayMessage::OpenData { count: POOL_TARGET }
    );

    let device = serve_one_request(addr, &device_id, "secret", 200, "hello from the device").await;

    let (status, body) = http_get(
        &format!("http://{addr}/d/{device_id}/api/v1/execute?x=1"),
        None,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(body, "hello from the device");

    let seen = device.await.unwrap();
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.path, "/api/v1/execute?x=1");
}

#[tokio::test]
async fn the_authorization_header_reaches_the_device_unchanged() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;
    let device = serve_one_request(addr, &device_id, "secret", 200, "ok").await;

    let (status, _body) = http_get(
        &format!("http://{addr}/d/{device_id}/api/v1/sessions"),
        Some(("authorization", "Bearer st_capability_token")),
    )
    .await;
    assert_eq!(status, 200);

    let seen = device.await.unwrap();
    let auth = seen
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.clone());
    // The relay routes; the capability token has to arrive untouched.
    assert_eq!(auth.as_deref(), Some("Bearer st_capability_token"));

    // Hop-by-hop headers describe the client's connection to the relay, not the
    // message, so they must not be replayed onto the device.
    assert!(
        !seen
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("host")),
        "{:?}",
        seen.headers
    );
}

#[tokio::test]
async fn an_unknown_device_is_a_bad_gateway() {
    let addr = start_relay().await;
    let (status, _body) = http_get(&format!("http://{addr}/d/does-not-exist/health"), None).await;
    assert_eq!(status, 502);
}

#[tokio::test]
async fn an_attached_device_with_no_connections_is_unavailable() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;

    // Enrolled but never opened a data connection: the pool is empty.
    let (status, _body) = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn a_data_connection_with_a_bad_token_never_joins_the_pool() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;

    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .expect("the upgrade itself is not the authentication step");
    let attach = DeviceMessage::Attach {
        device_id: device_id.clone(),
        enroll_token: "wrong".to_string(),
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();

    // A connection that cannot prove the secret must not become usable
    // capacity: requests still find an empty pool.
    let (status, _body) = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn credentials_never_appear_in_a_data_connection_url() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;

    // The URL a device dials carries no secret — proxies log query strings.
    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .expect("a credential-free URL must still be accepted");
    let attach = DeviceMessage::Attach {
        device_id: device_id.clone(),
        enroll_token: "secret".to_string(),
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();

    // Give the relay a moment to park it, then prove it became real capacity.
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::spawn(async move {
        let _ = conn.next().await;
    });
    let (status, _body) = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;
    assert_ne!(status, 503, "the connection should have joined the pool");
}

#[tokio::test]
async fn consuming_a_connection_asks_the_device_for_another() {
    let addr = start_relay().await;
    let (device_id, mut control) = enroll(addr).await;

    // Initial fill request.
    assert!(matches!(
        recv(&mut control).await,
        RelayMessage::OpenData { .. }
    ));

    let _device = serve_one_request(addr, &device_id, "secret", 200, "ok").await;
    let _ = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;

    // Taking a connection out of the pool must trigger a refill, or the pool
    // drains to nothing after a handful of requests.
    assert!(matches!(
        recv(&mut control).await,
        RelayMessage::OpenData { count: 1 }
    ));
}
