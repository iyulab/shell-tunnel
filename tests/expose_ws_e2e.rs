//! `/x/<name>/…` carrying a WebSocket to an exposed service, over real sockets.
//!
//! The router tests in `expose_api.rs` drive requests straight into the
//! router, which cannot upgrade a connection: an upgrade needs hyper holding a
//! real one. What is pinned here: the service's own handshake (its `101`, the
//! sub-protocol it accepted) reaches the caller, messages go both ways through
//! the pipe, this server's key never reaches the service while the caller's
//! `Authorization` does, a service that will not upgrade is passed back as the
//! refusal it gave, and the connection leaves an `expose` entry in the trail.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use shell_tunnel::api::{self, SecurityConfig};
use shell_tunnel::audit::{AuditEvent, AuditSink};
use shell_tunnel::expose::ExposeSet;
use shell_tunnel::{AppState, CapabilitySet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

/// What the upstream's handshake saw.
#[derive(Debug, Default, Clone)]
struct Seen {
    path: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A WebSocket service that echoes every message, accepting the `chat`
/// sub-protocol when asked, and records what it was sent.
async fn echo_service() -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                // The handshake callback's error type is the library's, and large.
                #[allow(clippy::result_large_err)]
                let callback = |request: &Request, mut response: Response| {
                    let mut seen = recorded.lock().unwrap();
                    seen.path = request
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default();
                    seen.headers = request
                        .headers()
                        .iter()
                        .map(|(n, v)| {
                            (
                                n.as_str().to_ascii_lowercase(),
                                v.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect();
                    if seen
                        .headers
                        .iter()
                        .any(|(n, v)| n == "sec-websocket-protocol" && v.contains("chat"))
                    {
                        response
                            .headers_mut()
                            .insert("sec-websocket-protocol", HeaderValue::from_static("chat"));
                    }
                    Ok(response)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(socket, callback).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    if message.is_close() {
                        break;
                    }
                    if ws.send(message).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, seen)
}

/// This server, exposing `echo` at `upstream_port`, with a key that holds
/// `expose:echo`. Returns its address and its trail.
async fn gateway(upstream_port: u16, dir: &std::path::Path) -> (SocketAddr, std::path::PathBuf) {
    let trail = dir.join("audit.jsonl");
    let sink = Arc::new(AuditSink::file(&trail).unwrap());
    let mut security = SecurityConfig::secure()
        .with_api_key("gateway-key")
        .with_capabilities(CapabilitySet::from_iter(["expose:echo"]));
    security.auth.enabled = true;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let exposes = ExposeSet::parse(&[format!("echo=http://127.0.0.1:{upstream_port}")]).unwrap();
    let state = AppState::new().with_audit(sink).with_exposes(exposes);
    let config =
        api::ServerConfig::new("127.0.0.1".to_string(), addr.port()).with_security(security);
    tokio::spawn(async move {
        api::serve_on(listener, config, state).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, trail)
}

fn request_to(
    addr: SocketAddr,
    path: &str,
    key: Option<&str>,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let mut request = format!("ws://{addr}{path}").into_client_request().unwrap();
    if let Some(key) = key {
        request
            .headers_mut()
            .insert("x-shell-tunnel-key", HeaderValue::from_str(key).unwrap());
    }
    request
}

#[tokio::test]
async fn messages_cross_the_pipe_both_ways_under_the_services_own_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let (port, seen) = echo_service().await;
    let (addr, _trail) = gateway(port, dir.path()).await;

    let mut request = request_to(addr, "/x/echo/socket?room=7", Some("gateway-key"));
    request
        .headers_mut()
        .insert("sec-websocket-protocol", HeaderValue::from_static("chat"));
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_static("Bearer service-token"),
    );
    let (mut ws, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("the upgrade reaches the service and comes back");

    // The service's own answer: the sub-protocol it accepted, not one this
    // server chose.
    assert_eq!(response.status(), 101);
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("chat")
    );

    ws.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::Text("hello".into())
    );
    let blob = vec![0u8, 255, 7, 128];
    ws.send(Message::Binary(blob.clone())).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Binary(blob));
    ws.close(None).await.ok();

    let seen = seen.lock().unwrap().clone();
    // Where it was asked for, with its query.
    assert_eq!(seen.path, "/socket?room=7");
    // The service's own credential arrives; this server's key does not.
    assert_eq!(seen.header("authorization"), Some("Bearer service-token"));
    assert_eq!(seen.header("x-shell-tunnel-key"), None, "{seen:?}");
}

#[tokio::test]
async fn an_upgrade_without_the_key_is_refused_before_it_reaches_the_service() {
    let dir = tempfile::tempdir().unwrap();
    let (port, seen) = echo_service().await;
    let (addr, _trail) = gateway(port, dir.path()).await;

    let refused = tokio_tungstenite::connect_async(request_to(addr, "/x/echo/", None)).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 401)
        }
        other => panic!("expected a 401 refusal, got {other:?}"),
    }
    assert_eq!(seen.lock().unwrap().path, "", "the service was not reached");
}

/// A service that is not a WebSocket server answers the upgrade with an
/// ordinary refusal; the caller gets that answer, not a hang and not a
/// made-up status.
#[tokio::test]
async fn a_service_that_will_not_upgrade_is_passed_back_as_the_refusal_it_gave() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 4\r\n\r\nnope")
            .await
            .unwrap();
        // Held open, the way a keep-alive service would: the answer must not
        // depend on the connection closing.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let (addr, _trail) = gateway(port, dir.path()).await;

    let answered = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async(request_to(addr, "/x/echo/", Some("gateway-key"))),
    )
    .await
    .expect("a refusal must not wait for the service to close");
    match answered {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 400);
            assert_eq!(response.body().as_deref(), Some(&b"nope"[..]));
        }
        other => panic!("expected the service's 400, got {other:?}"),
    }
}

#[tokio::test]
async fn a_service_that_is_not_there_is_a_bad_gateway() {
    let dir = tempfile::tempdir().unwrap();
    // A port nothing listens on: bound, then released.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let (addr, _trail) = gateway(port, dir.path()).await;

    match tokio_tungstenite::connect_async(request_to(addr, "/x/echo/", Some("gateway-key"))).await
    {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 502)
        }
        other => panic!("expected a 502, got {other:?}"),
    }
}

#[tokio::test]
async fn the_connection_leaves_one_expose_entry_with_its_traffic() {
    let dir = tempfile::tempdir().unwrap();
    let (port, _seen) = echo_service().await;
    let (addr, trail) = gateway(port, dir.path()).await;

    let (mut ws, _) =
        tokio_tungstenite::connect_async(request_to(addr, "/x/echo/", Some("gateway-key")))
            .await
            .unwrap();
    ws.send(Message::Text("count these bytes".into()))
        .await
        .unwrap();
    ws.next().await.unwrap().unwrap();
    // The entry is written when the connection ends, with what crossed it.
    ws.close(None).await.ok();
    drop(ws);

    let mut entry = None;
    for _ in 0..100 {
        let events: Vec<AuditEvent> = std::fs::read_to_string(&trail)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .filter(|event: &AuditEvent| event.kind == "expose")
            .collect();
        if let Some(event) = events.into_iter().next() {
            entry = Some(event);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let entry = entry.expect("the connection must be recorded");
    assert_eq!(entry.status, Some(101));
    assert!(entry.bytes.unwrap_or(0) > 0, "{entry:?}");
    assert!(entry
        .client
        .as_deref()
        .is_some_and(|c| c.starts_with("127.0.0.1:")));
}
