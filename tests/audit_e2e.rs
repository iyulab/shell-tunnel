//! The audit trail, written by a running server rather than by a unit test.
//!
//! What matters here is not that a struct serializes, but that a real request
//! through the real middleware and handlers leaves the right entry — and that a
//! credential never reaches the file.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use shell_tunnel::audit::{AuditEvent, AuditSink};
use shell_tunnel::{api, api::SecurityConfig, AppState, CapabilitySet};

/// Start a server with auth and an audit trail, returning its address.
async fn start(dir: &Path, key: &str, capabilities: &[&str]) -> (SocketAddr, std::path::PathBuf) {
    let trail = dir.join("audit.jsonl");
    let sink = Arc::new(AuditSink::file(&trail).unwrap());

    let mut security = SecurityConfig::secure().with_api_key(key);
    security.auth.enabled = true;
    if !capabilities.is_empty() {
        security =
            security.with_capabilities(CapabilitySet::from_iter(capabilities.iter().copied()));
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config =
        api::ServerConfig::new("127.0.0.1".to_string(), addr.port()).with_security(security);
    let state = AppState::new().with_audit(sink);

    tokio::spawn(async move {
        api::serve_on(listener, config, state).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, trail)
}

/// Minimal HTTP POST — the crate has no HTTP client dependency.
async fn post(addr: SocketAddr, path: &str, token: Option<&str>, body: &str) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n{auth}\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut raw))
        .await
        .expect("server should answer")
        .unwrap();

    String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// Read the trail, waiting briefly for the entry to land.
async fn events(trail: &Path, expected: usize) -> Vec<AuditEvent> {
    for _ in 0..50 {
        let parsed: Vec<AuditEvent> = std::fs::read_to_string(trail)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if parsed.len() >= expected {
            return parsed;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("expected {expected} audit entries");
}

#[tokio::test]
async fn an_execution_is_recorded_with_who_and_what() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "audit-key", &["exec"]).await;

    let status = post(
        addr,
        "/api/v1/execute",
        Some("audit-key"),
        r#"{"command":"echo audited"}"#,
    )
    .await;
    assert_eq!(status, 200);

    let event = events(&trail, 1).await.remove(0);
    assert_eq!(event.kind, "execute");
    assert_eq!(event.command.as_deref(), Some("echo audited"));
    assert_eq!(event.exit_code, Some(0));
    assert_eq!(event.timed_out, Some(false));
    // "someone called /execute" would be nearly useless; the caller has to be
    // identifiable across entries.
    let identity = event
        .identity
        .expect("an authenticated call has an identity");
    assert!(identity.token_id.starts_with("tok_"), "{identity:?}");
}

#[tokio::test]
async fn a_refused_request_is_recorded_too() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "audit-key", &["exec"]).await;

    assert_eq!(
        post(addr, "/api/v1/execute", Some("wrong"), r#"{"command":"x"}"#).await,
        401
    );
    assert_eq!(
        post(addr, "/api/v1/execute", None, r#"{"command":"x"}"#).await,
        401
    );

    let recorded = events(&trail, 2).await;
    assert!(recorded.iter().all(|e| e.kind == "denied"));
    assert_eq!(recorded[0].reason.as_deref(), Some("invalid-token"));
    assert_eq!(recorded[1].reason.as_deref(), Some("missing-token"));
}

#[tokio::test]
async fn an_insufficient_capability_names_what_was_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "ro-key", &["session.read"]).await;

    assert_eq!(
        post(
            addr,
            "/api/v1/execute",
            Some("ro-key"),
            r#"{"command":"x"}"#
        )
        .await,
        403
    );

    let event = events(&trail, 1).await.remove(0);
    assert_eq!(event.status, Some(403));
    assert_eq!(event.reason.as_deref(), Some("missing-capability:exec"));
    // A 403 is a known caller doing something they may not; the trail should say
    // which caller.
    assert!(event.identity.is_some());
}

#[tokio::test]
async fn the_token_never_reaches_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "super-secret-key", &["exec"]).await;

    post(
        addr,
        "/api/v1/execute",
        Some("super-secret-key"),
        r#"{"command":"echo hi"}"#,
    )
    .await;
    post(
        addr,
        "/api/v1/execute",
        Some("guessed-key"),
        r#"{"command":"x"}"#,
    )
    .await;

    events(&trail, 2).await;
    let raw = std::fs::read_to_string(&trail).unwrap();

    // An audit trail is kept, copied, and shipped elsewhere — a credential in it
    // outlives the incident it was meant to explain.
    assert!(!raw.contains("super-secret-key"), "{raw}");
    assert!(!raw.contains("guessed-key"), "{raw}");
    assert!(!raw.contains("Bearer"), "{raw}");
}

#[tokio::test]
async fn nothing_is_written_when_no_trail_is_configured() {
    // The default has to stay silent: creating files nobody asked for is its own
    // kind of surprise.
    let sink = AuditSink::Disabled;
    assert!(!sink.is_enabled());
    sink.record(AuditEvent::new("execute").with_command("echo nothing"));
}

#[tokio::test]
async fn a_websocket_execution_is_recorded_too() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "ws-key", &["exec"]).await;

    let mut request = format!("ws://{addr}/api/v1/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", "Bearer ws-key".parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();

    socket
        .send(Message::Text(
            r#"{"type":"execute","command":"echo over-websocket"}"#.to_string(),
        ))
        .await
        .unwrap();

    // Drain until the result arrives, so the execution has finished.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), socket.next()).await {
            Ok(Some(Ok(Message::Text(text)))) if text.contains("\"result\"") => break,
            Ok(Some(Ok(_))) => continue,
            _ => break,
        }
    }

    // Streaming execution is still execution: a trail that only sees the REST
    // path would miss whichever caller preferred WebSocket.
    let event = events(&trail, 1).await.remove(0);
    assert_eq!(event.kind, "execute");
    assert_eq!(event.command.as_deref(), Some("echo over-websocket"));
    assert_eq!(event.route.as_deref(), Some("WS /api/v1/ws"));
    assert!(event.identity.is_some());
}
