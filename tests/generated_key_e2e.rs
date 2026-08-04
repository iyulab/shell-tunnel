//! The key a server generates for itself, seen by a library consumer.
//!
//! The binary generates its key one layer up and prints it on the banner, so
//! this branch is the library's alone: `serve_on` with authentication on and no
//! key registered. It used to write that key to the log — a plaintext secret in
//! whatever an embedding consumer's logs go to. What matters here is that the
//! key now arrives on the channel *and is the one the server actually accepts*:
//! a reported key that does not authenticate would be worse than no report.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use shell_tunnel::{api, api::SecurityConfig, AppState};

/// Minimal HTTP GET — the crate has no HTTP client dependency.
async fn get(addr: SocketAddr, path: &str, token: Option<&str>) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{auth}\r\n");
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

#[tokio::test]
async fn a_generated_key_reaches_the_consumer_that_asked_for_it() {
    let mut security = SecurityConfig::secure();
    security.auth.enabled = true;
    // No `with_api_key`: this is the branch where the server has to make one.

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let config = api::ServerConfig::new("127.0.0.1".to_string(), addr.port())
        .with_security(security)
        .without_graceful_shutdown()
        .report_generated_key_to(tx);

    tokio::spawn(api::serve_on(listener, config, AppState::new()));

    // Receiving after the spawn, not before it: the channel is unbounded and
    // the send precedes the first accept, so the key waits rather than racing.
    let key = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the server must report the key it generated, not just hold it")
        .expect("the channel must carry the key, not close");

    assert!(key.starts_with("st_"), "{key}");
    assert_eq!(
        get(addr, "/api/v1/sessions", Some(&key)).await,
        200,
        "the reported key must be the one the server accepts"
    );
    assert_eq!(get(addr, "/api/v1/sessions", None).await, 401);
    assert_eq!(
        get(addr, "/api/v1/sessions", Some("st_not_this_one")).await,
        401
    );
}

/// Leaving the channel unset is allowed, and costs the caller the key.
///
/// The server still starts and still authenticates — it simply holds a key
/// nobody has. The warning that says so is not asserted here (it goes to
/// `tracing`, which a test binary does not install); what is pinned is that the
/// branch does not panic and does not fall open.
#[tokio::test]
async fn without_the_channel_the_server_still_refuses_unauthenticated_callers() {
    let mut security = SecurityConfig::secure();
    security.auth.enabled = true;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config = api::ServerConfig::new("127.0.0.1".to_string(), addr.port())
        .with_security(security)
        .without_graceful_shutdown();

    tokio::spawn(api::serve_on(listener, config, AppState::new()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(get(addr, "/api/v1/sessions", None).await, 401);
}
