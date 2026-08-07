//! What happens to a command whose caller hangs up in the middle of it.
//!
//! Every one of these failed before the fix, and each failed differently:
//!
//! - a session whose WebSocket client vanished reported `running: true` for
//!   ever, its idle clock running underneath it — 38.5 s after the client left,
//!   for a command with a five-second timeout;
//! - a session whose REST caller vanished did the same, 44.7 s after a command
//!   that had already finished.
//!
//! Every execute here carries an explicit short timeout, so "still running"
//! afterwards cannot be explained by the command legitimately taking long. Both
//! were confirmed to fail against the unfixed code before being kept.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures_util::SinkExt;
use shell_tunnel::api::{create_secure_router, AppState, SecurityConfig};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

async fn spawn_server() -> SocketAddr {
    let state = AppState::new();
    let (router, _store, _rl) = create_secure_router(state, SecurityConfig::development());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        axum::serve(listener, service).await.unwrap();
    });
    addr
}

/// Output enough to overrun the streaming channel many times over.
fn chatty() -> &'static str {
    if cfg!(windows) {
        "for /L %i in (1,1,20000) do @echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    } else {
        "i=0; while [ $i -lt 20000 ]; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; i=$((i+1)); done"
    }
}

/// Poll session status until it stops reporting a command running.
async fn wait_until_idle(base: &str, id: u64, within: Duration) -> serde_json::Value {
    let client = reqwest_lite::Client;
    let deadline = Instant::now() + within;
    let mut last = serde_json::Value::Null;
    while Instant::now() < deadline {
        last = client
            .get_json(&format!("{base}/sessions/{id}"))
            .await
            .expect("session status");
        if last["running"] == false {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "the session still reports a command running {:?} after the caller vanished — {last}",
        within
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_whose_websocket_client_vanishes_stops_reporting_a_command() {
    let addr = spawn_server().await;
    let base = format!("http://{}/api/v1", addr);

    let created = reqwest_lite::Client
        .post_json(&format!("{base}/sessions"), "{}")
        .await
        .expect("create session");
    let id = created["session_id"].as_u64().expect("session_id");

    let (mut ws, _resp) =
        tokio_tungstenite::connect_async(&format!("ws://{}/api/v1/sessions/{}/ws", addr, id))
            .await
            .expect("WebSocket connect failed");
    ws.send(Message::text(format!(
        r#"{{"type":"execute","command":"{}","timeout_secs":2}}"#,
        chatty()
    )))
    .await
    .expect("send failed");

    // Let the command get under way, then leave without reading a byte.
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(ws);

    // Generous on purpose. What this guards is *unbounded* — before the fix the
    // session reported a command running for ever, with no recovery — so every
    // finite bound discriminates equally well and a tight one only buys false
    // reds. Thirty seconds was buying them: this passes 3/3 in isolation
    // (7.5–21.5 s) and failed once under the full parallel suite on a loaded
    // workstation, where `chatty()` has `cmd` spawn twenty thousand echoes.
    wait_until_idle(&base, id, Duration::from_secs(120)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_whose_rest_caller_vanishes_stops_reporting_a_command() {
    use tokio::io::AsyncWriteExt;

    let addr = spawn_server().await;
    let base = format!("http://{}/api/v1", addr);

    let created = reqwest_lite::Client
        .post_json(&format!("{base}/sessions"), "{}")
        .await
        .expect("create session");
    let id = created["session_id"].as_u64().expect("session_id");

    let slow = if cfg!(windows) {
        "ping -n 6 127.0.0.1"
    } else {
        "sleep 5"
    };
    let body = format!(r#"{{"command":"{slow}"}}"#);
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /api/v1/sessions/{id}/execute HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    // Under way, then gone without reading the response.
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(stream);

    wait_until_idle(&base, id, Duration::from_secs(30)).await;
}

/// Hanging up does not cancel the command — USAGE §3 says so, and this is where
/// that sentence is checked.
///
/// It matters because the fix above could easily be read as cancellation: the
/// session goes idle the moment the caller disappears. It does not. The command
/// is on a blocking task that nothing signals, so it runs to its own end; the
/// only thing that stops it is its timeout. The command here writes a sentinel
/// after a second of work, well after its caller is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hanging_up_does_not_cancel_the_command() {
    use tokio::io::AsyncWriteExt;

    let addr = spawn_server().await;
    let dir = std::env::temp_dir().join("shell-tunnel-hangup");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let sentinel = dir.join(format!(
        "sentinel-{}-{}.txt",
        std::process::id(),
        addr.port()
    ));
    let _ = std::fs::remove_file(&sentinel);
    let s = sentinel.display().to_string();

    let command = if cfg!(windows) {
        format!("ping -n 3 127.0.0.1 >nul & echo done>\"{s}\"")
    } else {
        format!("sleep 2; echo done > '{s}'")
    };
    let body = serde_json::json!({ "command": command, "timeout_secs": 30 }).to_string();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /api/v1/execute HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    // Gone long before the command could have finished.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(stream);

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut arrived = false;
    while Instant::now() < deadline {
        if sentinel.exists() {
            arrived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = std::fs::remove_file(&sentinel);
    assert!(
        arrived,
        "the command stopped when its caller did — USAGE §3 says hanging up does not cancel it, and §4 rests on the same fact: {s}"
    );
}

// The one-shot socket (`/api/v1/ws`) runs the same shape of loop and got the
// same fix, but it is guarded one layer down instead of here, in
// `executor_integration.rs::a_consumer_that_stops_receiving_cannot_park_the_executor`.
// A one-shot has no session, so the only thing observable from outside is the
// command's own progress — and whether the channel fills before the client goes
// away turns out to depend on scheduling, so a test written here passes against
// the unfixed code about as often as it fails. A guard that green-lights the bug
// is worse than no guard; the executor-level one reproduces the stall directly
// and was confirmed to fail without the fix.

/// Minimal HTTP helper — this suite needs two verbs against a loopback address
/// and the tree carries no HTTP client dependency.
mod reqwest_lite {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    pub struct Client;

    impl Client {
        pub async fn post_json(&self, url: &str, body: &str) -> std::io::Result<serde_json::Value> {
            self.send("POST", url, Some(body)).await
        }

        pub async fn get_json(&self, url: &str) -> std::io::Result<serde_json::Value> {
            self.send("GET", url, None).await
        }

        async fn send(
            &self,
            method: &str,
            url: &str,
            body: Option<&str>,
        ) -> std::io::Result<serde_json::Value> {
            let rest = url.strip_prefix("http://").expect("http:// url");
            let (authority, path) = rest.split_once('/').expect("url has a path");
            let mut stream = TcpStream::connect(authority).await?;

            let mut req =
                format!("{method} /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
            if let Some(body) = body {
                req.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\n",
                    body.len()
                ));
            }
            req.push_str("\r\n");
            if let Some(body) = body {
                req.push_str(body);
            }
            stream.write_all(req.as_bytes()).await?;

            let mut raw = String::new();
            stream.read_to_string(&mut raw).await?;
            let payload = raw.split("\r\n\r\n").nth(1).unwrap_or("");
            Ok(serde_json::from_str(payload.trim()).unwrap_or(serde_json::Value::Null))
        }
    }
}
