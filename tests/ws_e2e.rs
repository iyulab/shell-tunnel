//! End-to-end WebSocket streaming test.
//!
//! Spins up a real server on an ephemeral port, connects a WebSocket client, and
//! verifies the one-shot execute path streams output frames and a final result —
//! exercising the HTTP upgrade + WS framing glue that `oneshot`-style router tests
//! and the executor unit tests do not cover.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use shell_tunnel::api::{create_secure_router, AppState, SecurityConfig};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

/// Bind a server on 127.0.0.1:0 and return its actual address.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_oneshot_streams_output_and_result() {
    let addr = spawn_server().await;
    let url = format!("ws://{}/api/v1/ws", addr);

    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WebSocket connect failed");

    ws.send(Message::text(
        r#"{"type":"execute","command":"echo ws_e2e_ok"}"#,
    ))
    .await
    .expect("send failed");

    let mut saw_output = false;
    let mut result_exit: Option<i64> = None;

    // Bound the whole exchange so a hang fails fast instead of blocking the suite.
    let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(msg) = ws.next().await {
            let text = match msg.expect("ws frame error") {
                Message::Text(t) => t.to_string(),
                Message::Close(_) => break,
                _ => continue,
            };
            let v: serde_json::Value = serde_json::from_str(&text).expect("invalid JSON frame");
            match v["type"].as_str() {
                Some("output") => {
                    if v["data"].as_str().unwrap_or("").contains("ws_e2e_ok") {
                        saw_output = true;
                    }
                }
                Some("result") => {
                    result_exit = v["exit_code"].as_i64();
                    break;
                }
                Some("error") => panic!("unexpected error frame: {text}"),
                _ => {}
            }
        }
    })
    .await;

    assert!(outcome.is_ok(), "WebSocket e2e exchange timed out");
    assert!(
        saw_output,
        "expected at least one output frame containing the echoed text"
    );
    assert_eq!(
        result_exit,
        Some(0),
        "expected a result frame with exit_code 0"
    );
}

/// A misspelled field on an inbound frame is answered, not silently accepted.
///
/// `timeoutSecs` for `timeout_secs` used to be dropped, which ran the command
/// with no timeout at all and then reported `timed_out: false` — indistinguishable
/// from having finished inside the limit. This asserts the pair: the correct
/// spelling runs, the near-miss comes back as an error frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_refuses_an_inbound_frame_with_an_unknown_field() {
    let addr = spawn_server().await;
    let url = format!("ws://{}/api/v1/ws", addr);

    // Each case: what to send, and whether the first frame back must be an error.
    let cases = [
        (
            r#"{"type":"execute","command":"echo ok","timeout_secs":30}"#,
            false,
        ),
        (
            r#"{"type":"execute","command":"echo ok","timeoutSecs":30}"#,
            true,
        ),
        // A frame only the server ever sends. Previously ignored in silence.
        (
            r#"{"type":"result","success":true,"exit_code":0,"duration_ms":1,"timed_out":false,"total_bytes":0}"#,
            true,
        ),
    ];

    for (frame, expect_error) in cases {
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WebSocket connect failed");
        ws.send(Message::text(frame)).await.expect("send failed");

        let first_kind = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(msg) = ws.next().await {
                let text = match msg.expect("ws frame error") {
                    Message::Text(t) => t.to_string(),
                    Message::Close(_) => return None,
                    _ => continue,
                };
                let v: serde_json::Value = serde_json::from_str(&text).expect("invalid JSON frame");
                return Some(v["type"].as_str().unwrap_or_default().to_string());
            }
            None
        })
        .await
        .expect("WebSocket exchange timed out");

        if expect_error {
            assert_eq!(
                first_kind.as_deref(),
                Some("error"),
                "expected a refusal for {frame}, got {first_kind:?}"
            );
        } else {
            assert_ne!(
                first_kind.as_deref(),
                Some("error"),
                "the accepted spelling was refused: {frame}"
            );
        }
    }
}

/// A command driven over a session's WebSocket counts as running in that
/// session, and leaves the same trail a REST execute does.
///
/// The session WS handler verifies the session exists at connect and then hands
/// the command to the executor directly, bypassing `execute_in_session` — the
/// only place session state is touched. So this path used to leave the session
/// looking idle for the whole command, never advance `execution_count`, and let
/// `idle_seconds` grow while a build was running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_command_over_a_session_websocket_marks_the_session_running() {
    let addr = spawn_server().await;
    let base = format!("http://{}/api/v1", addr);
    let client = reqwest_lite::Client;

    let created = client
        .post_json(&format!("{base}/sessions"), "{}")
        .await
        .expect("create session");
    let id = created["session_id"].as_u64().expect("session_id");

    let (mut ws, _resp) =
        tokio_tungstenite::connect_async(&format!("ws://{}/api/v1/sessions/{}/ws", addr, id))
            .await
            .expect("WebSocket connect failed");

    // Slow *and* talkative: the wait below takes the first output frame as
    // proof the command is under way, so a command that is merely slow never
    // satisfies it. `sleep 2` alone is silent, and this timed out on every
    // Unix — unnoticed until the branch first ran outside Windows, where
    // `ping` happens to print as it goes.
    let slow = if cfg!(windows) {
        "ping -n 4 127.0.0.1"
    } else {
        "echo started; sleep 2"
    };
    ws.send(Message::text(format!(
        r#"{{"type":"execute","command":"{slow}"}}"#
    )))
    .await
    .expect("send failed");

    // Wait for the first output frame: proof the command is under way, without
    // racing a fixed sleep against process startup.
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(msg) = ws.next().await {
            if let Ok(Message::Text(t)) = msg {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "output" {
                    return;
                }
            }
        }
        panic!("no output frame before the socket closed");
    })
    .await
    .expect("timed out waiting for the first output frame");

    let status = client
        .get_json(&format!("{base}/sessions/{id}"))
        .await
        .expect("session status");

    assert_eq!(
        status["running"], true,
        "a session streaming a command over WS reported {status}"
    );

    let final_status = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(msg) = ws.next().await {
            if let Ok(Message::Text(t)) = msg {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "result" {
                    break;
                }
            }
        }
        client.get_json(&format!("{base}/sessions/{id}")).await
    })
    .await
    .expect("timed out waiting for the result frame")
    .expect("session status");

    assert_eq!(final_status["running"], false, "{final_status}");
    assert_eq!(
        final_status["execution_count"], 1,
        "a WS execute left no trace in the session's bookkeeping: {final_status}"
    );
}

/// A session leaves `Active` when its *command* ends, not when the consumer
/// gets round to reading the output.
///
/// The two used to be the same wait, and the second one is unbounded: a
/// consumer that stops reading parks the handler inside `sink.send`, so the
/// guard that marks the session busy could not drop even though the command had
/// already been killed at its deadline. Measured on 0.21.0 over both the direct
/// and relayed paths — a command that died at 5.005 s left its session reporting
/// `running: true` for 75 seconds, ending at the instant the consumer resumed
/// rather than at any deadline. The idle sweep skips `Active` sessions on the
/// stated grounds that a command's deadline bounds them, so such a session was
/// never reclaimed at all.
///
/// This test reads nothing until after it has watched the session go idle. It
/// asserts both directions: `running` must be observed **true** first, or a fix
/// that simply never marked the session busy would pass; and the result frame
/// must still arrive afterwards with `timed_out`, or a command that died some
/// other way would look the same. The 30 s ceiling is a hang detector, not a
/// measurement — the discriminating gap is against the command's own 2 s
/// deadline, and the command itself is unbounded so it cannot end early on a
/// slow machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_goes_idle_when_the_command_ends_not_when_the_consumer_resumes() {
    let addr = spawn_server().await;
    let base = format!("http://{}/api/v1", addr);
    let client = reqwest_lite::Client;

    let created = client
        .post_json(&format!("{base}/sessions"), "{}")
        .await
        .expect("create session");
    let id = created["session_id"].as_u64().expect("session_id");

    let (mut ws, _resp) =
        tokio_tungstenite::connect_async(&format!("ws://{}/api/v1/sessions/{}/ws", addr, id))
            .await
            .expect("WebSocket connect failed");

    // Endlessly talkative, and a shell builtin on both platforms: the point is
    // to fill the socket the consumer is not draining, and a test whose premise
    // is an interpreter starting measures the interpreter (cycle-110).
    let loud = if cfg!(windows) {
        "for /L %i in (1,1,100000000) do @echo pinning-the-session-with-output"
    } else {
        "while :; do echo pinning-the-session-with-output; done"
    };
    ws.send(Message::text(format!(
        r#"{{"type":"execute","command":"{loud}","timeout_secs":2}}"#
    )))
    .await
    .expect("send failed");

    let poll_running = |want: bool| {
        let base = base.clone();
        async move {
            let client = reqwest_lite::Client;
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let status = client
                        .get_json(&format!("{base}/sessions/{id}"))
                        .await
                        .expect("session status");
                    if status["running"] == want {
                        return status;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
        }
    };

    poll_running(true)
        .await
        .expect("the session never reported `running: true` — nothing marked it busy");

    // Still not a single frame read from `ws`.
    let idle = poll_running(false).await.expect(
        "the session stayed `running: true` after its command's deadline, with the consumer \
         not reading — the busy guard is spanning delivery again",
    );
    assert_eq!(idle["running"], false, "{idle}");

    // Only now does the consumer come back. Delivery must still complete, and
    // the result must say the command was killed by its own deadline.
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = ws.next().await {
            if let Ok(Message::Text(t)) = msg {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "result" {
                    return v;
                }
            }
        }
        panic!("the socket closed without a result frame");
    })
    .await
    .expect("timed out waiting for the result frame after the consumer resumed");

    assert_eq!(
        result["timed_out"], true,
        "the command should have been killed by its own deadline: {result}"
    );
}

/// Minimal HTTP helper — this suite has no HTTP client dependency and needs
/// only two verbs against a loopback address.
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
