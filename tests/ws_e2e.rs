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
