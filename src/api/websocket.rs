//! WebSocket handler for real-time command streaming.

use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};

use super::handlers::AppState;
use super::types::{WsClientMessage, WsServerMessage};
use crate::execution::Command;
use crate::session::{BusySession, SessionId};

/// WebSocket upgrade handler.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(session_id): Path<u64>,
    identity: Option<axum::Extension<crate::audit::Identity>>,
) -> impl IntoResponse {
    // Taken here because extensions belong to the upgrade request, not to the
    // socket that outlives it.
    let identity = identity.map(|axum::Extension(id)| id);
    ws.on_upgrade(move |socket| handle_socket(socket, state, session_id, identity))
}

/// Handle WebSocket connection.
async fn handle_socket(
    socket: WebSocket,
    state: AppState,
    session_id: u64,
    identity: Option<crate::audit::Identity>,
) {
    let id = SessionId::from_raw(session_id);

    // Verify session exists
    if state.store.get(&id).ok().flatten().is_none() {
        let (mut sink, _) = socket.split();
        let err = WsServerMessage::Error {
            code: "SESSION_NOT_FOUND".to_string(),
            message: format!("Session {} not found", session_id),
        };
        if let Ok(json) = serde_json::to_string(&err) {
            let _ = sink.send(Message::Text(json.into())).await;
        }
        return;
    }

    let (mut sink, mut stream) = socket.split();

    // Process incoming messages
    while let Some(msg) = stream.next().await {
        let msg = match msg {
            Ok(Message::Text(text)) => text.to_string(),
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(data)) => {
                let _ = sink.send(Message::Pong(data)).await;
                continue;
            }
            Ok(_) => continue,
            Err(_) => break,
        };

        // Parse WebSocket message
        let ws_msg: WsClientMessage = match serde_json::from_str(&msg) {
            Ok(m) => m,
            Err(e) => {
                let err = WsServerMessage::Error {
                    code: "PARSE_ERROR".to_string(),
                    message: e.to_string(),
                };
                if let Ok(json) = serde_json::to_string(&err) {
                    let _ = sink.send(Message::Text(json.into())).await;
                }
                continue;
            }
        };

        match ws_msg {
            WsClientMessage::Execute {
                command,
                timeout_secs,
            } => {
                // Build command
                let mut cmd = Command::new(&command);
                if let Some(secs) = timeout_secs {
                    cmd = cmd.timeout(Duration::from_secs(secs));
                }

                // Busy for the whole command, exactly as the REST path is. This
                // handler streams through `execute_async` rather than
                // `execute_in_session`, so nothing else here touches the session
                // — without it a command driven over the socket left the session
                // reporting `running: false` and its idle clock running while a
                // build was under way. The guard also covers the ways out that
                // no branch below expresses.
                //
                // Held in an `Option` so the delivery loop can put it down the
                // moment the command itself is over: see `while_running`.
                let mut busy = BusySession::begin(&state.store, &id).ok();

                // Execute with streaming
                match state.executor.execute_async(&cmd).await {
                    Ok((mut rx, mut handle)) => {
                        // The command's own outcome, if it finished while output
                        // was still being delivered — which is the normal case
                        // for a consumer that reads slowly or not at all.
                        let mut finished = None;

                        // Stream output chunks
                        while let Some(chunk) = rx.recv().await {
                            let output = WsServerMessage::Output {
                                data: String::from_utf8_lossy(&chunk.raw).to_string(),
                                is_final: false,
                            };
                            if let Ok(json) = serde_json::to_string(&output) {
                                let sent = while_running(
                                    sink.send(Message::Text(json.into())),
                                    &mut handle,
                                    &mut finished,
                                    &mut busy,
                                )
                                .await;
                                if sent.is_err() {
                                    break;
                                }
                            }
                        }

                        // Let the command go once nobody is reading it. Holding
                        // the receiver across the await below would stall the
                        // loop that enforces the timeout — see `execute_async`.
                        drop(rx);

                        // Wait for completion and send result. `while_running`
                        // has usually taken it already — awaiting a handle it
                        // has consumed would panic, which is why it is stored
                        // rather than re-awaited.
                        let outcome = match finished {
                            Some(res) => res,
                            None => handle.await,
                        };
                        match outcome {
                            Ok(Ok(result)) => {
                                state
                                    .audit
                                    .record_async(
                                        crate::audit::AuditEvent::new("execute")
                                            .with_identity(identity.clone())
                                            .with_route("WS /api/v1/sessions/{id}/ws")
                                            .with_command(&command)
                                            .with_session(session_id)
                                            .with_outcome(
                                                result.exit_code,
                                                result.timed_out,
                                                result.duration.as_millis() as u64,
                                            ),
                                    )
                                    .await;

                                // Update session context
                                state
                                    .store
                                    .update(&id, |s| {
                                        s.context.record_execution(&command, result.exit_code);
                                    })
                                    .ok();

                                let result_msg = WsServerMessage::Result {
                                    success: result.exit_code.map(|c| c == 0).unwrap_or(false)
                                        && !result.timed_out,
                                    exit_code: result.exit_code,
                                    duration_ms: result.duration.as_millis() as u64,
                                    timed_out: result.timed_out,
                                    total_bytes: result.total_bytes,
                                };
                                if let Ok(json) = serde_json::to_string(&result_msg) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                            Ok(Err(e)) => {
                                let err = WsServerMessage::Error {
                                    code: "EXECUTION_ERROR".to_string(),
                                    message: e.to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&err) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                            Err(e) => {
                                let err = WsServerMessage::Error {
                                    code: "TASK_ERROR".to_string(),
                                    message: e.to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&err) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let err = WsServerMessage::Error {
                            code: "EXECUTION_ERROR".to_string(),
                            message: e.to_string(),
                        };
                        if let Ok(json) = serde_json::to_string(&err) {
                            let _ = sink.send(Message::Text(json.into())).await;
                        }
                    }
                }
                // `busy` drops here if `while_running` did not already put it
                // down: idle again on every way out, including the ones that
                // never reached the executor and the ones no branch here
                // expresses.
            }
            WsClientMessage::Ping => {
                let pong = WsServerMessage::Pong;
                if let Ok(json) = serde_json::to_string(&pong) {
                    let _ = sink.send(Message::Text(json.into())).await;
                }
            }
            _ => {
                // Ignore other message types from client
            }
        }
    }
}

/// The task running one streamed command, as `execute_async` hands it over.
type CommandHandle = tokio::task::JoinHandle<crate::Result<crate::execution::ExecutionResult>>;

/// What that task produced: the command's result, or the join error if the task
/// itself came apart.
type CommandOutcome =
    std::result::Result<crate::Result<crate::execution::ExecutionResult>, tokio::task::JoinError>;

/// Await `fut`, releasing the session's busy guard the moment the *command*
/// ends rather than when delivery does.
///
/// The two are not the same wait, and the gap between them is unbounded. A
/// consumer that stops reading its socket parks `sink.send` for as long as it
/// likes; the command still dies at its own deadline (`forward_chunk` stops
/// waiting on a stalled receiver there), but the handler is still inside a send
/// and cannot reach the end of the arm where the guard would drop. Measured on
/// 0.21.0: a command with `timeout_secs: 5` died at 5.005 s and its session went
/// on reporting `running: true` for **75 seconds**, ending not at any deadline
/// but at the instant the consumer resumed reading. A silent command released at
/// 5.3 s, which is what says the delay belongs to undelivered output rather than
/// to the deadline. The direct and relayed paths behaved identically.
///
/// That mattered beyond the field's own honesty: the idle sweep skips sessions
/// in [`SessionState::Active`](crate::session::SessionState::Active), on the
/// stated grounds that a command's deadline bounds how long that can last. A
/// session pinned by an unread socket is therefore never swept at all.
///
/// `fut` is pinned once and re-polled rather than re-created, so a send that was
/// half-written when the command finished is resumed, not cancelled — cancelling
/// mid-frame would corrupt the stream. The handle branch is disabled after it
/// fires, since polling a completed `JoinHandle` panics.
///
/// This bounds the *session*, not the socket: a consumer that never reads again
/// still holds the connection, which is the separate open item (there is no
/// WebSocket idle timeout).
async fn while_running<F: std::future::Future>(
    fut: F,
    handle: &mut CommandHandle,
    finished: &mut Option<CommandOutcome>,
    busy: &mut Option<BusySession>,
) -> F::Output {
    tokio::pin!(fut);
    loop {
        if finished.is_some() {
            return fut.await;
        }
        tokio::select! {
            out = &mut fut => return out,
            res = &mut *handle => {
                *finished = Some(res);
                // Dropping the guard returns the session to idle and restarts
                // its clock from the command's end, which is the instant the
                // clock is meant to measure from.
                *busy = None;
            }
        }
    }
}

/// One-shot WebSocket execution (no session required).
pub async fn ws_oneshot_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    identity: Option<axum::Extension<crate::audit::Identity>>,
) -> impl IntoResponse {
    let identity = identity.map(|axum::Extension(id)| id);
    ws.on_upgrade(move |socket| handle_oneshot_socket(socket, state, identity))
}

/// Handle one-shot WebSocket connection.
async fn handle_oneshot_socket(
    socket: WebSocket,
    state: AppState,
    identity: Option<crate::audit::Identity>,
) {
    let (mut sink, mut stream) = socket.split();

    while let Some(msg) = stream.next().await {
        let msg = match msg {
            Ok(Message::Text(text)) => text.to_string(),
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(data)) => {
                let _ = sink.send(Message::Pong(data)).await;
                continue;
            }
            Ok(_) => continue,
            Err(_) => break,
        };

        let ws_msg: WsClientMessage = match serde_json::from_str(&msg) {
            Ok(m) => m,
            Err(e) => {
                let err = WsServerMessage::Error {
                    code: "PARSE_ERROR".to_string(),
                    message: e.to_string(),
                };
                if let Ok(json) = serde_json::to_string(&err) {
                    let _ = sink.send(Message::Text(json.into())).await;
                }
                continue;
            }
        };

        match ws_msg {
            WsClientMessage::Execute {
                command,
                timeout_secs,
            } => {
                let mut cmd = Command::new(&command);
                if let Some(secs) = timeout_secs {
                    cmd = cmd.timeout(Duration::from_secs(secs));
                }

                match state.executor.execute_async(&cmd).await {
                    Ok((mut rx, handle)) => {
                        while let Some(chunk) = rx.recv().await {
                            let output = WsServerMessage::Output {
                                data: String::from_utf8_lossy(&chunk.raw).to_string(),
                                is_final: false,
                            };
                            if let Ok(json) = serde_json::to_string(&output) {
                                if sink.send(Message::Text(json.into())).await.is_err() {
                                    break;
                                }
                            }
                        }

                        // Nobody is reading any more: release the command so its
                        // timeout can still be enforced (see `execute_async`).
                        // This path has no session, so a stalled command here
                        // showed up only as a child that never died.
                        drop(rx);

                        match handle.await {
                            Ok(Ok(result)) => {
                                state
                                    .audit
                                    .record_async(
                                        crate::audit::AuditEvent::new("execute")
                                            .with_identity(identity.clone())
                                            .with_route("WS /api/v1/ws")
                                            .with_command(&command)
                                            .with_outcome(
                                                result.exit_code,
                                                result.timed_out,
                                                result.duration.as_millis() as u64,
                                            ),
                                    )
                                    .await;

                                let result_msg = WsServerMessage::Result {
                                    success: result.exit_code.map(|c| c == 0).unwrap_or(false)
                                        && !result.timed_out,
                                    exit_code: result.exit_code,
                                    duration_ms: result.duration.as_millis() as u64,
                                    timed_out: result.timed_out,
                                    total_bytes: result.total_bytes,
                                };
                                if let Ok(json) = serde_json::to_string(&result_msg) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                            Ok(Err(e)) => {
                                let err = WsServerMessage::Error {
                                    code: "EXECUTION_ERROR".to_string(),
                                    message: e.to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&err) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                            Err(e) => {
                                let err = WsServerMessage::Error {
                                    code: "TASK_ERROR".to_string(),
                                    message: e.to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&err) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let err = WsServerMessage::Error {
                            code: "EXECUTION_ERROR".to_string(),
                            message: e.to_string(),
                        };
                        if let Ok(json) = serde_json::to_string(&err) {
                            let _ = sink.send(Message::Text(json.into())).await;
                        }
                    }
                }
            }
            WsClientMessage::Ping => {
                let pong = WsServerMessage::Pong;
                if let Ok(json) = serde_json::to_string(&pong) {
                    let _ = sink.send(Message::Text(json.into())).await;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_message_execute_parse() {
        let json = r#"{"type": "execute", "command": "echo hello"}"#;
        let msg: WsClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            WsClientMessage::Execute { command, .. } => assert_eq!(command, "echo hello"),
            _ => panic!("Expected Execute message"),
        }
    }

    #[test]
    fn test_ws_message_ping_parse() {
        let json = r#"{"type": "ping"}"#;
        let msg: WsClientMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, WsClientMessage::Ping));
    }
}
