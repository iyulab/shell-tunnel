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
                let _busy = BusySession::begin(&state.store, &id).ok();

                // Execute with streaming
                match state.executor.execute_async(&cmd).await {
                    Ok((mut rx, handle)) => {
                        // Stream output chunks
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

                        // Let the command go once nobody is reading it. Holding
                        // the receiver across the await below would stall the
                        // loop that enforces the timeout — see `execute_async`.
                        drop(rx);

                        // Wait for completion and send result
                        match handle.await {
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
                // `_busy` drops here: idle again on every way out, including the
                // ones that never reached the executor and the ones no branch
                // here expresses.
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
