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
use super::types::WsMessage;
use crate::execution::Command;
use crate::session::SessionId;

/// WebSocket upgrade handler.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(session_id): Path<u64>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state, session_id))
}

/// Handle WebSocket connection.
async fn handle_socket(socket: WebSocket, state: AppState, session_id: u64) {
    let id = SessionId::from_raw(session_id);

    // Verify session exists
    if state.store.get(&id).ok().flatten().is_none() {
        let (mut sink, _) = socket.split();
        let err = WsMessage::Error {
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
        let ws_msg: WsMessage = match serde_json::from_str(&msg) {
            Ok(m) => m,
            Err(e) => {
                let err = WsMessage::Error {
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
            WsMessage::Execute {
                command,
                timeout_secs,
            } => {
                // Build command
                let mut cmd = Command::new(&command);
                if let Some(secs) = timeout_secs {
                    cmd = cmd.timeout(Duration::from_secs(secs));
                }

                // Execute with streaming
                match state.executor.execute_async(&cmd).await {
                    Ok((mut rx, handle)) => {
                        // Stream output chunks
                        while let Some(chunk) = rx.recv().await {
                            let output = WsMessage::Output {
                                data: String::from_utf8_lossy(&chunk.raw).to_string(),
                                is_final: false,
                            };
                            if let Ok(json) = serde_json::to_string(&output) {
                                if sink.send(Message::Text(json.into())).await.is_err() {
                                    break;
                                }
                            }
                        }

                        // Wait for completion and send result
                        match handle.await {
                            Ok(Ok(result)) => {
                                // Update session context
                                state
                                    .store
                                    .update(&id, |s| {
                                        s.context.record_execution(&command, result.exit_code);
                                    })
                                    .ok();

                                let result_msg = WsMessage::Result {
                                    success: result
                                        .exit_code
                                        .map(|c| c == 0)
                                        .unwrap_or(false)
                                        && !result.timed_out,
                                    exit_code: result.exit_code,
                                    duration_ms: result.duration.as_millis() as u64,
                                    timed_out: result.timed_out,
                                };
                                if let Ok(json) = serde_json::to_string(&result_msg) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                            Ok(Err(e)) => {
                                let err = WsMessage::Error {
                                    code: "EXECUTION_ERROR".to_string(),
                                    message: e.to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&err) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                            Err(e) => {
                                let err = WsMessage::Error {
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
                        let err = WsMessage::Error {
                            code: "EXECUTION_ERROR".to_string(),
                            message: e.to_string(),
                        };
                        if let Ok(json) = serde_json::to_string(&err) {
                            let _ = sink.send(Message::Text(json.into())).await;
                        }
                    }
                }
            }
            WsMessage::Ping => {
                let pong = WsMessage::Pong;
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
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_oneshot_socket(socket, state))
}

/// Handle one-shot WebSocket connection.
async fn handle_oneshot_socket(socket: WebSocket, state: AppState) {
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

        let ws_msg: WsMessage = match serde_json::from_str(&msg) {
            Ok(m) => m,
            Err(e) => {
                let err = WsMessage::Error {
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
            WsMessage::Execute {
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
                            let output = WsMessage::Output {
                                data: String::from_utf8_lossy(&chunk.raw).to_string(),
                                is_final: false,
                            };
                            if let Ok(json) = serde_json::to_string(&output) {
                                if sink.send(Message::Text(json.into())).await.is_err() {
                                    break;
                                }
                            }
                        }

                        match handle.await {
                            Ok(Ok(result)) => {
                                let result_msg = WsMessage::Result {
                                    success: result
                                        .exit_code
                                        .map(|c| c == 0)
                                        .unwrap_or(false)
                                        && !result.timed_out,
                                    exit_code: result.exit_code,
                                    duration_ms: result.duration.as_millis() as u64,
                                    timed_out: result.timed_out,
                                };
                                if let Ok(json) = serde_json::to_string(&result_msg) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                            Ok(Err(e)) => {
                                let err = WsMessage::Error {
                                    code: "EXECUTION_ERROR".to_string(),
                                    message: e.to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&err) {
                                    let _ = sink.send(Message::Text(json.into())).await;
                                }
                            }
                            Err(e) => {
                                let err = WsMessage::Error {
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
                        let err = WsMessage::Error {
                            code: "EXECUTION_ERROR".to_string(),
                            message: e.to_string(),
                        };
                        if let Ok(json) = serde_json::to_string(&err) {
                            let _ = sink.send(Message::Text(json.into())).await;
                        }
                    }
                }
            }
            WsMessage::Ping => {
                let pong = WsMessage::Pong;
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
        let msg: WsMessage = serde_json::from_str(json).unwrap();
        match msg {
            WsMessage::Execute { command, .. } => assert_eq!(command, "echo hello"),
            _ => panic!("Expected Execute message"),
        }
    }

    #[test]
    fn test_ws_message_ping_parse() {
        let json = r#"{"type": "ping"}"#;
        let msg: WsMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, WsMessage::Ping));
    }
}
