//! REST API handlers.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use super::types::{
    CreateSessionRequest, CreateSessionResponse, ErrorResponse, ExecuteCommandRequest,
    ExecuteCommandResponse, ListSessionsResponse, SessionStatusResponse, SessionSummary,
};
use crate::execution::{Command, CommandExecutor};
use crate::session::{SessionConfig, SessionId, SessionState, SessionStore};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<SessionStore>,
    pub executor: Arc<CommandExecutor>,
}

impl AppState {
    pub fn new() -> Self {
        let store = Arc::new(SessionStore::new());
        let executor = Arc::new(CommandExecutor::new(Arc::clone(&store)));
        Self { store, executor }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check endpoint.
pub async fn health() -> &'static str {
    "OK"
}

/// API information endpoint.
pub async fn api_info() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "shell-tunnel",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running"
    }))
}

/// List all sessions.
pub async fn list_sessions(
    State(state): State<AppState>,
) -> Result<Json<ListSessionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ids = state.store.list_ids().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::internal_error(e.to_string())),
        )
    })?;

    let mut sessions = Vec::with_capacity(ids.len());
    for id in ids {
        if let Ok(Some(session)) = state.store.get(&id) {
            sessions.push(SessionSummary {
                session_id: session.id.as_u64(),
                state: format!("{:?}", session.state),
                idle_seconds: session.idle_duration().as_secs_f64(),
            });
        }
    }

    Ok(Json(ListSessionsResponse {
        count: sessions.len(),
        sessions,
    }))
}

/// Create a new session.
pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<CreateSessionResponse>), (StatusCode, Json<ErrorResponse>)> {
    let config = SessionConfig {
        shell: req.shell,
        working_dir: req.working_dir,
        env: req.env,
    };

    let session_id = state.store.create(config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::internal_error(e.to_string())),
        )
    })?;

    // Transition to Idle state (ready for commands)
    state
        .store
        .update(&session_id, |s| {
            let _ = s.state.transition_to(SessionState::Idle);
        })
        .ok();

    Ok((
        StatusCode::CREATED,
        Json(CreateSessionResponse::new(session_id)),
    ))
}

/// Get session status.
pub async fn get_session(
    State(state): State<AppState>,
    Path(session_id): Path<u64>,
) -> Result<Json<SessionStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let id = SessionId::from_raw(session_id);

    let session = state
        .store
        .get(&id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::internal_error(e.to_string())),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse::session_not_found(&session_id.to_string())),
            )
        })?;

    Ok(Json(SessionStatusResponse::from_session(&session)))
}

/// Delete a session.
pub async fn delete_session(
    State(state): State<AppState>,
    Path(session_id): Path<u64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let id = SessionId::from_raw(session_id);

    // First mark as terminated
    state
        .store
        .update(&id, |s| {
            let _ = s.state.transition_to(SessionState::Terminated);
        })
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse::session_not_found(&session_id.to_string())),
            )
        })?;

    // Then remove from store
    state.store.remove(&id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::internal_error(e.to_string())),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Execute a command in a session.
pub async fn execute_command(
    State(state): State<AppState>,
    Path(session_id): Path<u64>,
    Json(req): Json<ExecuteCommandRequest>,
) -> Result<Json<ExecuteCommandResponse>, (StatusCode, Json<ErrorResponse>)> {
    let id = SessionId::from_raw(session_id);

    // Verify session exists and is in valid state
    let session = state
        .store
        .get(&id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::internal_error(e.to_string())),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse::session_not_found(&session_id.to_string())),
            )
        })?;

    if !session.state.can_execute() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse::invalid_state(session.state)),
        ));
    }

    // Build command
    let mut cmd = Command::new(&req.command);
    if let Some(dir) = &req.working_dir {
        cmd = cmd.working_dir(PathBuf::from(dir));
    }
    if let Some(timeout) = req.timeout() {
        cmd = cmd.timeout(timeout);
    }
    for (key, value) in &req.env {
        cmd = cmd.env(key, value);
    }

    // Execute
    let result = state.executor.execute_in_session(&id, &cmd).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::internal_error(e.to_string())),
        )
    })?;

    // Update session context
    state
        .store
        .update(&id, |s| {
            s.context.record_execution(&req.command, result.exit_code);
        })
        .ok();

    Ok(Json(ExecuteCommandResponse::from_result(&result)))
}

/// Execute a command without session (one-shot).
pub async fn execute_oneshot(
    State(state): State<AppState>,
    Json(req): Json<ExecuteCommandRequest>,
) -> Result<Json<ExecuteCommandResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Build command
    let mut cmd = Command::new(&req.command);
    if let Some(dir) = &req.working_dir {
        cmd = cmd.working_dir(PathBuf::from(dir));
    }
    if let Some(timeout) = req.timeout() {
        cmd = cmd.timeout(timeout);
    }
    for (key, value) in &req.env {
        cmd = cmd.env(key, value);
    }

    // Execute directly without session
    let result = state.executor.execute_sync(&cmd).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::internal_error(e.to_string())),
        )
    })?;

    Ok(Json(ExecuteCommandResponse::from_result(&result)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_new() {
        let state = AppState::new();
        assert_eq!(state.store.count(), 0);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let response = health().await;
        assert_eq!(response, "OK");
    }

    #[tokio::test]
    async fn test_api_info_endpoint() {
        let response = api_info().await;
        let json = response.0;
        assert_eq!(json["name"], "shell-tunnel");
        assert_eq!(json["status"], "running");
    }
}
