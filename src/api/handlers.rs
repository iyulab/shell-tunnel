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
    /// Where execution events are recorded; disabled unless configured.
    pub audit: Arc<crate::audit::AuditSink>,
    /// The directory the filesystem API may touch.
    ///
    /// `None` means the API is off. Since 0.12.0 the shipped binary no longer
    /// defaults to this: it always installs `FsRoot::machine_wide()` unless
    /// `--fs-root` narrows it, on the reasoning that a token holding `fs.*`
    /// already needs `exec` to matter, and `exec` can already reach anything
    /// this process can (`src/main.rs`). `None` now only occurs when a
    /// library consumer builds an `AppState` directly instead of going
    /// through the binary's startup path.
    pub fs: Option<Arc<crate::fs::FsRoot>>,
    /// In-flight uploads. Always present; useless until `fs` is set.
    pub uploads: Arc<crate::fs::UploadStore>,
}

impl AppState {
    pub fn new() -> Self {
        let store = Arc::new(SessionStore::new());
        let executor = Arc::new(CommandExecutor::new(Arc::clone(&store)));
        Self {
            store,
            executor,
            audit: Arc::new(crate::audit::AuditSink::Disabled),
            fs: None,
            uploads: Arc::new(crate::fs::UploadStore::new(crate::fs::DEFAULT_CHUNK_SIZE)),
        }
    }

    /// Record execution events to `sink`.
    pub fn with_audit(mut self, sink: Arc<crate::audit::AuditSink>) -> Self {
        self.audit = sink;
        self
    }

    /// Enable the filesystem API, confined to `root`.
    pub fn with_fs_root(mut self, root: crate::fs::FsRoot) -> Self {
        self.fs = Some(Arc::new(root));
        self
    }

    /// Advertise a different chunk size to upload clients.
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.uploads = Arc::new(crate::fs::UploadStore::new(chunk_size));
        self
    }
}

/// Build the execution event for a finished command.
///
/// Written from the handler rather than from middleware because only here are
/// the command and its outcome both in hand — an entry saying a request reached
/// `/execute` would say almost nothing about what ran.
fn execution_event(
    identity: Option<crate::audit::Identity>,
    route: &str,
    command: &str,
    session_id: Option<u64>,
    result: &crate::execution::ExecutionResult,
) -> crate::audit::AuditEvent {
    let mut event = crate::audit::AuditEvent::new("execute")
        .with_identity(identity)
        .with_route(route)
        .with_command(command)
        .with_outcome(
            result.exit_code,
            result.timed_out,
            result.duration.as_millis() as u64,
        )
        .with_truncated_output(result.truncated, result.total_bytes);
    if let Some(id) = session_id {
        event = event.with_session(id);
    }
    event
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
    identity: Option<axum::Extension<crate::audit::Identity>>,
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
    if let Some(bytes) = req.max_output_bytes {
        cmd = cmd.max_output_bytes(bytes);
    }
    for (key, value) in &req.env {
        cmd = cmd.env(key, value);
    }

    // Execute
    let result = state
        .executor
        .execute_in_session(&id, &cmd)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::internal_error(e.to_string())),
            )
        })?;

    state
        .audit
        .record_async(execution_event(
            identity.map(|axum::Extension(id)| id),
            "POST /api/v1/sessions/{id}/execute",
            &req.command,
            Some(session_id),
            &result,
        ))
        .await;

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
    identity: Option<axum::Extension<crate::audit::Identity>>,
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
    if let Some(bytes) = req.max_output_bytes {
        cmd = cmd.max_output_bytes(bytes);
    }
    for (key, value) in &req.env {
        cmd = cmd.env(key, value);
    }

    // Execute directly without session (off the async runtime workers)
    let result = state.executor.execute(&cmd).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::internal_error(e.to_string())),
        )
    })?;

    state
        .audit
        .record_async(execution_event(
            identity.map(|axum::Extension(id)| id),
            "POST /api/v1/execute",
            &req.command,
            None,
            &result,
        ))
        .await;

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
