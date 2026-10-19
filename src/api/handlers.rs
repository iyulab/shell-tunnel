//! REST API handlers.

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
use crate::execution::CommandExecutor;
use crate::session::{SessionId, SessionState, SessionStore};

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
    /// The named actions this server runs. Empty unless `--actions` gave some.
    pub actions: Arc<crate::actions::ActionSet>,
    /// The services this server exposes at `/x/<name>/…`. Empty unless
    /// `--expose` gave some.
    pub exposes: Arc<crate::expose::ExposeSet>,
    /// What is in flight, and the latch an update closes the door with.
    pub activity: Arc<super::activity::Activity>,
    /// Background processes (`/api/v1/processes`).
    pub processes: crate::execution::processes::ProcessTable,
    /// The relay this server last enrolled with, when it runs as a relay
    /// device. Written by the relay client's attach events, read by
    /// `GET /api/v1`.
    pub relay: Arc<std::sync::RwLock<Option<RelayAttachment>>>,
}

/// What a device knows about the relay it attached to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RelayAttachment {
    /// The version the relay reported at enrolment; `None` from a relay older
    /// than 0.28.0, which does not report one.
    pub version: Option<String>,
    /// When this device last enrolled with it, in Unix milliseconds.
    pub enrolled_at_ms: u64,
}

impl AppState {
    /// Record an enrolment with a relay that reported `version`.
    pub fn record_relay_enrolment(&self, version: Option<String>) {
        let enrolled_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut relay) = self.relay.write() {
            *relay = Some(RelayAttachment {
                version,
                enrolled_at_ms,
            });
        }
    }
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
            uploads: Arc::new(crate::fs::UploadStore::new(
                crate::fs::DEFAULT_CHUNK_SIZE,
                crate::fs::DEFAULT_CHUNK_SIZE,
            )),
            actions: Arc::new(crate::actions::ActionSet::default()),
            exposes: Arc::new(crate::expose::ExposeSet::default()),
            activity: Arc::new(super::activity::Activity::new()),
            processes: crate::execution::processes::ProcessTable::new(),
            relay: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Serve these named actions.
    pub fn with_actions(mut self, actions: crate::actions::ActionSet) -> Self {
        self.actions = Arc::new(actions);
        self
    }

    /// Expose these services at `/x/<name>/…`.
    pub fn with_exposes(mut self, exposes: crate::expose::ExposeSet) -> Self {
        self.exposes = Arc::new(exposes);
        self
    }

    /// Record execution events to `sink`.
    pub fn with_audit(mut self, sink: Arc<crate::audit::AuditSink>) -> Self {
        self.processes.set_audit(Arc::clone(&sink));
        self.audit = sink;
        self
    }

    /// Kill whatever a command leaves running when the command ends.
    ///
    /// Rebuilds the executor, so call it before handing the state out. Off
    /// unless asked for — see [`CommandExecutor::kill_orphans`].
    pub fn with_kill_orphans(mut self, kill: bool) -> Self {
        self.executor = Arc::new(CommandExecutor::new(Arc::clone(&self.store)).kill_orphans(kill));
        self.processes.set_kill_orphans(kill);
        self
    }

    /// Enable the filesystem API, confined to `root`.
    pub fn with_fs_root(mut self, root: crate::fs::FsRoot) -> Self {
        self.fs = Some(Arc::new(root));
        self
    }

    /// Advertise a different chunk size to upload clients — `direct_chunk_size`
    /// for a request that reached this device directly, `relayed_chunk_size`
    /// for one that arrived through a relay (see `fs::UploadStore::chunk_size`).
    pub fn with_chunk_size(mut self, direct_chunk_size: usize, relayed_chunk_size: usize) -> Self {
        self.uploads = Arc::new(crate::fs::UploadStore::new(
            direct_chunk_size,
            relayed_chunk_size,
        ));
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
    // The size of the input, never its content: what a command is fed may be a
    // secret where the command line that reads it is not.
    if let Some(written) = result.stdin_written {
        event = event.with_bytes(written);
    }
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
///
/// `relay` is present on a relay device once it has enrolled: the relay's
/// version is otherwise unobservable to a caller, since the relay publishes it
/// to nobody but the devices it enrols — and a fix split between a relay and a
/// device works only when both halves are at its version.
pub async fn api_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut info = serde_json::json!({
        "name": "shell-tunnel",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running"
    });
    if let Some(relay) = state.relay.read().ok().and_then(|r| r.clone()) {
        info["relay"] = serde_json::json!(relay);
    }
    Json(info)
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
                running: session.state == SessionState::Active,
                last_exit_code: session.context.last_exit_code(),
                execution_count: session.context.execution_count(),
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
/// The body is optional because the request carries no fields: `POST /sessions`
/// with nothing at all is the natural call. A body that *is* sent still has to
/// parse, so a caller who passes the old `shell`/`working_dir`/`env` is told so
/// rather than having them dropped.
pub async fn create_session(
    State(state): State<AppState>,
    _req: Option<Json<CreateSessionRequest>>,
) -> Result<(StatusCode, Json<CreateSessionResponse>), (StatusCode, Json<ErrorResponse>)> {
    let session_id = state.store.create().map_err(|e| {
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

    let cmd = req.to_command();

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
    let cmd = req.to_command();

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
        let response = api_info(State(AppState::new())).await;
        let json = response.0;
        assert_eq!(json["name"], "shell-tunnel");
        assert_eq!(json["status"], "running");
        assert!(json.get("relay").is_none(), "not a relay device: {json}");
    }

    #[tokio::test]
    async fn api_info_names_the_relay_a_device_enrolled_with() {
        let state = AppState::new();
        state.record_relay_enrolment(Some("0.30.0".into()));
        let json = api_info(State(state.clone())).await.0;
        assert_eq!(json["relay"]["version"], "0.30.0", "{json}");
        assert!(json["relay"]["enrolled_at_ms"].as_u64().unwrap() > 0);

        // A relay too old to report its version is still reported as one.
        state.record_relay_enrolment(None);
        let json = api_info(State(state)).await.0;
        assert!(json["relay"]["version"].is_null(), "{json}");
    }
}
