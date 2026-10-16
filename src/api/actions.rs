//! `GET /api/v1/actions` and `POST /api/v1/actions/{id}` — the named actions
//! a device's owner defined (`src/actions.rs`).
//!
//! Authorization for running one is decided before the handler, in the
//! capability middleware (`src/api/router.rs`), so a refusal is recorded by
//! the same layer as every other `403`. What is left here is what only the
//! definition can answer: whether the action exists, and whether the caller's
//! parameters are ones it accepts.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use super::handlers::AppState;
use super::types::{ErrorResponse, ExecuteCommandResponse};
use crate::actions::{capability_for, ActionInfo, ANY_ACTION};
use crate::audit::{AuditEvent, Identity};
use crate::security::CapabilitySet;

/// The route template, as the audit trail names it.
const RUN_ROUTE: &str = "POST /api/v1/actions/{id}";

/// The longest action id a refusal records. A defined id is at most 64
/// characters, so anything longer is a probe, and the trail should not carry
/// whatever the caller chose to send.
const MAX_AUDITED_ID: usize = 64;

/// Body of `GET /api/v1/actions`.
#[derive(Debug, Serialize)]
pub struct ListActionsResponse {
    /// The actions this caller may run, in id order.
    pub actions: Vec<ActionInfo>,
}

/// Body of `POST /api/v1/actions/{id}`. Optional: an action without
/// parameters can be run with no body at all.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunActionRequest {
    /// The action's parameters, by name.
    #[serde(default)]
    pub params: serde_json::Map<String, serde_json::Value>,
}

/// What running an action returns: the execution result, and which action.
#[derive(Debug, Serialize)]
pub struct RunActionResponse {
    /// The action that ran.
    pub action: String,
    /// How it went — the same fields `POST /api/v1/execute` answers with.
    #[serde(flatten)]
    pub result: ExecuteCommandResponse,
}

type Refusal = (StatusCode, Json<ErrorResponse>);

/// Whether `capabilities` may run the action `id`.
///
/// Two questions rather than one widened rule: `satisfies` is set membership
/// plus the `*` wildcard and nothing else, and teaching it that `action:*`
/// covers `action:<id>` would change the access-decision primitive for every
/// route to serve one.
pub fn may_run(capabilities: &CapabilitySet, id: &str) -> bool {
    capabilities.satisfies(&capability_for(id)) || capabilities.satisfies(ANY_ACTION)
}

/// List the actions this caller may run.
///
/// Filtered by the caller's token: the list answers "what can I do here", and
/// an action the token cannot run is not part of that answer. With
/// authentication off there is no token, and every action is listed.
pub async fn list_actions(
    State(state): State<AppState>,
    capabilities: Option<Extension<CapabilitySet>>,
) -> Json<ListActionsResponse> {
    let actions = state
        .actions
        .iter()
        .filter(|action| match &capabilities {
            Some(Extension(caps)) => may_run(caps, action.id()),
            None => true,
        })
        .map(|action| action.info())
        .collect();
    Json(ListActionsResponse { actions })
}

/// Run one action with the caller's parameters.
pub async fn run_action(
    State(state): State<AppState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<RunActionResponse>, Refusal> {
    let identity = identity.map(|Extension(identity)| identity);
    let refuse = |status: StatusCode, reason: String, error: ErrorResponse| {
        let state = state.clone();
        let identity = identity.clone();
        async move {
            state
                .audit
                .record_async(
                    AuditEvent::new("denied")
                        .with_identity(identity)
                        .with_route(RUN_ROUTE)
                        .with_denial(status.as_u16(), reason),
                )
                .await;
            (status, Json(error))
        }
    };

    let Some(action) = state.actions.get(&id) else {
        let shown: String = id.chars().take(MAX_AUDITED_ID).collect();
        return Err(refuse(
            StatusCode::NOT_FOUND,
            format!("unknown-action:{shown}"),
            ErrorResponse::new("ACTION_NOT_FOUND", format!("no action named '{shown}'")),
        )
        .await);
    };

    let request: RunActionRequest = if body.iter().all(u8::is_ascii_whitespace) {
        RunActionRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(e) => {
                return Err(refuse(
                    StatusCode::BAD_REQUEST,
                    "malformed-body".into(),
                    ErrorResponse::bad_request(format!("the body is not a valid request: {e}")),
                )
                .await)
            }
        }
    };

    let (argv, accepted) = match action.render(&request.params) {
        Ok(rendered) => rendered,
        Err(e) => {
            return Err(refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("invalid-param:{}", e.param),
                ErrorResponse::new("INVALID_PARAMS", e.to_string()).with_details(e.param),
            )
            .await)
        }
    };

    let command = action.command(argv);
    let result = state.executor.execute(&command).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::internal_error(e.to_string())),
        )
    })?;

    state
        .audit
        .record_async(
            AuditEvent::new("action")
                .with_identity(identity)
                .with_route(RUN_ROUTE)
                .with_action(action.id(), accepted)
                .with_command(command.invocation.display())
                .with_outcome(
                    result.exit_code,
                    result.timed_out,
                    result.duration.as_millis() as u64,
                )
                .with_truncated_output(result.truncated, result.total_bytes),
        )
        .await;

    Ok(Json(RunActionResponse {
        action: action.id().to_string(),
        result: ExecuteCommandResponse::from_result(&result),
    }))
}
