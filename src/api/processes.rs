//! `/api/v1/processes` — background processes started now and read later.
//!
//! The table and its watcher live in `execution::processes`; these handlers
//! only translate HTTP. Every route needs `exec`: starting a process is the
//! same power `execute` grants, and reading or ending one is no less.

use std::collections::HashMap;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use super::fs::error_response;
use super::handlers::AppState;
use crate::audit::Identity;
use crate::execution::processes::{ProcessError, Signal, StartRequest, StdinWrite, Stream};

type Caller = Option<axum::Extension<Identity>>;

/// Longest a read waits for output. Under the relay's per-request limit with
/// room to spare, and under the idle timeouts proxies commonly apply.
pub const MAX_WAIT_MS: u64 = 25_000;

/// Largest read, and the default.
pub const MAX_READ_BYTES: usize = 1024 * 1024;
const DEFAULT_READ_BYTES: usize = 64 * 1024;

fn refusal(error: ProcessError) -> Response {
    match error {
        ProcessError::NotFound => error_response(
            StatusCode::NOT_FOUND,
            "process-not-found",
            "no process with that id; it may have been deleted, or kept past its hour after exiting",
        ),
        ProcessError::TooMany => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too-many-processes",
            "the most processes this server keeps exist already; delete one that has exited",
        ),
        ProcessError::NotRunning => error_response(
            StatusCode::CONFLICT,
            "process-not-running",
            "the process has already exited",
        ),
        ProcessError::StdinUnavailable => error_response(
            StatusCode::CONFLICT,
            "stdin-unavailable",
            "stdin was not requested at start, or has been closed — by a caller or by the process",
        ),
        ProcessError::StdinBacklogFull => error_response(
            StatusCode::CONFLICT,
            "stdin-backlog-full",
            "more input is queued for this process than the server holds; wait for it to read what is queued (stdin_pending) and send again",
        ),
        ProcessError::SignalUnsupported => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "signal-unsupported",
            "this platform cannot deliver that signal; terminate or kill instead",
        ),
        ProcessError::Io(detail) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "process-failed",
            &format!("the operating system refused: {detail}"),
        ),
    }
}

/// Run a blocking table call off the async runtime.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ProcessError> + Send + 'static,
) -> Result<T, ProcessError> {
    tokio::task::spawn_blocking(work)
        .await
        .unwrap_or_else(|_| Err(ProcessError::Io("the operation panicked".into())))
}

/// Body of `POST /api/v1/processes`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartProcess {
    pub command: String,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Keep a pipe to the process's stdin for `POST …/stdin`. Without it the
    /// process reads an empty stdin.
    #[serde(default)]
    pub stdin: bool,
}

pub async fn start(
    State(state): State<AppState>,
    identity: Caller,
    Json(body): Json<StartProcess>,
) -> Response {
    let identity = identity.map(|axum::Extension(id)| id);
    let request = StartRequest {
        command: body.command,
        working_dir: body.working_dir,
        env: body.env.into_iter().collect(),
        stdin: body.stdin,
    };
    let table = state.processes.clone();
    match blocking(move || table.start(&request, identity)).await {
        Ok(info) => (StatusCode::CREATED, Json(info)).into_response(),
        Err(error) => refusal(error),
    }
}

pub async fn list(State(state): State<AppState>) -> Response {
    Json(serde_json::json!({ "processes": state.processes.list() })).into_response()
}

pub async fn get(State(state): State<AppState>, Path(id): Path<u64>) -> Response {
    match state.processes.info(id) {
        Ok(info) => Json(info).into_response(),
        Err(error) => refusal(error),
    }
}

/// Query of `GET /api/v1/processes/{id}/output`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputQuery {
    #[serde(default)]
    pub stream: StreamName,
    /// Offset to read from — `next` of the previous read, or 0.
    #[serde(default)]
    pub since: u64,
    /// Wait up to this long for output when there is none yet. Capped at
    /// [`MAX_WAIT_MS`]; 0 answers at once.
    #[serde(default)]
    pub wait_ms: u64,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum StreamName {
    #[default]
    Stdout,
    Stderr,
}

pub async fn output(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Query(query): Query<OutputQuery>,
) -> Response {
    let stream = match query.stream {
        StreamName::Stdout => Stream::Stdout,
        StreamName::Stderr => Stream::Stderr,
    };
    let max = query
        .max_bytes
        .unwrap_or(DEFAULT_READ_BYTES)
        .clamp(1, MAX_READ_BYTES);
    let wait = Duration::from_millis(query.wait_ms.min(MAX_WAIT_MS));
    let read = match state
        .processes
        .read_wait(id, stream, query.since, max, wait)
        .await
    {
        Ok(read) => read,
        Err(error) => return refusal(error),
    };

    // Text, cut at a character boundary: a multi-byte character split across
    // two reads would otherwise come back as two replacement characters. The
    // incomplete tail is left for the next read by moving `next` back — unless
    // the stream is over, when no more bytes can complete it.
    let mut consumed = read.data.len();
    if !read.complete {
        if let Err(e) = std::str::from_utf8(&read.data) {
            if e.error_len().is_none() {
                consumed = e.valid_up_to();
            }
        }
    }
    let text = String::from_utf8_lossy(&read.data[..consumed]).into_owned();
    let next = read.start + consumed as u64;
    let complete = read.complete && consumed == read.data.len();
    let info = state.processes.info(id).ok();
    Json(serde_json::json!({
        "stream": match stream { Stream::Stdout => "stdout", Stream::Stderr => "stderr" },
        "start": read.start,
        "next": next,
        "text": text,
        "complete": complete,
        "state": info.as_ref().map(|i| i.state),
        "exit_code": info.and_then(|i| i.exit_code),
    }))
    .into_response()
}

/// Query of `POST /api/v1/processes/{id}/stdin`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdinQuery {
    /// Close stdin after writing, so the process reads end-of-file.
    #[serde(default)]
    pub close: bool,
    /// How long to wait for the process to take the input, in milliseconds;
    /// at most [`MAX_STDIN_WAIT_MS`]. Omitted, the most.
    #[serde(default)]
    pub wait_ms: Option<u64>,
}

/// The longest a stdin write waits for the process to take its input — the
/// same bound the output long-poll has.
pub const MAX_STDIN_WAIT_MS: u64 = 25_000;

pub async fn stdin(
    State(state): State<AppState>,
    identity: Caller,
    Path(id): Path<u64>,
    Query(query): Query<StdinQuery>,
    body: axum::body::Bytes,
) -> Response {
    let identity = identity.map(|axum::Extension(id)| id);
    let wait = Duration::from_millis(
        query
            .wait_ms
            .unwrap_or(MAX_STDIN_WAIT_MS)
            .min(MAX_STDIN_WAIT_MS),
    );
    match state
        .processes
        .write_stdin(id, &body, query.close, identity, wait)
        .await
    {
        // All of it is in the pipe.
        Ok(StdinWrite { pending: 0 }) => StatusCode::NO_CONTENT.into_response(),
        // Queued, and still going in: the process has not read it all yet.
        Ok(StdinWrite { pending }) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "pending": pending })),
        )
            .into_response(),
        Err(error) => refusal(error),
    }
}

/// Body of `POST /api/v1/processes/{id}/signal`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalRequest {
    pub signal: SignalName,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum SignalName {
    Terminate,
    Kill,
    Interrupt,
}

pub async fn signal(
    State(state): State<AppState>,
    identity: Caller,
    Path(id): Path<u64>,
    Json(body): Json<SignalRequest>,
) -> Response {
    let identity = identity.map(|axum::Extension(id)| id);
    let signal = match body.signal {
        SignalName::Terminate => Signal::Terminate,
        SignalName::Kill => Signal::Kill,
        SignalName::Interrupt => Signal::Interrupt,
    };
    let table = state.processes.clone();
    match blocking(move || table.signal(id, signal, identity)).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => refusal(error),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    identity: Caller,
    Path(id): Path<u64>,
) -> Response {
    let identity = identity.map(|axum::Extension(id)| id);
    let table = state.processes.clone();
    match blocking(move || table.delete(id, identity)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => refusal(error),
    }
}
