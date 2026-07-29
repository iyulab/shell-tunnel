//! Filesystem endpoints.
//!
//! Every path in here reaches the disk through `FsRoot` and by no other route.
//! The handlers hold no path logic of their own — that separation is what makes
//! the jail auditable by reading one file.

use std::time::UNIX_EPOCH;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::handlers::AppState;
use crate::fs::{platform, FsError, FsRoot};

/// One filesystem entry, as reported by `stat` and by each `list` item.
///
/// The same shape in both so a consumer can hold list items and single lookups
/// in one type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsEntry {
    /// Root-relative path with POSIX separators.
    pub path: String,
    /// Size in bytes. Zero for directories.
    pub size: u64,
    /// Modification time, Unix milliseconds.
    pub mtime_ms: u64,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Content hash, only when the caller asked for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Query parameters shared by the single-path endpoints.
#[derive(Debug, Deserialize)]
pub struct PathQuery {
    pub path: String,
}

/// Render a refusal as JSON with a machine-readable code.
///
/// The code matters more than the prose: a consumer decides whether to retry,
/// re-authorise, or give up by reading it.
pub fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": code, "message": message })),
    )
        .into_response()
}

/// Map a jail refusal onto HTTP.
///
/// `Escapes` is 403 rather than 404 deliberately, and identically whether or
/// not the target exists: a split between the two would tell a caller what
/// lives outside the root.
pub fn fs_error_response(error: FsError) -> Response {
    match error {
        FsError::Malformed(reason) => error_response(StatusCode::BAD_REQUEST, "bad-path", reason),
        FsError::Escapes => error_response(
            StatusCode::FORBIDDEN,
            "path-escapes-root",
            "path resolves outside the configured root",
        ),
        FsError::NotFound => error_response(
            StatusCode::NOT_FOUND,
            "not-found",
            "no such file or directory",
        ),
    }
}

/// The refusal sent when no `--fs-root` was configured.
///
/// A function rather than a `Result`-returning guard: handlers return `Response`
/// directly, so `?` never applies and a `Result` buys nothing — it only makes
/// the error variant large enough to trip `clippy::result_large_err`, which
/// invites boxing a problem that need not exist. Callers pair this with
/// `let Some(root) = state.fs.clone() else { return fs_not_enabled(); }`.
pub fn fs_not_enabled() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "fs-not-enabled",
        "the filesystem API is disabled; start with --fs-root <path> to enable it",
    )
}

/// Milliseconds since the Unix epoch, or zero when the clock says otherwise.
pub fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build an entry for one already-resolved path.
pub fn entry_for(
    root: &FsRoot,
    absolute: &std::path::Path,
    meta: &std::fs::Metadata,
    sha256: Option<String>,
) -> FsEntry {
    FsEntry {
        path: root.relative(absolute).unwrap_or_default(),
        size: if meta.is_dir() { 0 } else { meta.len() },
        mtime_ms: mtime_ms(meta),
        is_dir: meta.is_dir(),
        sha256,
    }
}

/// `GET /api/v1/fs/stat` — one entry, file or directory.
pub async fn stat(State(state): State<AppState>, Query(query): Query<PathQuery>) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };

    let resolved = match root.resolve_existing(&query.path) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };

    let meta = match std::fs::metadata(&resolved) {
        Ok(meta) => meta,
        Err(_) => return fs_error_response(FsError::NotFound),
    };

    // `file_identity` is unused here but keeps the platform module honest about
    // being the only place that reaches for OS-specific metadata.
    let _ = platform::file_identity(&meta);

    Json(entry_for(&root, &resolved, &meta, None)).into_response()
}
