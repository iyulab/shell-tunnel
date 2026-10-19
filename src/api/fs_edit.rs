//! The filesystem writes that are not an upload: making a directory, moving an
//! entry, and writing a small file in one request.
//!
//! Kept beside `fs.rs` rather than in it, and holding no path logic of its own
//! for the same reason that module gives: every path reaches the disk through
//! `FsRoot` — `resolve_for_create` for a path that may not exist yet, and
//! `fs::resolve_named_entry` for an entry acted on as itself rather than as
//! whatever a symlink points to.

use std::path::{Path, PathBuf};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use super::fs::{
    error_response, fs_error_response, fs_not_enabled, is_reserved_path, reserved_path_response,
    resolve_named_entry, upload_error_code, upload_error_response,
};
use super::handlers::AppState;
use crate::audit::{AuditEvent, AuditSink, Identity};
use crate::fs::{FsError, FsRoot, UploadStore};

type Caller = Option<axum::Extension<Identity>>;

/// Run a blocking body off the async runtime, the convention every route in
/// `fs.rs` follows: resolving a path and touching the disk both block, and a
/// slow filesystem must not starve the workers that serve `/health`.
async fn blocking(work: impl FnOnce() -> Response + Send + 'static) -> Response {
    tokio::task::spawn_blocking(work).await.unwrap_or_else(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "fs-panicked",
            "the filesystem operation failed unexpectedly",
        )
    })
}

/// Record an outcome these routes decided themselves.
///
/// Same scope rule as the delete route's refusals: a path that does not resolve
/// is refused by machinery shared with every other fs route and is not recorded
/// here, so the trail does not claim to see a fraction of those attempts.
fn event(
    identity: Option<Identity>,
    kind: &str,
    route: &str,
    file: &str,
    denial: Option<(StatusCode, &str)>,
) -> AuditEvent {
    let mut event = AuditEvent::new(kind)
        .with_identity(identity)
        .with_route(route)
        .with_file(file.to_string(), None);
    if let Some((status, reason)) = denial {
        event = event.with_denial(status.as_u16(), reason);
    }
    event
}

/// The answer when the server cannot place a path it has just resolved
/// (`FsRoot::relative` returned `None`) — the same fail-closed 500
/// `create_upload` gives the identical call.
fn unplaceable() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "path-resolution-failed",
        "could not compute the entry's canonical path",
    )
}

/// A refusal both answered and recorded, with one code for both. `base` names
/// the operation; the denial is added here.
fn refuse(
    audit: &AuditSink,
    base: AuditEvent,
    status: StatusCode,
    code: &str,
    message: &str,
) -> Response {
    audit.record(base.with_denial(status.as_u16(), code));
    error_response(status, code, message)
}

// ---------------------------------------------------------------------------
// mkdir
// ---------------------------------------------------------------------------

/// Body of `POST /api/v1/fs/mkdir`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MkdirRequest {
    pub path: String,
    /// Create missing parents too, and accept a directory that already exists
    /// — `mkdir -p`. Without it a missing parent is `404` and an existing
    /// directory is `409`.
    #[serde(default)]
    pub parents: bool,
}

const MKDIR: &str = "POST /api/v1/fs/mkdir";

/// `POST /api/v1/fs/mkdir` — create a directory.
pub async fn mkdir(
    State(state): State<AppState>,
    identity: Caller,
    Json(body): Json<MkdirRequest>,
) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };
    let audit = state.audit.clone();
    let identity = identity.map(|axum::Extension(id)| id);
    blocking(move || mkdir_blocking(&root, &audit, identity, &body)).await
}

fn mkdir_blocking(
    root: &FsRoot,
    audit: &AuditSink,
    identity: Option<Identity>,
    body: &MkdirRequest,
) -> Response {
    let target = match root.resolve_for_create(&body.path) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };
    let Some(rel) = root.relative(&target) else {
        return unplaceable();
    };
    if is_reserved_path(&rel) {
        audit.record(event(
            identity,
            "fs.mkdir.refused",
            MKDIR,
            &rel,
            Some((StatusCode::FORBIDDEN, "reserved-path")),
        ));
        return reserved_path_response();
    }

    // `resolve_for_create` hands back the canonical path when the entry
    // exists, so `metadata` here describes what is really there.
    if let Ok(meta) = std::fs::metadata(&target) {
        if !meta.is_dir() {
            return refuse(
                audit,
                event(identity, "fs.mkdir.refused", MKDIR, &rel, None),
                StatusCode::CONFLICT,
                "exists-not-directory",
                "something other than a directory already exists at this path",
            );
        }
        if !body.parents {
            return refuse(
                audit,
                event(identity, "fs.mkdir.refused", MKDIR, &rel, None),
                StatusCode::CONFLICT,
                "exists",
                "the directory already exists; pass parents=true to accept that",
            );
        }
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "path": rel, "created": false })),
        )
            .into_response();
    }

    let made = if body.parents {
        std::fs::create_dir_all(&target)
    } else {
        std::fs::create_dir(&target)
    };
    match made {
        Ok(()) => {
            audit.record(event(identity, "fs.mkdir", MKDIR, &rel, None));
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "path": rel, "created": true })),
            )
                .into_response()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => error_response(
            StatusCode::NOT_FOUND,
            "not-found",
            "the parent directory does not exist; pass parents=true to create it",
        ),
        Err(e) => {
            audit.record(event(
                identity,
                "fs.mkdir.failed",
                MKDIR,
                &rel,
                Some((StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
            ));
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "mkdir-failed",
                &format!("could not create the directory: {e}"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// move
// ---------------------------------------------------------------------------

/// Body of `POST /api/v1/fs/move`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveRequest {
    pub from: String,
    pub to: String,
    /// Replace a file already at `to`. A directory at `to` is never replaced.
    #[serde(default)]
    pub overwrite: bool,
}

const MOVE: &str = "POST /api/v1/fs/move";

/// `POST /api/v1/fs/move` — rename or move one entry within what the file API
/// reaches.
pub async fn move_entry(
    State(state): State<AppState>,
    identity: Caller,
    Json(body): Json<MoveRequest>,
) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };
    let audit = state.audit.clone();
    let uploads = state.uploads.clone();
    let identity = identity.map(|axum::Extension(id)| id);
    blocking(move || move_blocking(&root, &audit, &uploads, identity, &body)).await
}

/// Where a move lands: the entry already there (named, not followed), or the
/// path it will be created at.
fn resolve_destination(root: &FsRoot, rel: &str) -> Result<(PathBuf, bool), FsError> {
    match resolve_named_entry(root, rel) {
        Ok(existing) => Ok((existing, true)),
        Err(FsError::NotFound) => Ok((root.resolve_for_create(rel)?, false)),
        Err(error) => Err(error),
    }
}

/// Whether an I/O error says the two paths are on different filesystems —
/// `EXDEV` on Unix, `ERROR_NOT_SAME_DEVICE` on Windows. A rename cannot cross
/// one, and this route does not copy.
fn crosses_devices(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    const CODE: i32 = 18;
    #[cfg(windows)]
    const CODE: i32 = 17;
    #[cfg(not(any(unix, windows)))]
    const CODE: i32 = -1;
    error.raw_os_error() == Some(CODE)
}

fn move_blocking(
    root: &FsRoot,
    audit: &AuditSink,
    uploads: &UploadStore,
    identity: Option<Identity>,
    body: &MoveRequest,
) -> Response {
    let source = match resolve_named_entry(root, &body.from) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };
    let (dest, dest_exists) = match resolve_destination(root, &body.to) {
        Ok(found) => found,
        Err(error) => return fs_error_response(error),
    };
    let Some(from_rel) = root.relative(&source) else {
        return unplaceable();
    };
    let Some(to_rel) = root.relative(&dest) else {
        return unplaceable();
    };
    let refused = |status, code, message: &str| {
        audit.record(
            event(
                identity.clone(),
                "fs.move.refused",
                MOVE,
                &from_rel,
                Some((status, code)),
            )
            .with_target(to_rel.clone()),
        );
        error_response(status, code, message)
    };

    if is_reserved_path(&from_rel) || is_reserved_path(&to_rel) {
        return refused(
            StatusCode::FORBIDDEN,
            "reserved-path",
            "path resolves into the upload staging directory, which is reserved",
        );
    }

    let source_meta = match std::fs::symlink_metadata(&source) {
        Ok(meta) => meta,
        Err(_) => return fs_error_response(FsError::NotFound),
    };

    if source == dest {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "from": from_rel, "to": to_rel, "replaced": false })),
        )
            .into_response();
    }

    if source_meta.is_dir() {
        // `rename` refuses this itself (`EINVAL`), but in words that do not
        // say why; and the check is lexical on two canonical parents, so it
        // cannot be fooled by spelling.
        if dest.starts_with(&source) {
            return refused(
                StatusCode::BAD_REQUEST,
                "bad-path",
                "a directory cannot be moved into itself",
            );
        }
        // Bytes an upload has already staged under this tree would move away
        // from the session that is writing them — the move the delete route
        // refuses for the same reason.
        if uploads.has_live_part_under(&source) {
            return refused(
                StatusCode::CONFLICT,
                "staging-in-tree",
                "an upload is in flight under this path; cancel it or wait for it to finish",
            );
        }
    }
    // An upload destined at or under the source would recreate the old path
    // when it completes; one destined at the destination would overwrite what
    // this move put there. Either way the move would not be what stays.
    if uploads.live_destinations_at(&source) > 0 || uploads.live_destinations_at(&dest) > 0 {
        return refused(
            StatusCode::CONFLICT,
            "destination-busy",
            "an upload in flight is destined for one of these paths; cancel it or wait for it to finish",
        );
    }

    if dest_exists {
        let dest_meta = match std::fs::symlink_metadata(&dest) {
            Ok(meta) => meta,
            Err(_) => return fs_error_response(FsError::NotFound),
        };
        if dest_meta.is_dir() {
            return refused(
                StatusCode::CONFLICT,
                "destination-is-directory",
                "a directory already exists at the destination; a move never replaces one",
            );
        }
        if source_meta.is_dir() {
            return refused(
                StatusCode::CONFLICT,
                "destination-exists",
                "something already exists at the destination, and a directory cannot replace it",
            );
        }
        if !body.overwrite {
            return refused(
                StatusCode::CONFLICT,
                "destination-exists",
                "something already exists at the destination; pass overwrite=true to replace it",
            );
        }
    } else if !dest.parent().is_some_and(Path::is_dir) {
        return error_response(
            StatusCode::NOT_FOUND,
            "not-found",
            "the destination's parent directory does not exist",
        );
    }

    match std::fs::rename(&source, &dest) {
        Ok(()) => {
            audit.record(
                event(identity, "fs.move", MOVE, &from_rel, None).with_target(to_rel.clone()),
            );
            Json(serde_json::json!({
                "from": from_rel,
                "to": to_rel,
                "replaced": dest_exists,
            }))
            .into_response()
        }
        Err(e) if crosses_devices(&e) => refused(
            StatusCode::CONFLICT,
            "cross-device",
            "source and destination are on different filesystems; a move does not copy",
        ),
        Err(e) => {
            audit.record(
                event(
                    identity,
                    "fs.move.failed",
                    MOVE,
                    &from_rel,
                    Some((StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
                )
                .with_target(to_rel),
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "move-failed",
                &format!("could not move the entry: {e}"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// put
// ---------------------------------------------------------------------------

/// Query of `PUT /api/v1/fs/file`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutQuery {
    pub path: String,
    /// Replace a file already at `path`. A directory is never replaced.
    #[serde(default)]
    pub overwrite: bool,
}

const PUT: &str = "PUT /api/v1/fs/file";

/// `PUT /api/v1/fs/file` — write a whole file from one request body.
///
/// For a file small enough to send at once: the body may be at most the chunk
/// size an upload session would advertise to this caller, and a larger one is
/// `413` pointing at `POST /api/v1/fs/uploads`. The route carries axum's body
/// limit at `MAX_CHUNK_SIZE` (`router.rs`) so an over-limit body reaches this
/// handler and gets the machine-readable refusal rather than a bare `413`.
pub async fn put_file(
    State(state): State<AppState>,
    identity: Caller,
    headers: axum::http::HeaderMap,
    Query(query): Query<PutQuery>,
    body: axum::body::Bytes,
) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };
    let limit = state.uploads.chunk_size(super::fs::via_relay(&headers));
    let audit = state.audit.clone();
    let uploads = state.uploads.clone();
    let identity = identity.map(|axum::Extension(id)| id);
    blocking(move || put_blocking(&root, &audit, &uploads, identity, &query, &body, limit)).await
}

fn put_blocking(
    root: &FsRoot,
    audit: &AuditSink,
    uploads: &UploadStore,
    identity: Option<Identity>,
    query: &PutQuery,
    body: &[u8],
    limit: usize,
) -> Response {
    let (target, exists) = match resolve_destination(root, &query.path) {
        Ok(found) => found,
        Err(error) => return fs_error_response(error),
    };
    let Some(rel) = root.relative(&target) else {
        return unplaceable();
    };
    let refused = |status, code, message: &str| {
        refuse(
            audit,
            event(identity.clone(), "fs.write.refused", PUT, &rel, None),
            status,
            code,
            message,
        )
    };

    if is_reserved_path(&rel) {
        return refused(
            StatusCode::FORBIDDEN,
            "reserved-path",
            "path resolves into the upload staging directory, which is reserved",
        );
    }
    if body.len() > limit {
        audit.record(event(
            identity,
            "fs.write.refused",
            PUT,
            &rel,
            Some((StatusCode::PAYLOAD_TOO_LARGE, "body-too-large")),
        ));
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": "body-too-large",
                "message": "the body is larger than this route takes in one request; send it through POST /api/v1/fs/uploads",
                "limit": limit,
            })),
        )
            .into_response();
    }
    if exists {
        match std::fs::symlink_metadata(&target) {
            Ok(meta) if meta.is_dir() => {
                return refused(
                    StatusCode::CONFLICT,
                    "destination-is-directory",
                    "the destination path already exists as a directory",
                )
            }
            Ok(_) if !query.overwrite => {
                return refused(
                    StatusCode::CONFLICT,
                    "destination-exists",
                    "a file already exists at this path; pass overwrite=true to replace it",
                )
            }
            _ => {}
        }
    } else if !target.parent().is_some_and(Path::is_dir) {
        return error_response(
            StatusCode::NOT_FOUND,
            "not-found",
            "the parent directory does not exist; create it with POST /api/v1/fs/mkdir",
        );
    }
    // Through the upload store's claim: an upload in flight to this path is
    // refused here as `destination-busy` (the same body `create_upload` gives,
    // `upload_id` included), and while this write holds the claim an upload
    // opened for the path is refused the same way. Staged and renamed into
    // place, so a reader never sees half a file and a failed write leaves the
    // old one.
    match uploads.write_whole(root, &target, rel.clone(), body) {
        Ok(()) => {
            let mut hasher = crate::fs::sha256::Hasher::new();
            hasher.update(body);
            let digest = hasher.finish();
            audit.record(
                AuditEvent::new("fs.write")
                    .with_identity(identity)
                    .with_route(PUT)
                    .with_file(rel.clone(), Some(body.len() as u64)),
            );
            let status = if exists {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            (
                status,
                Json(serde_json::json!({
                    "path": rel,
                    "bytes": body.len(),
                    "sha256": digest,
                    "replaced": exists,
                })),
            )
                .into_response()
        }
        Err(crate::fs::UploadError::Io { detail, .. }) => {
            audit.record(
                AuditEvent::new("fs.write.failed")
                    .with_identity(identity)
                    .with_route(PUT)
                    .with_denial(500, detail.clone())
                    .with_file(rel, None),
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write-failed",
                &format!("could not write the file: {detail}"),
            )
        }
        Err(error) => {
            let reason = upload_error_code(&error);
            let response = upload_error_response(error);
            audit.record(event(
                identity,
                "fs.write.refused",
                PUT,
                &rel,
                Some((response.status(), reason)),
            ));
            response
        }
    }
}
