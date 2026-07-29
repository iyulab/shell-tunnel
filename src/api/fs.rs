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

/// Default page size for `list`.
///
/// The relay buffers whole bodies with an 8 MiB ceiling (`relay::MAX_BODY`), so
/// an unpaginated listing of a real deployment tree would 413 — on exactly the
/// tree sizes this endpoint exists to serve.
pub const DEFAULT_LIST_LIMIT: usize = 1_000;

/// Largest page a caller may ask for. Requests above it are clamped, not refused.
pub const MAX_LIST_LIMIT: usize = 10_000;

/// Where in-flight uploads are staged. Never reported by `list`.
pub use crate::fs::UPLOAD_DIR;

/// Query parameters for `list`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
    /// Only `sha256` is understood; anything else is ignored.
    #[serde(default)]
    pub hash: Option<String>,
    /// Resume point: the last path returned by the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// One page of entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub entries: Vec<FsEntry>,
    /// Pass back as `cursor` to continue. `None` means this was the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// `GET /api/v1/fs/list` — one page of a directory's contents.
///
/// The cursor is the last path returned, not an offset: entries are ordered by
/// path, so a file added or removed mid-walk shifts offsets but never
/// invalidates a path.
pub async fn list(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };

    // Resolving `path`, walking the tree, and hashing whole files are all
    // blocking I/O. Same convention as `execution::executor::execute`
    // (`src/execution/executor.rs:209-215`): run it on `spawn_blocking` so a
    // large tree, a slow filesystem, or — absent the `is_file()` guard below
    // — a FIFO can never starve the tokio worker pool that also runs
    // `/health` and the accept loop.
    match tokio::task::spawn_blocking(move || list_blocking(&root, &query)).await {
        Ok(response) => response,
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "list-failed",
            "listing the directory failed unexpectedly",
        ),
    }
}

/// The synchronous body of `list`. Blocking throughout — see `list`, which
/// runs this via `spawn_blocking` rather than directly on the async runtime.
fn list_blocking(root: &FsRoot, query: &ListQuery) -> Response {
    let base = match root.resolve_existing(&query.path) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };

    match std::fs::metadata(&base) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "not-a-directory",
                "path is a file; use /api/v1/fs/stat for a single entry",
            )
        }
        Err(_) => return fs_error_response(FsError::NotFound),
    }

    let limit = query
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let want_hash = query.hash.as_deref() == Some("sha256");

    let mut collected: Vec<(String, std::path::PathBuf, std::fs::Metadata)> = Vec::new();
    if let Err(WalkError::Unreadable) = walk(root, &base, query.recursive, &mut collected) {
        return error_response(StatusCode::FORBIDDEN, "unreadable", "directory unreadable");
    }
    collected.sort_by(|a, b| a.0.cmp(&b.0));

    // Strictly greater than the cursor, so the page boundary cannot repeat an
    // entry or skip one.
    let start = match query.cursor.as_deref() {
        Some(token) => match decode_cursor(token) {
            Some(cursor) => {
                collected.partition_point(|(path, _, _)| path.as_str() <= cursor.as_str())
            }
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "bad-cursor",
                    "cursor is not a value this endpoint produced",
                )
            }
        },
        None => 0,
    };

    let end = (start + limit).min(collected.len());
    let next_cursor = (end < collected.len()).then(|| encode_cursor(&collected[end - 1].0));

    let mut entries = Vec::with_capacity(end.saturating_sub(start));
    for (relative, absolute, meta) in &collected[start..end] {
        // Hashing is per page, never per tree: a recursive hashed walk of a
        // large root would otherwise outrun the relay's 120s request timeout.
        let sha256 = match want_hash && !meta.is_dir() {
            // `walk` produced this path from a directory scan, so it has never
            // been through the jail — `relative()` is a lexical strip_prefix and
            // `DirEntry::metadata` is lstat, so a symlink looks in-root while
            // `File::open` would follow it out. Re-resolve, and hash only what
            // the jail hands back.
            true => match root.resolve_existing(relative) {
                Ok(canonical) => match std::fs::metadata(&canonical) {
                    // A FIFO or character device never reaches EOF, so hashing
                    // one blocks forever. Only regular files are hashable.
                    Ok(target) if target.is_file() => crate::fs::sha256::hash_file(&canonical).ok(),
                    _ => None,
                },
                Err(_) => None,
            },
            false => None,
        };
        entries.push(entry_for(root, absolute, meta, sha256));
    }

    Json(ListResponse {
        entries,
        next_cursor,
    })
    .into_response()
}

/// Encode a relative path as an opaque cursor.
///
/// Not for confidentiality — hex has no special characters, and that is the
/// point: axum's `Query` decodes form-urlencoded input, where `+` means a
/// space, and `+` is a legal, ordinary filename character (`libstdc++`). A
/// cursor built from the raw path would decode back to a different string
/// than the one that produced it, sort earlier than the real entry, and
/// repeat the same page forever. Hex removes the ambiguity instead of
/// chasing every character `Query` might reinterpret.
fn encode_cursor(path: &str) -> String {
    let mut out = String::with_capacity(path.len() * 2);
    for byte in path.as_bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decode a cursor produced by `encode_cursor`. `None` for anything else —
/// including a raw path a caller might paste in by hand — so a malformed
/// cursor is refused with 400 `bad-cursor` rather than silently resetting to
/// page one.
fn decode_cursor(token: &str) -> Option<String> {
    if token.is_empty() || token.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(token.len() / 2);
    for pair in token.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        bytes.push((hi * 16 + lo) as u8);
    }
    String::from_utf8(bytes).ok()
}

/// The one fatal outcome `walk` can report.
///
/// A dedicated enum rather than `Result<(), Response>`: the latter trips
/// `clippy::result_large_err` (a `Response` is well over the 128-byte
/// threshold) for exactly the reason `fs_not_enabled`'s doc comment already
/// explains — the caller builds the actual `Response` once it knows which
/// refusal applies.
enum WalkError {
    Unreadable,
}

/// Collect entries under `base`, skipping the upload staging directory.
///
/// Only `base` itself being unreadable is fatal, and only to the caller of
/// this exact invocation — `list`'s top-level call turns that into a 403.
/// Below that, nothing is fatal: an entry whose metadata cannot be read is
/// skipped, and so is a nested subdirectory that fails to open. A
/// permission-restricted subdirectory is ordinary in a real deployment tree;
/// one bad subtree, however deep, must not discard everything already
/// collected from the rest of the walk.
fn walk(
    root: &FsRoot,
    base: &std::path::Path,
    recursive: bool,
    out: &mut Vec<(String, std::path::PathBuf, std::fs::Metadata)>,
) -> Result<(), WalkError> {
    let read = std::fs::read_dir(base).map_err(|_| WalkError::Unreadable)?;

    for entry in read.flatten() {
        let absolute = entry.path();
        let Some(relative) = root.relative(&absolute) else {
            continue;
        };
        if relative == UPLOAD_DIR || relative.starts_with(&format!("{UPLOAD_DIR}/")) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let is_dir = meta.is_dir();
        out.push((relative, absolute.clone(), meta));
        if recursive && is_dir {
            // Discarded, not propagated with `?`: only the top-level `base`
            // being unreadable is fatal (see the doc comment above).
            let _ = walk(root, &absolute, true, out);
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    // Scoped to unix: the only test in this module needs it, and an
    // unconditional `use super::*` would be an unused-import warning on a
    // platform where that test doesn't compile at all.
    #[cfg(unix)]
    use super::*;

    /// Regression for the bug where a nested `read_dir` failure propagated
    /// with `?` all the way out of `walk`, discarding every entry the walk
    /// had already collected. Only the top-level directory being unreadable
    /// should be fatal; a permission-restricted subdirectory further down is
    /// ordinary in a real deployment tree.
    ///
    /// `#[cfg(unix)]` because removing read permission from a directory has
    /// no direct `std::fs` equivalent on Windows (ACLs, not a mode bit) —
    /// same constraint the existing `a_symlink_out_of_the_root_is_refused`
    /// test in `src/fs/root.rs` already accepts.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_nested_subdirectory_does_not_abort_the_whole_walk() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("app/locked")).expect("mkdir locked");
        std::fs::write(dir.path().join("app/locked/secret.txt"), b"x").expect("write secret");
        std::fs::write(dir.path().join("app/visible.txt"), b"y").expect("write visible");
        std::fs::write(dir.path().join("app/zzz.txt"), b"z").expect("write zzz");

        let root = FsRoot::new(dir.path()).expect("root");
        let locked = dir.path().join("app/locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("chmod locked");

        // A privileged account (root, or a runner that ignores the mode bit)
        // can still read a "locked" directory — nothing to verify then.
        if std::fs::read_dir(&locked).is_ok() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();
            return;
        }

        let mut collected: Vec<(String, std::path::PathBuf, std::fs::Metadata)> = Vec::new();
        let result = walk(&root, &dir.path().join("app"), true, &mut collected);

        // Restore permissions before any assertion can panic and leak a
        // directory the temp-dir cleanup would otherwise be unable to remove.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
            .expect("restore permissions");

        assert!(
            result.is_ok(),
            "an unreadable nested subdirectory must not fail the whole walk"
        );
        let paths: Vec<&str> = collected.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(paths.contains(&"app/visible.txt"));
        assert!(paths.contains(&"app/zzz.txt"));
        assert!(
            paths.contains(&"app/locked"),
            "the locked directory itself is still listed — only its contents are unreachable"
        );
        assert!(
            !paths.iter().any(|p| p.starts_with("app/locked/")),
            "contents of the unreadable subdirectory are simply absent, not fatal"
        );
    }
}
