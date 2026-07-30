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

/// Resolve the requested page size against the configured bounds.
///
/// Clamped, not refused: a caller asking for zero or for more than the
/// ceiling gets a valid page size instead of an error or an unbounded walk.
/// Pure arithmetic on `requested`, independent of how large the tree being
/// listed is — proving it holds does not require building a tree above
/// `MAX_LIST_LIMIT`, only calling this with the numbers that matter.
fn resolve_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT)
}

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
    /// Resume point: the opaque token from the previous page's `next_cursor`.
    ///
    /// Echo it back verbatim. It is not a path, and a hand-built value is
    /// refused with `400 bad-cursor`.
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
/// Paging is by opaque cursor, which encodes the last path returned rather than
/// an offset: entries are ordered by path, so a file added or removed mid-walk
/// shifts every offset but cannot invalidate a path.
///
/// The encoding is what makes the token opaque, and it is not decoration. A raw
/// path on the wire passes through form-urlencoded decoding, where `+` becomes a
/// space — so a file named `data+1.csv` at a page boundary produced a cursor that
/// decoded to a name sorting *before* the real entry, and a client looping until
/// `next_cursor` was `None` re-fetched the same page forever.
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

    let limit = resolve_limit(query.limit);
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
    // `saturating_sub` rather than `end - 1`: the index is safe only because the
    // clamp keeps `limit` at 1 or more, which is a guarantee living in a
    // different expression. A future edit that relaxes the clamp would turn this
    // into a panic, and a panicking handler is a 500.
    let next_cursor =
        (end < collected.len()).then(|| encode_cursor(&collected[end.saturating_sub(1)].0));

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

/// A validator that changes whenever the bytes at a path might have changed.
///
/// Size and mtime on every platform, plus the inode on Unix. Windows has no
/// equivalent reachable from `std::fs::metadata`, so the validator is weaker
/// there — stated rather than papered over, because a validator that claims
/// more than the platform delivers is worse than one that is honest.
pub fn etag_for(meta: &std::fs::Metadata) -> String {
    format!(
        "\"{:x}-{:x}-{:x}\"",
        meta.len(),
        mtime_ms(meta),
        platform::file_identity(meta)
    )
}

/// The outcome of interpreting a `Range` header against a file of `size` bytes.
///
/// RFC 9110 §14.2 requires two different failure shapes to produce two
/// different responses: an unrecognised range unit, or a syntactically
/// invalid `bytes` spec, must be *ignored* — served as the whole file, 200 —
/// while only a well-formed `bytes` range that names bytes the file does not
/// have is "not satisfiable" (416). Collapsing both into one `Option::None`,
/// as an earlier version of this function did, served 416 for `Range:
/// items=0-4`, which the RFC forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeOutcome {
    /// No usable range: fall through to serving the whole file, exactly as
    /// if `Range` had not been sent at all.
    Ignore,
    /// A well-formed `bytes` range outside the file's current length.
    Unsatisfiable,
    /// A well-formed, in-bounds range: inclusive `(start, end)`.
    Satisfiable(u64, u64),
}

/// Parse a single-range `Range` header against a file of `size` bytes.
///
/// Only one range is supported: a multi-range spec is syntactically valid
/// but this implementation has no multipart body to serve it with, so it is
/// treated the same as an unrecognised unit — ignored, not refused with 416
/// for something the client asked for correctly.
pub fn parse_range(header: &str, size: u64) -> RangeOutcome {
    use RangeOutcome::{Ignore, Satisfiable, Unsatisfiable};

    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return Ignore; // unrecognised unit
    };
    if spec.contains(',') {
        return Ignore; // multipart; unsupported, but not the client's fault
    }
    let Some((from, to)) = spec.split_once('-') else {
        return Ignore;
    };

    let (start, end) = match (from.trim(), to.trim()) {
        ("", "") => return Ignore,
        // `bytes=-N`: the last N bytes. `saturating_sub` throughout rather
        // than an early `size == 0` guard: an empty file and a suffix of `0`
        // both collapse to `start >= size` below — the same "nothing to
        // serve" outcome either way, reached without a special case.
        ("", suffix) => {
            let Ok(n) = suffix.parse::<u64>() else {
                return Ignore;
            };
            (size.saturating_sub(n), size.saturating_sub(1))
        }
        (first, "") => {
            let Ok(start) = first.parse::<u64>() else {
                return Ignore;
            };
            (start, size.saturating_sub(1))
        }
        (first, last) => {
            let (Ok(start), Ok(end)) = (first.parse::<u64>(), last.parse::<u64>()) else {
                return Ignore;
            };
            // `last-byte-pos < first-byte-pos` is an invalid byte-range-spec
            // (RFC 9110 §14.1.2) — a syntax problem, not an out-of-bounds one.
            if end < start {
                return Ignore;
            }
            (start, end)
        }
    };

    if start >= size {
        return Unsatisfiable;
    }
    Satisfiable(start, end.min(size - 1))
}

/// `GET /api/v1/fs/file` — the whole file, or a range of it.
///
/// `HEAD` reaches this handler too: `axum`'s `get()` serves it automatically,
/// running the same handler and discarding the body. Without the `method`
/// check below, that meant loading the entire file into a `Vec` purely to
/// throw it away — waste on every call, and an amplification on a large file.
/// `include_body` skips every read while still computing the same status and
/// headers a `GET` would.
pub async fn download(
    State(state): State<AppState>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
    Query(query): Query<PathQuery>,
) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };

    // Everything this handler needs from the headers, extracted before
    // handing off to `spawn_blocking` — the blocking body below has no access
    // to the request beyond what it is passed.
    let header_str = |name: axum::http::HeaderName| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    let range_header = header_str(axum::http::header::RANGE);
    let if_range_header = header_str(axum::http::header::IF_RANGE);
    let include_body = method != axum::http::Method::HEAD;

    // Resolving the path, `stat`-ing it, and reading the bytes (whole file or
    // a span) are all blocking I/O. Same convention as `execution::executor::execute`
    // (`src/execution/executor.rs:209-215`) and `list`/`list_blocking` above:
    // run it on `spawn_blocking` so a large file, a slow filesystem, or —
    // absent the `is_file()` guard below — a FIFO or character device can
    // never starve the tokio worker pool that also runs `/health` and the
    // accept loop.
    match tokio::task::spawn_blocking(move || {
        download_blocking(
            &root,
            &query,
            range_header.as_deref(),
            if_range_header.as_deref(),
            include_body,
        )
    })
    .await
    {
        Ok(response) => response,
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "download-failed",
            "reading the file failed unexpectedly",
        ),
    }
}

/// The synchronous body of `download`. Blocking throughout — see `download`,
/// which runs this via `spawn_blocking` rather than directly on the async
/// runtime.
///
/// `include_body` is `false` for `HEAD`: every status code and header below
/// is computed exactly as for `GET`, but no file content is read, and
/// `content-length` is set explicitly from metadata rather than left to be
/// inferred from an (empty) body.
fn download_blocking(
    root: &FsRoot,
    query: &PathQuery,
    range_header: Option<&str>,
    if_range_header: Option<&str>,
    include_body: bool,
) -> Response {
    let resolved = match root.resolve_existing(&query.path) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };

    // Metadata of the path the jail handed back, not the caller's string —
    // and `is_file()` gates every read below. A FIFO blocks `File::open`
    // indefinitely and a character device never reaches EOF, so without this
    // check a path like `/dev/zero` inside the root would hang the request
    // forever instead of failing fast. The message says "not a regular
    // file" rather than "a directory": a FIFO or character device hits this
    // same arm, and a message that named only directories would be wrong for
    // them.
    let meta = match std::fs::metadata(&resolved) {
        Ok(meta) if meta.is_file() => meta,
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "not-a-file",
                "path is not a regular file; if it is a directory, use /api/v1/fs/list",
            )
        }
        Err(_) => return fs_error_response(FsError::NotFound),
    };

    let size = meta.len();
    let etag = etag_for(&meta);

    // A stale `If-Range` means the caller's prefix belongs to a different file.
    // Serving the range anyway would let them stitch two files together and
    // notice only when the checksum failed, if they checked at all.
    let range_allowed = match if_range_header {
        Some(sent) => sent == etag,
        None => true,
    };

    let requested = range_header
        .filter(|_| range_allowed)
        .map(|raw| parse_range(raw, size));

    match requested {
        Some(RangeOutcome::Satisfiable(start, end)) => {
            let length = end - start + 1;
            let bytes = if include_body {
                match read_span(&resolved, start, length) {
                    Ok(bytes) => bytes,
                    Err(_) => return fs_error_response(FsError::NotFound),
                }
            } else {
                Vec::new()
            };
            (
                StatusCode::PARTIAL_CONTENT,
                [
                    ("content-type", "application/octet-stream".to_string()),
                    ("accept-ranges", "bytes".to_string()),
                    ("etag", etag),
                    ("content-range", format!("bytes {start}-{end}/{size}")),
                    ("content-length", length.to_string()),
                ],
                bytes,
            )
                .into_response()
        }
        Some(RangeOutcome::Unsatisfiable) => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            [("content-range", format!("bytes */{size}"))],
        )
            .into_response(),
        // `Ignore` (unrecognised unit, or a syntactically invalid `bytes`
        // spec — RFC 9110 §14.2) falls through to the whole file exactly as
        // `None` (no `Range` header at all) does.
        Some(RangeOutcome::Ignore) | None => {
            let bytes = if include_body {
                match std::fs::read(&resolved) {
                    Ok(bytes) => bytes,
                    Err(_) => return fs_error_response(FsError::NotFound),
                }
            } else {
                Vec::new()
            };
            // `bytes.len()`, not the `size` read from `metadata` earlier: a
            // concurrent writer can truncate or extend the file between that
            // `metadata` call and this `std::fs::read` (Tasks 5-6 add upload
            // routes into this same root, so this is not hypothetical). Using
            // the length of what was actually just read means the header can
            // never disagree with the body hyper is about to frame it around.
            // `HEAD` never reads, so it has no body length to take instead —
            // `size` from metadata is exactly what RFC 9110 §9.3.2 asks a
            // `HEAD` response to report.
            let content_length = if include_body {
                bytes.len() as u64
            } else {
                size
            };
            (
                StatusCode::OK,
                [
                    ("content-type", "application/octet-stream".to_string()),
                    ("accept-ranges", "bytes".to_string()),
                    ("etag", etag),
                    ("content-length", content_length.to_string()),
                ],
                bytes,
            )
                .into_response()
        }
    }
}

/// Read `length` bytes starting at `start`.
fn read_span(path: &std::path::Path, start: u64, length: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut buffer = vec![0_u8; length as usize];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// `DELETE /api/v1/fs/file` — remove one named entry.
///
/// Only a *real* directory is refused. Recursive removal is a destructive
/// operation that wants the guards (dry-run, backup, approval) this layer
/// does not have; a convenience flag here would hand out that power without
/// them. Everything else the entry could be — a regular file, a symlink (to
/// a file or to a directory), a FIFO, a socket, a device node — is removed:
/// unlike `download`, this handler never reads the entry's contents, so
/// `download`'s reason for gating on `is_file()` (a FIFO never reaches EOF)
/// does not apply here. And refusing a non-regular entry would leave it
/// permanently undeletable through this API, the same trap that decided the
/// symlink question below in favour of acting on the named entry.
pub async fn delete_file(
    State(state): State<AppState>,
    Query(query): Query<PathQuery>,
) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };

    // Resolving the path and removing the file are both blocking I/O. Same
    // convention as `list`/`list_blocking` and `download`/`download_blocking`
    // above (`src/execution/executor.rs:209-215`): run it on `spawn_blocking`
    // so a slow filesystem can never starve the tokio worker pool that also
    // runs `/health` and the accept loop.
    match tokio::task::spawn_blocking(move || delete_file_blocking(&root, &query)).await {
        Ok(response) => response,
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "delete-panicked",
            "removing the file failed unexpectedly",
        ),
    }
}

/// Split a root-relative request path into (parent, last component).
///
/// `"."` names the root itself when there is no separator — `resolve_existing`
/// already gives that string a defined meaning (`src/fs/root.rs:113`), so this
/// reuses it rather than inventing a second convention for "no parent".
fn split_last_component(rel: &str) -> (&str, &str) {
    match rel.rfind(['/', '\\']) {
        Some(idx) => (&rel[..idx], &rel[idx + 1..]),
        None => (".", rel),
    }
}

/// The synchronous body of `delete_file`. Blocking throughout — see
/// `delete_file`, which runs this via `spawn_blocking` rather than directly on
/// the async runtime.
///
/// Deliberately does not act on what `resolve_existing(&query.path)` returns:
/// that path follows symlinks all the way to their target
/// (`src/fs/root.rs:122-132`), so for a same-root symlink it would remove
/// whatever the link points to and leave the link itself behind — dangling,
/// and undeletable afterward, since `resolve_existing` refuses every dangling
/// symlink (`src/fs/root.rs:145-147`). A caller who named a link would see a
/// different file disappear and the one they named survive.
///
/// Instead: resolve the request path in full once, purely to get
/// `FsRoot`'s Malformed/Escapes/NotFound verdict exactly as every other
/// route does. Then split the *request string* into its parent and final
/// component, resolve only the parent through the jail, and rejoin the
/// literal final component onto that canonical parent. The result names
/// whatever the caller actually asked for — a symlink stays a symlink — while
/// every directory on the way there has still been walked through
/// `FsRoot::resolve_existing` and had `check_component` applied to it.
///
/// This does not weaken containment: splitting a string that has already
/// passed the first resolution cannot manufacture a component that didn't
/// already pass `check_component` during that walk. It only decides which of
/// two jail-approved paths to act on — the request's own final component, not
/// whatever that component's target happens to be.
fn delete_file_blocking(root: &FsRoot, query: &PathQuery) -> Response {
    if let Err(error) = root.resolve_existing(&query.path) {
        return fs_error_response(error);
    }

    let (parent_rel, name) = split_last_component(&query.path);

    // `name` can be `..` (`path=app/..` passes the full-path resolution
    // above — `resolve_existing` walks it back up to a real directory, not
    // out of the root, so nothing refuses it there). `named` below is built
    // with a lexical `PathBuf::join`, which never resolves `..`, so joining
    // `..` onto an in-root `parent` produces a path whose *actual* location —
    // once something reads it — is one level above `parent`, without ever
    // having gone through the jail. Today the directory refusal further down
    // happens to catch this anyway, since `X/..` always names a directory;
    // that is an accident of recursive removal not being supported yet, not
    // a reason, so it is checked here explicitly instead: `..` is refused as
    // a delete target outright, before it is ever joined.
    //
    // A containment check on the joined path instead of this would not work:
    // `Path::starts_with` is a pure component-prefix comparison that does not
    // resolve `..` either (verified: `Path::new("/root/app").join("..")
    // .starts_with("/root")` is `true`), so `named` always "starts with"
    // `root` regardless of a trailing `..`. And canonicalising `named` to get
    // a real answer would defeat the reason this function builds it lexically
    // in the first place — it would resolve the very symlink this handler
    // exists to leave untouched.
    if name == ".." {
        return fs_error_response(FsError::Escapes);
    }

    let parent = match root.resolve_existing(parent_rel) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };
    let named = parent.join(name);

    // `symlink_metadata` (lstat), not `metadata` (stat): the latter follows
    // the link and would report a symlink as whatever it points to, making a
    // symlink-to-directory indistinguishable from a real directory below.
    let meta = match std::fs::symlink_metadata(&named) {
        Ok(meta) => meta,
        Err(_) => return fs_error_response(FsError::NotFound),
    };

    // Refused only when `named` is a *real* directory. A symlink is never
    // refused here regardless of what it points to — removing a link is
    // removing one directory entry, not a recursive walk, so it carries none
    // of the risk the directory refusal above exists to guard against.
    if meta.is_dir() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "not-a-file",
            "path is a directory; recursive removal is not supported",
        );
    }

    match platform::remove_entry(&named, &meta) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "delete-failed",
            &format!("could not remove the file: {e}"),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse_into_inclusive_bounds() {
        use RangeOutcome::Satisfiable;

        assert_eq!(parse_range("bytes=0-4", 11), Satisfiable(0, 4));
        assert_eq!(parse_range("bytes=6-10", 11), Satisfiable(6, 10));
        // Open-ended: to the last byte.
        assert_eq!(parse_range("bytes=6-", 11), Satisfiable(6, 10));
        // Suffix: the last N bytes.
        assert_eq!(parse_range("bytes=-3", 11), Satisfiable(8, 10));
        // Clamped to the file, not refused.
        assert_eq!(parse_range("bytes=0-999", 11), Satisfiable(0, 10));
    }

    #[test]
    fn a_well_formed_out_of_bounds_range_is_unsatisfiable() {
        use RangeOutcome::Unsatisfiable;

        // First-byte-pos at or past the current length: well-formed, but the
        // file does not have those bytes.
        assert_eq!(parse_range("bytes=11-20", 11), Unsatisfiable);
        // A suffix of 0 bytes names nothing the file can supply.
        assert_eq!(parse_range("bytes=-0", 11), Unsatisfiable);
        // An empty file satisfies no byte-range-spec at all.
        assert_eq!(parse_range("bytes=0-4", 0), Unsatisfiable);
    }

    #[test]
    fn malformed_or_unrecognised_ranges_are_ignored_not_refused() {
        use RangeOutcome::Ignore;

        // RFC 9110 §14.2: an unrecognised unit or a syntactically invalid
        // `bytes` spec must be ignored — served as the whole file (200) —
        // not refused with 416. Only a well-formed, out-of-bounds `bytes`
        // range is 416 (see `a_well_formed_out_of_bounds_range_is_unsatisfiable`).
        assert_eq!(parse_range("items=0-4", 11), Ignore); // unrecognised unit
        assert_eq!(parse_range("bytes=5-2", 11), Ignore); // last-byte-pos < first-byte-pos
        assert_eq!(parse_range("bytes=0-1,4-5", 11), Ignore); // multipart, unsupported
        assert_eq!(parse_range("bytes=-", 11), Ignore); // empty suffix
    }

    #[test]
    fn resolve_limit_clamps_to_the_configured_bounds() {
        assert_eq!(resolve_limit(None), DEFAULT_LIST_LIMIT);
        // Lower bound: zero must not mean "empty page".
        assert_eq!(resolve_limit(Some(0)), 1);
        // Ceiling: a caller asking for far more than the max is clamped, not
        // refused and not served unbounded.
        assert_eq!(resolve_limit(Some(999_999)), MAX_LIST_LIMIT);
        // Pass-through within bounds.
        assert_eq!(resolve_limit(Some(50)), 50);
    }

    #[test]
    fn etag_reflects_size_and_discriminates_on_mtime() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.bin");
        std::fs::write(&path, b"hello").expect("write");
        let meta = std::fs::metadata(&path).expect("metadata");
        let etag = etag_for(&meta);

        // Shape: `"<size>-<mtime>-<identity>"`, three hex fields.
        let inner = etag.trim_matches('"');
        let parts: Vec<&str> = inner.split('-').collect();
        assert_eq!(
            parts.len(),
            3,
            "etag should be three hyphen-separated fields: {etag}"
        );
        assert_eq!(
            u64::from_str_radix(parts[0], 16).expect("size field is hex"),
            meta.len()
        );

        // Rewriting with different content of the *same* length changes only
        // the mtime (and, on Unix, nothing else — same inode). If the etag
        // did not change too, a caller could not tell a mutated same-size
        // file from the original — exactly the failure `If-Range` depends on
        // this function to prevent.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&path, b"HELLO").expect("rewrite, same size");
        let meta2 = std::fs::metadata(&path).expect("metadata");

        if mtime_ms(&meta) == mtime_ms(&meta2) {
            // Coarse filesystem clock; the two writes landed in the same
            // millisecond. Nothing to compare — skip rather than flake.
            return;
        }
        assert_ne!(
            etag,
            etag_for(&meta2),
            "same-size file with a different mtime must get a different etag"
        );
    }

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
