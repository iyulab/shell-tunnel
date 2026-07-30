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

/// Whether a root-relative path names the upload staging directory itself, or
/// anything inside it.
///
/// One helper rather than one inline copy per handler that takes a `path`.
/// Before this existed, `list`'s walk hid the directory from listings and
/// `create_upload` refused it as a destination, but `stat`, `download`, and
/// `delete_file` checked nothing — each of those was added in a different
/// task, correct in its own scope, and none of them noticed the other two
/// routes exposing the same directory the first two were built to protect.
/// A sixth route taking a `path` calls this too, instead of becoming the
/// place someone forgets it a third time.
fn is_reserved_path(rel: &str) -> bool {
    rel == UPLOAD_DIR || rel.starts_with(&format!("{UPLOAD_DIR}/"))
}

/// The refusal for a path that names the upload staging directory, or
/// something inside it. Same code and wording `create_upload` already used
/// for refusing it as a destination — kept identical rather than letting each
/// caller invent its own phrasing for the same condition.
fn reserved_path_response() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "reserved-path",
        "path resolves into the upload staging directory, which is reserved",
    )
}

/// Refuse `resolved` if it names the reserved upload staging directory, or
/// something inside it. `None` means proceed.
///
/// Every call site passes a path already established to be under `root` —
/// via `resolve_existing` (`stat`, `download`), or via the postcondition just
/// above this call in `delete_file_blocking` — so `root.relative` returning
/// `None` here should not be reachable. Handled as a 500 rather than treated
/// as "not reserved, proceed" regardless: `create_upload_blocking`'s own
/// `dest_rel` binding faces the identical call and already answers `None`
/// with a 500 rather than silently continuing, and this follows that
/// precedent rather than the opposite one. A broken invariant must not
/// degrade into serving or removing the very file this check exists to
/// refuse — that would be fail-*open*, the wrong direction for a guard whose
/// only job is refusing.
///
/// **Existence-gated, deliberately — and that leaves a residual oracle.**
/// This guard only runs once a caller's path has already resolved to
/// something that exists (`resolve_existing`'s own 404 answers a
/// non-existent path first, before this ever sees it). So a caller probing
/// `.shell-tunnel-uploads/up-{serial:016x}.part` for a serial that never
/// existed gets 404, while the same probe against a serial with a session
/// currently in flight gets 403 `reserved-path`. Session ids are a
/// predictable per-process counter, so that pair of outcomes lets a holder
/// of `fs.read`/`fs.write` enumerate *which* session ids are live right now.
/// Accepted, not overlooked: what leaks is presence alone — never the
/// staged content (closed by this guard) and never the upload's destination
/// path (which lives only in the in-memory session and was never
/// derivable from the staging filename either way) — to a caller who
/// already holds root-wide read or delete via that same capability. The
/// asymmetry this guard exists to close (content exposure, cross-session
/// deletion) is a materially different severity than a presence bit.
///
/// The alternative — checking before resolution, directly on the caller's
/// raw string — was considered and rejected. Matching the unresolved string
/// is bypassable by spelling (`./`, backslashes, a `.` component), the same
/// aliasing class `two_sessions_for_aliased_spellings_of_one_destination_are_refused`
/// exists to cover for the upload destination claim key; making it reliable
/// would mean canonicalising independently of `resolve_existing`, i.e. a
/// second canonicalisation on every `stat`/`download` call — a real cost on
/// what is otherwise the hot read path — to close a leak that only ever
/// reveals a boolean, against a caller who is not thereby granted anything
/// they could not already reach.
fn refuse_if_reserved(root: &FsRoot, resolved: &std::path::Path) -> Option<Response> {
    match root.relative(resolved) {
        Some(rel) if is_reserved_path(&rel) => Some(reserved_path_response()),
        Some(_) => None,
        None => Some(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "path-resolution-failed",
            "could not compute the entry's canonical path",
        )),
    }
}

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
///
/// **`base` must already have been resolved through `root`** — as
/// `list_blocking` does with `resolve_existing` before calling this. Every
/// entry is named by `root.relative`, which is a pure `strip_prefix` and does
/// no resolution of its own, so a `base` that merely *points* inside the root
/// without being its canonical form yields `None` for every entry and this
/// returns `Ok(())` with **nothing collected** — an empty listing rather than
/// an error. That failure is invisible on a platform where the paths in play
/// are already canonical and loud on one where they are not: passing an
/// unresolved temp-dir path here read as a product bug on macOS, where
/// `/var/folders/…` canonicalises to `/private/var/folders/…`, while the same
/// code was silently fine on Linux. Resolve first; do not hand this a path
/// assembled by `join`.
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
        if is_reserved_path(&relative) {
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

    // Same reservation `create_upload` enforces on the way in and `list`
    // enforces on the way out: without it, a predictable session id
    // (`up-{serial:016x}.part`, a per-process counter from zero) let an
    // `fs.read` token read another caller's in-progress partial upload —
    // exactly the exposure `crate::fs::transfer`'s module doc says the
    // staging design prevents.
    if let Some(response) = refuse_if_reserved(root, &resolved) {
        return response;
    }

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
/// them.
///
/// Everything else the entry could be — a regular file, a symlink (to a file
/// or to a directory), a FIFO, a socket, a device node — is removed. Unlike
/// `download`, this handler never reads the entry's contents, so
/// `download`'s reason for gating on `is_file()` (a FIFO never reaches EOF)
/// does not apply here; and refusing a non-regular entry would leave it
/// permanently undeletable through this API, the same trap that decided the
/// symlink question below in favour of acting on the named entry.
///
/// Accepted limitation: the paragraph above holds only for a link that
/// itself resolves inside the root. A symlink pointing outside the root, or
/// a dangling one, stays undeletable through this route — both are refused
/// with `Escapes` before the named-entry logic below ever runs, because the
/// jail's verdict on the full path is final, and reaching either kind of
/// link would mean overriding it. That is the property every other route in
/// this feature rests on, so it is not relaxed here just to reach a broken
/// link; an operator has to remove those directly.
pub async fn delete_file(
    State(state): State<AppState>,
    identity: Option<axum::Extension<crate::audit::Identity>>,
    Query(query): Query<PathQuery>,
) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };
    let audit = state.audit.clone();
    let identity = identity.map(|axum::Extension(id)| id);

    // Resolving the path and removing the file are both blocking I/O. Same
    // convention as `list`/`list_blocking` and `download`/`download_blocking`
    // above (`src/execution/executor.rs:209-215`): run it on `spawn_blocking`
    // so a slow filesystem can never starve the tokio worker pool that also
    // runs `/health` and the accept loop. `audit.record` is blocking too
    // (`AuditSink::record` opens/writes/flushes a file), so it is recorded
    // from `delete_file_blocking` rather than back here — same reason the
    // upload handlers thread it into their own `_blocking` bodies.
    match tokio::task::spawn_blocking(move || delete_file_blocking(&root, &audit, identity, &query))
        .await
    {
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
///
/// The very first line below is what enforces `delete_file`'s documented
/// "accepted limitation": a symlink pointing outside the root, or a
/// dangling one, is refused with `Escapes` right there, before any of the
/// named-entry logic that follows ever runs.
fn delete_file_blocking(
    root: &FsRoot,
    audit: &crate::audit::AuditSink,
    identity: Option<crate::audit::Identity>,
    query: &PathQuery,
) -> Response {
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
    //
    // A *`parent`-based* postcondition check (`named.starts_with(&parent)`,
    // below, after `named` is built) is a different check from the
    // `root`-based one just ruled out — it does not rule out `..` either
    // (`join("..")` on Unix does not collapse, so `named` is literally
    // `parent/..` and does start with `parent`), so this guard stays
    // load-bearing for `..` regardless.
    if name == ".." {
        return fs_error_response(FsError::Escapes);
    }

    // `.` is the other value `FsRoot::components` never runs `check_component`
    // over, and it fails the same way `..` did above, through a different
    // mechanism: `PathBuf::join` absorbs a trailing `.` on a verbatim path,
    // and `resolve_existing`'s result *is* verbatim on Windows (`canonicalize`
    // returns `\\?\C:\...`). So for `path=link/.` where `link` is a
    // same-root symlink, `parent = resolve_existing("link")` is the link's
    // *followed target*, and `parent.join(".")` collapses right back onto
    // that target — reproduced on this box: `canonicalize(link).join(".") ==
    // canonicalize(link)`, both the link's target, with no `.` component
    // surviving to distinguish them. That reintroduces exactly the defect
    // this handler exists to avoid, through a spelling `..`'s guard does not
    // cover. `Malformed`, not `Escapes`: naming an entry as `.` is not an
    // escape, just not a name.
    if name == "." {
        return fs_error_response(FsError::Malformed(
            "delete target must name an entry, not `.`",
        ));
    }

    let parent = match root.resolve_existing(parent_rel) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };
    let named = parent.join(name);

    // `named` above assumes `join` appends exactly one ordinary component. It
    // does not: `PathBuf::join` discards `parent` entirely for an argument
    // carrying a Windows drive prefix (verified: `Path::new(r"C:\root\app")
    // .join("C:evil")` is `"C:evil"`, `parent` gone). A `name` containing `:`
    // would drop the jail-resolved parent and hand `remove_file` an arbitrary
    // drive-relative path.
    //
    // Checked as a postcondition of the join rather than as a precondition on
    // `name`, deliberately: `platform::check_component` already rejects `:`
    // (for Alternate Data Streams, an unrelated reason), and an earlier
    // version of this guard called it here directly — but that only restates
    // the dependency, it does not remove it. Relax `:` in `check_component`
    // for its own purpose (a plausible future change, since Unix has no
    // Alternate Data Streams to protect) and a precondition re-running the
    // same rule is defeated identically; this postcondition is not, because
    // it does not consult that rule at all — it only asks whether the result
    // of the join still extends `parent`, which is true or false independent
    // of why `check_component` currently rejects `:`.
    //
    // Not currently reachable from any request that also passes the
    // full-path resolution at the top of this function: that resolution
    // already runs `check_component` over every component including this
    // one, so `path=app/C:evil` is refused there today regardless of this
    // line. Kept anyway as the thing that keeps working if that upstream
    // check's scope narrows for a reason that has nothing to do with this
    // handler.
    if !named.starts_with(&parent) {
        return fs_error_response(FsError::Escapes);
    }

    // Same reservation `create_upload` enforces on the way in and `list`
    // enforces on the way out: without it, a predictable session id let an
    // `fs.write` token delete another caller's in-progress `.part` file —
    // the open staging handle survives the removal on Windows, so the
    // upload later fails `complete` with an opaque 500 instead of the
    // caller ever seeing a clean refusal.
    if let Some(response) = refuse_if_reserved(root, &named) {
        return response;
    }

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
        Ok(()) => {
            // `query.path` as the caller spelled it, not a canonical form —
            // unlike `upload.start`/`upload.complete`, which need to agree on
            // one spelling to correlate two events for the *same* session,
            // this is the only event this deletion will ever produce, so
            // there is nothing to correlate it with. Recording the raw
            // request path here also matches what this handler actually acts
            // on: `delete_file_blocking`'s own doc comment above explains why
            // it deliberately targets the named entry (`query.path`'s own
            // final component) rather than whatever a symlink resolves to.
            audit.record(
                crate::audit::AuditEvent::new("fs.delete")
                    .with_identity(identity)
                    .with_route("DELETE /api/v1/fs/file")
                    .with_file(query.path.clone(), None),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "delete-failed",
            &format!("could not remove the file: {e}"),
        ),
    }
}

/// `GET /api/v1/fs/stat` — one entry, file or directory.
///
/// Resolving the path and reading its metadata are both blocking I/O. Same
/// convention as `list`/`list_blocking`, `download`/`download_blocking`, and
/// `delete_file`/`delete_file_blocking` above (`src/execution/executor.rs:209-215`):
/// run it on `spawn_blocking` so a slow filesystem can never starve the tokio
/// worker pool that also runs `/health` and the accept loop. This was, until
/// now, the one route in this module that called `resolve_existing` and
/// `std::fs::metadata` directly on the async runtime.
pub async fn stat(State(state): State<AppState>, Query(query): Query<PathQuery>) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };

    match tokio::task::spawn_blocking(move || stat_blocking(&root, &query)).await {
        Ok(response) => response,
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stat-failed",
            "reading the entry failed unexpectedly",
        ),
    }
}

/// The synchronous body of `stat`. Blocking throughout — see `stat`, which
/// runs this via `spawn_blocking` rather than directly on the async runtime.
fn stat_blocking(root: &FsRoot, query: &PathQuery) -> Response {
    let resolved = match root.resolve_existing(&query.path) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };

    // Same reservation `create_upload` enforces on the way in and `list`
    // enforces on the way out: a caller must not be able to read an
    // in-progress upload's staging file, or its metadata, by guessing a
    // session id — session ids are a predictable per-process counter.
    if let Some(response) = refuse_if_reserved(root, &resolved) {
        return response;
    }

    let meta = match std::fs::metadata(&resolved) {
        Ok(meta) => meta,
        Err(_) => return fs_error_response(FsError::NotFound),
    };

    // `file_identity` is unused here but keeps the platform module honest about
    // being the only place that reaches for OS-specific metadata.
    let _ = platform::file_identity(&meta);

    Json(entry_for(root, &resolved, &meta, None)).into_response()
}

/// Body of `POST /api/v1/fs/uploads`.
#[derive(Debug, Deserialize)]
pub struct CreateUpload {
    /// Destination, root-relative.
    pub path: String,
    /// Total size the caller intends to send.
    pub size: u64,
    /// SHA-256 of the whole file, lowercase hex.
    pub sha256: String,
}

/// Reply describing a session's current state.
#[derive(Debug, Serialize)]
pub struct UploadState {
    pub upload_id: String,
    /// Next byte the server expects.
    pub offset: u64,
    /// Largest chunk the caller may send.
    ///
    /// Advertised rather than assumed: the ceiling depends on the path the
    /// request travelled, and a client that guesses will guess wrong on one of
    /// them.
    pub chunk_size: usize,
}

/// Map an upload refusal onto HTTP.
fn upload_error_response(error: crate::fs::UploadError) -> Response {
    use crate::fs::UploadError;
    match error {
        UploadError::NotFound => error_response(
            StatusCode::NOT_FOUND,
            "no-such-upload",
            "unknown, completed, or expired upload session",
        ),
        UploadError::OffsetMismatch { expected } => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "offset-mismatch",
                "message": "chunk does not continue from the session offset",
                "offset": expected,
            })),
        )
            .into_response(),
        UploadError::Conflict => error_response(
            StatusCode::CONFLICT,
            "destination-busy",
            "another upload session is already targeting this path",
        ),
        UploadError::TooLarge => error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "chunk-too-large",
            "chunk exceeds the advertised chunk_size",
        ),
        // Distinct code from `TooLarge`: that one is "this single chunk is
        // bigger than the configured chunk_size", a protocol-level ceiling
        // unrelated to any particular session. This one is "the bytes this
        // session has now received, plus this chunk, exceed what *this*
        // session declared at creation" — a session-level contract
        // violation. Conflating the two would leave a client unable to tell
        // "resize your chunk" from "abort, you have already overrun what
        // you said you'd send".
        UploadError::SizeExceeded => error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "declared-size-exceeded",
            "chunk would exceed the size declared when the session was created",
        ),
        // Distinct from `Conflict` (409, same path contested): this is a
        // capacity refusal, not a path collision, so it gets its own code and
        // status — a client should back off and retry rather than pick a
        // different destination.
        UploadError::TooManySessions => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too-many-uploads",
            "too many upload sessions are open; finish or cancel one and retry",
        ),
        UploadError::Checksum {
            expected, actual, ..
        } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "checksum-mismatch",
                "message": "the assembled bytes do not match the declared digest",
                "expected": expected,
                "actual": actual,
            })),
        )
            .into_response(),
        // 507 vs. 500 decided on the numeric OS error code, never on
        // `detail`'s text: an earlier version matched substrings like
        // "space" or "full" in the rendered message, which is
        // locale-dependent (the OS renders `io::Error`'s `Display` in the
        // system locale) and would also trip on an ordinary error that
        // happens to name a directory "full". For a transfer API this
        // distinction is worth making — "the disk is full, retry after
        // freeing space" and "the server has a bug, file a report" are two
        // answers a client acts on completely differently, and a
        // `sha256`-verified GB-scale upload is exactly where a full disk is
        // a likely failure, not an edge case.
        //
        // `platform::is_out_of_space` takes `&io::Error`, which this arm no
        // longer has — `UploadError::Io` carries only the numeric
        // `raw_os_error`, not the original error, so the error is
        // reconstructed from that code purely to hand it to the one
        // existing predicate rather than duplicating its comparison here.
        UploadError::Io {
            detail,
            raw_os_error,
        } => {
            let out_of_space = raw_os_error
                .map(std::io::Error::from_raw_os_error)
                .is_some_and(|e| platform::is_out_of_space(&e));
            let status = match out_of_space {
                true => StatusCode::INSUFFICIENT_STORAGE,
                false => StatusCode::INTERNAL_SERVER_ERROR,
            };
            error_response(status, "io-error", &detail)
        }
    }
}

/// `POST /api/v1/fs/uploads` — open a session.
///
/// Resolving the destination, creating the staging directory, and opening the
/// staging file (`UploadStore::create`) are all blocking I/O — same
/// convention as `list`/`list_blocking` and `download`/`download_blocking`
/// above (`src/execution/executor.rs:209-215`): run it on `spawn_blocking` so
/// a slow filesystem can never starve the tokio worker pool that also runs
/// `/health` and the accept loop.
pub async fn create_upload(
    State(state): State<AppState>,
    identity: Option<axum::Extension<crate::audit::Identity>>,
    Json(body): Json<CreateUpload>,
) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };
    let uploads = state.uploads.clone();
    let audit = state.audit.clone();
    let identity = identity.map(|axum::Extension(id)| id);

    match tokio::task::spawn_blocking(move || {
        create_upload_blocking(&root, &uploads, &audit, identity, body)
    })
    .await
    {
        Ok(response) => response,
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "create-upload-failed",
            "creating the upload session failed unexpectedly",
        ),
    }
}

/// The synchronous body of `create_upload`. Blocking throughout — see
/// `create_upload`, which runs this via `spawn_blocking` rather than directly
/// on the async runtime. `audit` is threaded in as a parameter rather than
/// recorded back on the async side, because `AuditSink::record` itself does
/// blocking file I/O (open/write/flush) — recording it here keeps that I/O on
/// the same blocking-pool thread as everything else this function does,
/// instead of adding a second blocking call directly on the tokio runtime.
fn create_upload_blocking(
    root: &FsRoot,
    uploads: &crate::fs::UploadStore,
    audit: &crate::audit::AuditSink,
    identity: Option<crate::audit::Identity>,
    body: CreateUpload,
) -> Response {
    // Validate the destination before claiming anything, so a bad path cannot
    // leave a staging file or a claim behind.
    let resolved = match root.resolve_for_create(&body.path) {
        Ok(path) => path,
        Err(error) => return fs_error_response(error),
    };

    // Canonical, not the raw request string: `body.path` is whatever the
    // caller spelled it (`./app/x.bin`, `app\x.bin`, `app//x.bin` — the last
    // one is refused by `resolve_for_create` itself, since `check_component`
    // rejects the empty component it produces). Two different spellings of
    // one destination discarding `resolved` here (an earlier version did)
    // would claim it under two different keys, so both sessions proceed,
    // both eventually `complete`, and both `rename` onto the same file —
    // exactly the last-writer-wins data loss `UploadStore`'s destination
    // claim exists to prevent. `root.relative` on the path `resolve_for_create`
    // already produced is this function's only source of that canonical
    // form.
    let dest_rel = match root.relative(&resolved) {
        Some(rel) => rel,
        // `resolve_for_create` already established that `resolved` is under
        // `root`, so `relative` returning `None` here should not be
        // reachable — handled rather than unwrapped so a future change to
        // either function cannot turn this into a panic.
        None => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "path-resolution-failed",
                "could not compute the destination's canonical path",
            )
        }
    };

    // The upload staging directory is reserved: `list` deliberately hides it
    // (`src/api/fs.rs`'s `walk`), so a file published inside it could never be
    // reported back through this API, and a destination shaped like
    // `up-{serial:016x}.part` could collide with a future session's own
    // staging file, making that session's `create_new` fail for a reason
    // that has nothing to do with it.
    if is_reserved_path(&dest_rel) {
        return reserved_path_response();
    }

    // Checked before the digest/size validation below, and before claiming
    // anything: a real directory at the destination is not something
    // `rename` at `complete` time can replace (`EISDIR`/`ENOTDIR`), so
    // finding out only then means the client has already uploaded the whole
    // file for nothing. `symlink_metadata` (lstat), not `metadata` (stat): a
    // *symlink* to a directory is not refused here — `rename` never follows
    // a symlink on either operand (see `complete_upload_blocking`'s doc
    // comment), so it simply replaces the link rather than failing.
    if let Ok(meta) = std::fs::symlink_metadata(&resolved) {
        if meta.is_dir() {
            return error_response(
                StatusCode::CONFLICT,
                "destination-is-directory",
                "the destination path already exists as a directory",
            );
        }
    }

    if body.sha256.len() != 64 || !body.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "bad-digest",
            "sha256 must be 64 hexadecimal characters",
        );
    }

    // Cloned before the move below: `dest_rel` is canonical (see the comment
    // on its own `let` above), and the audit event must record that same
    // canonical form rather than `body.path` as spelled by the caller — a
    // session's `start` and `complete` events need to agree on `file` so the
    // two can be correlated even when the request used a different spelling
    // (`./x.bin` vs. `x.bin`) than `complete`'s response does.
    let dest_for_audit = dest_rel.clone();

    // Opportunistic reclamation used to live inside `UploadStore::create`
    // itself, unaudited (see that method's own doc comment for why it moved).
    // Sweeping here, immediately before `create`, preserves the ordering the
    // old internal call existed for: stale capacity is reclaimed before the
    // cap check inside `create` runs, so a session old enough to matter is
    // freed the moment somebody next asks for a new one.
    sweep_expired_uploads(uploads, audit, crate::fs::SESSION_TTL);

    // Machine-wide staging follows the destination rather than sitting in one
    // enumerable directory, so no startup pass can reclaim what a previous run
    // left there. Reclaiming it here — at the one moment this process knows a
    // destination's staging directory — is what keeps that path bounded; see
    // `sweep_orphan_parts`'s doc for why it cannot be done globally.
    if root.jail_path().is_none() {
        let staging = crate::fs::UploadStore::staging_dir(root, &resolved);
        // `SESSION_TTL`, not zero: this staging directory is shared with every
        // other upload heading for the same destination directory, and one of
        // those may be in flight right now. `sweep_expired_uploads` above has
        // already reclaimed anything a live session no longer owns, so a
        // `.part` younger than the TTL still belongs to somebody.
        record_orphans(
            &crate::fs::sweep_orphan_parts_in(&staging, crate::fs::SESSION_TTL),
            audit,
        );
    }

    match uploads.create(
        root,
        &resolved,
        dest_rel,
        body.size,
        body.sha256.to_ascii_lowercase(),
    ) {
        Ok(upload_id) => {
            audit.record(
                crate::audit::AuditEvent::new("upload.start")
                    .with_identity(identity)
                    .with_route("POST /api/v1/fs/uploads")
                    .with_file(dest_for_audit, Some(body.size))
                    .with_upload_id(upload_id.clone()),
            );
            (
                StatusCode::CREATED,
                Json(UploadState {
                    upload_id,
                    offset: 0,
                    chunk_size: uploads.chunk_size(),
                }),
            )
                .into_response()
        }
        Err(error) => upload_error_response(error),
    }
}

/// `GET /api/v1/fs/uploads/{id}` — where to resume from.
///
/// Reads only in-memory session state (`UploadStore::offset`), so unlike the
/// other four upload routes this never touches disk and stays directly on the
/// async runtime rather than going through `spawn_blocking`.
pub async fn upload_status(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    if state.fs.is_none() {
        return fs_not_enabled();
    }
    match state.uploads.offset(&id) {
        Some(offset) => Json(UploadState {
            upload_id: id,
            offset,
            chunk_size: state.uploads.chunk_size(),
        })
        .into_response(),
        None => upload_error_response(crate::fs::UploadError::NotFound),
    }
}

/// `PATCH /api/v1/fs/uploads/{id}` — append one chunk.
///
/// The offset comes from `Content-Range` rather than the body, so a chunk that
/// arrives twice is refused by position instead of being appended again.
///
/// Writing the chunk to the staging file (`UploadStore::append`) is blocking
/// disk I/O — `spawn_blocking`, same convention as the other routes here. The
/// route this handler serves also carries `DefaultBodyLimit::max(MAX_CHUNK_SIZE)`
/// (`src/api/router.rs`), raising axum-core's own 2 MiB default so a chunk at
/// the advertised `chunk_size` (4 MiB) reaches this handler at all, rather than
/// being cut off by axum before `append`'s own `TooLarge` check ever runs.
pub async fn append_chunk(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if state.fs.is_none() {
        return fs_not_enabled();
    }

    let offset = match headers
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range_start)
    {
        Some(offset) => offset,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad-content-range",
                "a Content-Range header of the form 'bytes <start>-<end>/<total>' is required",
            )
        }
    };

    let uploads = state.uploads.clone();
    match tokio::task::spawn_blocking(move || append_chunk_blocking(&uploads, &id, offset, &body))
        .await
    {
        Ok(response) => response,
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "append-failed",
            "writing the chunk failed unexpectedly",
        ),
    }
}

/// The synchronous body of `append_chunk`. Blocking throughout — see
/// `append_chunk`, which runs this via `spawn_blocking` rather than directly
/// on the async runtime.
fn append_chunk_blocking(
    uploads: &crate::fs::UploadStore,
    id: &str,
    offset: u64,
    body: &[u8],
) -> Response {
    match uploads.append(id, offset, body) {
        Ok(next) => Json(UploadState {
            upload_id: id.to_string(),
            offset: next,
            chunk_size: uploads.chunk_size(),
        })
        .into_response(),
        Err(error) => upload_error_response(error),
    }
}

/// The start offset named by a `Content-Range` request header.
pub fn parse_content_range_start(header: &str) -> Option<u64> {
    let spec = header.trim().strip_prefix("bytes ")?;
    let (range, _total) = spec.split_once('/')?;
    let (start, _end) = range.split_once('-')?;
    start.trim().parse().ok()
}

/// `POST /api/v1/fs/uploads/{id}/complete` — verify and publish.
///
/// Verifying the checksum, resolving the destination, creating its parent
/// directory, and the rename itself are all blocking I/O — `spawn_blocking`,
/// same convention as the other routes here.
pub async fn complete_upload(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    identity: Option<axum::Extension<crate::audit::Identity>>,
) -> Response {
    let Some(root) = state.fs.clone() else {
        return fs_not_enabled();
    };
    let uploads = state.uploads.clone();
    let audit = state.audit.clone();
    let identity = identity.map(|axum::Extension(id)| id);

    match tokio::task::spawn_blocking(move || {
        complete_upload_blocking(&root, &uploads, &audit, identity, &id)
    })
    .await
    {
        Ok(response) => response,
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "complete-upload-failed",
            "publishing the upload failed unexpectedly",
        ),
    }
}

/// The synchronous body of `complete_upload`. Blocking throughout — see
/// `complete_upload`, which runs this via `spawn_blocking` rather than
/// directly on the async runtime. `audit` is threaded in for the same reason
/// `create_upload_blocking` takes it: `AuditSink::record` is itself blocking
/// I/O, and this function already runs on the blocking pool.
///
/// `UploadStore::take_for_complete` deliberately keeps `finished.dest_rel`'s
/// claim alive on success (see its doc comment), so every exit path below
/// calls `release_destination` exactly once — whether the rename lands or
/// not — instead of relying on `take_for_complete` to have released it
/// already.
fn complete_upload_blocking(
    root: &FsRoot,
    uploads: &crate::fs::UploadStore,
    audit: &crate::audit::AuditSink,
    identity: Option<crate::audit::Identity>,
    id: &str,
) -> Response {
    let finished = match uploads.take_for_complete(id) {
        Ok(finished) => finished,
        // `take_for_complete` already removed the session from the map before
        // returning this error (`src/fs/transfer.rs`'s checksum-mismatch
        // branch), so this is terminal for the session, not a state a later
        // sweep could also see and double-record.
        Err(error) => {
            if let crate::fs::UploadError::Checksum { ref dest_rel, .. } = error {
                audit.record(
                    crate::audit::AuditEvent::new("upload.rejected")
                        .with_identity(identity)
                        .with_route("POST /api/v1/fs/uploads/{id}/complete")
                        .with_file(dest_rel.clone(), None)
                        .with_digest(false)
                        .with_upload_id(id),
                );
            }
            return upload_error_response(error);
        }
    };

    // From here on, `take_for_complete` has already removed the session and
    // the destination's claim survives only until `release_destination` is
    // called below — so every exit path, success or failure, is terminal for
    // this upload and must leave its own event. `upload.failed` (distinct
    // from `upload.rejected` above): these are IO failures on the server's
    // own publication step, not a contract violation by the caller.
    let destination = match root.resolve_for_create(&finished.dest_rel) {
        Ok(path) => path,
        Err(error) => {
            std::fs::remove_file(&finished.part_path).ok();
            uploads.release_destination(&finished.dest_rel);
            let response = fs_error_response(error);
            audit.record(
                crate::audit::AuditEvent::new("upload.failed")
                    .with_identity(identity)
                    .with_route("POST /api/v1/fs/uploads/{id}/complete")
                    .with_file(finished.dest_rel.clone(), Some(finished.bytes))
                    .with_denial(response.status().as_u16(), "destination-resolve-failed")
                    .with_upload_id(id),
            );
            return response;
        }
    };

    if let Some(parent) = destination.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            std::fs::remove_file(&finished.part_path).ok();
            uploads.release_destination(&finished.dest_rel);
            // Consults the same `platform::is_out_of_space` predicate
            // `upload_error_response` uses for `UploadError::Io`, rather
            // than a second, undifferentiated 500 — a full disk publishing
            // a GB-scale, checksum-verified upload is exactly the likely
            // failure this distinction exists for, not an edge case, and it
            // would be dishonest to make it 507 for `append`'s writes but
            // not for the one this function does itself.
            let status = match platform::is_out_of_space(&e) {
                true => StatusCode::INSUFFICIENT_STORAGE,
                false => StatusCode::INTERNAL_SERVER_ERROR,
            };
            audit.record(
                crate::audit::AuditEvent::new("upload.failed")
                    .with_identity(identity)
                    .with_route("POST /api/v1/fs/uploads/{id}/complete")
                    .with_file(finished.dest_rel.clone(), Some(finished.bytes))
                    .with_denial(status.as_u16(), "directory-creation-failed")
                    .with_upload_id(id),
            );
            return error_response(
                status,
                "io-error",
                &format!("could not create the destination directory: {e}"),
            );
        }
    }

    // Rename is the publication step: until it runs the destination holds the
    // old file or nothing, never a half-written one. `rename` never follows a
    // symlink on either operand, so even if `destination`'s final component
    // became a symlink between the `resolve_for_create` above and this call,
    // the rename simply replaces that directory entry rather than writing
    // through it — no additional guard is needed for that case.
    if let Err(e) = std::fs::rename(&finished.part_path, &destination) {
        std::fs::remove_file(&finished.part_path).ok();
        uploads.release_destination(&finished.dest_rel);
        // Same reasoning as the `create_dir_all` failure above: consult the
        // predicate rather than always answering 500.
        let status = match platform::is_out_of_space(&e) {
            true => StatusCode::INSUFFICIENT_STORAGE,
            false => StatusCode::INTERNAL_SERVER_ERROR,
        };
        audit.record(
            crate::audit::AuditEvent::new("upload.failed")
                .with_identity(identity)
                .with_route("POST /api/v1/fs/uploads/{id}/complete")
                .with_file(finished.dest_rel.clone(), Some(finished.bytes))
                .with_denial(status.as_u16(), "rename-failed")
                .with_upload_id(id),
        );
        return error_response(
            status,
            "io-error",
            &format!("could not publish the upload: {e}"),
        );
    }
    uploads.release_destination(&finished.dest_rel);

    audit.record(
        crate::audit::AuditEvent::new("upload.complete")
            .with_identity(identity)
            .with_route("POST /api/v1/fs/uploads/{id}/complete")
            .with_file(finished.dest_rel.clone(), Some(finished.bytes))
            .with_digest(true)
            .with_upload_id(id),
    );

    Json(serde_json::json!({
        "path": finished.dest_rel,
        "size": finished.bytes,
        "sha256": finished.digest,
    }))
    .into_response()
}

/// `DELETE /api/v1/fs/uploads/{id}` — abandon a session.
///
/// Removing the staging file (`UploadStore::cancel`) is blocking I/O —
/// `spawn_blocking`, same convention as the other routes here.
pub async fn cancel_upload(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    identity: Option<axum::Extension<crate::audit::Identity>>,
) -> Response {
    if state.fs.is_none() {
        return fs_not_enabled();
    }
    let uploads = state.uploads.clone();
    let audit = state.audit.clone();
    let identity = identity.map(|axum::Extension(id)| id);
    match tokio::task::spawn_blocking(move || {
        cancel_upload_blocking(&uploads, &audit, identity, &id)
    })
    .await
    {
        Ok(response) => response,
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cancel-failed",
            "cancelling the upload failed unexpectedly",
        ),
    }
}

/// The synchronous body of `cancel_upload`. Blocking throughout — see
/// `cancel_upload`, which runs this via `spawn_blocking` rather than directly
/// on the async runtime.
///
/// An explicit cancel is as terminal as a sweep-driven expiry, and without a
/// recorded event here the trail would show a session starting and then
/// nothing — indistinguishable from one still in progress. `UploadStore::cancel`
/// returns `(destination, bytes_received)` for the same reason `sweep` returns
/// `(id, destination, bytes_received)`: the primary question an audit trail
/// answers is "what happened to this file", and a reader grepping for a path
/// would otherwise see `upload.start` and then silence for a cancelled
/// session, the same failure this task's sweep-driven `upload.expired` event
/// exists to rule out.
fn cancel_upload_blocking(
    uploads: &crate::fs::UploadStore,
    audit: &crate::audit::AuditSink,
    identity: Option<crate::audit::Identity>,
    id: &str,
) -> Response {
    match uploads.cancel(id) {
        Some((destination, bytes)) => {
            audit.record(
                crate::audit::AuditEvent::new("upload.cancel")
                    .with_identity(identity)
                    .with_route("DELETE /api/v1/fs/uploads/{id}")
                    .with_file(destination, Some(bytes))
                    .with_upload_id(id),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        None => upload_error_response(crate::fs::UploadError::NotFound),
    }
}

/// Drop upload sessions idle past `ttl`, recording a terminal event for each.
///
/// A session that starts and never ends leaves a trail showing only a
/// beginning. Sweeping silently would make every abandoned transfer look, in
/// the log, exactly like one still in progress.
///
/// Takes `uploads`/`audit` directly rather than `&AppState`: this is the only
/// state either caller needs, and one of those callers is
/// `create_upload_blocking`, which already holds both as separate parameters
/// (see that function's own signature) rather than an `AppState`. Matching
/// shapes means the opportunistic sweep that used to live inside
/// `UploadStore::create` can call this exactly the way the periodic sweeper
/// in `main.rs` does, instead of needing a second, `AppState`-shaped variant.
///
/// Plain and synchronous rather than `async` or `spawn_blocking`-wrapped
/// itself: `UploadStore::sweep` removes staging files and `audit.record`
/// writes to a file, both blocking I/O, but which runtime this runs on is the
/// caller's decision to make — a periodic task on the async runtime needs to
/// wrap this in `spawn_blocking` (see `main.rs`); `create_upload_blocking`
/// calls it directly because it is already running on the blocking pool
/// itself; a test calling it directly from a `#[tokio::test]` body does not
/// need that ceremony to observe what it records.
///
/// The recorded event carries no `route` (there is no request driving this —
/// it runs off a timer, or opportunistically off an unrelated request) and no
/// `identity` (the session was opened by some caller, long since
/// disconnected; nothing here still knows who that was). Every other event
/// this task adds carries both.
pub fn sweep_expired_uploads(
    uploads: &crate::fs::UploadStore,
    audit: &crate::audit::AuditSink,
    ttl: std::time::Duration,
) -> usize {
    let expired = uploads.sweep(ttl);
    for (id, destination, bytes) in &expired {
        audit.record(
            crate::audit::AuditEvent::new("upload.expired")
                .with_file(destination.clone(), Some(*bytes))
                .with_upload_id(id.clone()),
        );
    }
    expired.len()
}

/// Remove `.part` staging files left behind by a previous run, recording a
/// terminal event for each.
///
/// Thin wrapper over `crate::fs::sweep_orphan_parts`: that function stays
/// audit-agnostic (it lives in `crate::fs`, which has no `AuditSink`), and
/// this is where the recording happens instead — same split as
/// `sweep_expired_uploads` over `UploadStore::sweep`.
///
/// The recorded `upload.orphaned` event carries `upload_id` but not `file`:
/// the destination lived only in the in-memory session a restart already
/// discarded before this ever runs, so there is nothing left to attach as
/// `file`. It also carries neither `route` nor `identity`, for the same
/// reason `upload.expired` does not — nothing here was driven by a request.
/// A reader correlates an orphan back to the `upload.start` that does have
/// the destination by matching `upload_id` between the two events.
pub fn sweep_orphaned_uploads(root: &FsRoot, audit: &crate::audit::AuditSink) -> usize {
    let removed = crate::fs::sweep_orphan_parts(root);
    record_orphans(&removed, audit);
    removed.len()
}

/// Record one `upload.orphaned` per reclaimed staging file.
///
/// Shared by the startup/interval sweep above and the per-destination sweep in
/// `create_upload_blocking`, which is the only reclaim path machine-wide scope
/// has. One builder in one place: an earlier round of this work found three
/// terminal upload paths that recorded nothing, and two callers assembling the
/// same event by hand is how a fourth would appear.
fn record_orphans(removed: &[(String, u64)], audit: &crate::audit::AuditSink) {
    for (upload_id, bytes) in removed {
        // Built without `with_file`: that builder always sets `file`
        // alongside `bytes`, and this event deliberately carries no `file` —
        // there is nothing left here to attach one from. `bytes` is set
        // directly on the field instead (both `pub` within the crate).
        let mut event =
            crate::audit::AuditEvent::new("upload.orphaned").with_upload_id(upload_id.clone());
        event.bytes = Some(*bytes);
        audit.record(event);
    }
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

    /// `refuse_if_reserved`'s `None` arm — `root.relative` failing to strip
    /// the root prefix — has no route to it through any HTTP request: every
    /// call site passes a path already established to be under `root`. That
    /// is exactly why it needs a direct test: nothing at the HTTP level can
    /// ever exercise it, so a silent flip from this 500 to "not reserved,
    /// proceed" (fail-open, serving or removing a file this check exists to
    /// refuse) would ship with the whole suite green.
    #[test]
    fn refuse_if_reserved_fails_closed_when_relative_cannot_be_computed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = FsRoot::new(dir.path()).expect("root");

        // A path with no relationship to `root` at all — `relative` returns
        // `None` for it the same way it would for any path this function's
        // callers should never be able to construct.
        let unrelated = std::env::temp_dir().join("definitely-not-under-the-root");

        let response =
            refuse_if_reserved(&root, &unrelated).expect("None must refuse, not silently allow");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn content_range_yields_its_start_offset() {
        assert_eq!(
            parse_content_range_start("bytes 0-4194303/209715200"),
            Some(0)
        );
        assert_eq!(
            parse_content_range_start("bytes 4194304-8388607/209715200"),
            Some(4194304)
        );
        assert_eq!(parse_content_range_start("bytes 0-4"), None);
        assert_eq!(parse_content_range_start("items 0-4/9"), None);
    }

    /// `platform::is_out_of_space`'s own unit tests (`src/fs/platform.rs`)
    /// prove the predicate is correct against the raw codes; this proves
    /// `upload_error_response` actually *wires* it in — that a
    /// `raw_os_error` meaning "out of space" reaches `507`, an unrelated
    /// one stays `500`, and no code at all (the `poisoned()` case, which
    /// never had an underlying `io::Error`) also stays `500`.
    #[test]
    fn io_error_maps_to_507_only_when_the_raw_code_means_out_of_space() {
        use crate::fs::UploadError;

        #[cfg(unix)]
        let out_of_space_code = libc::ENOSPC;
        #[cfg(windows)]
        let out_of_space_code = 112; // ERROR_DISK_FULL

        let out_of_space = upload_error_response(UploadError::Io {
            detail: "no space left on device".to_string(),
            raw_os_error: Some(out_of_space_code),
        });
        assert_eq!(out_of_space.status(), StatusCode::INSUFFICIENT_STORAGE);

        // A real but unrelated OS error must not be mistaken for it.
        let unrelated = upload_error_response(UploadError::Io {
            detail: "permission denied".to_string(),
            raw_os_error: Some(13),
        });
        assert_eq!(unrelated.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // No OS code at all (e.g. `poisoned()`'s synthetic error) must not
        // default to the space-exhausted branch either.
        let no_code = upload_error_response(UploadError::Io {
            detail: "internal lock poisoned".to_string(),
            raw_os_error: None,
        });
        assert_eq!(no_code.status(), StatusCode::INTERNAL_SERVER_ERROR);
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

        // Resolved through the root rather than assembled with `join`, which
        // is what `list_blocking` does and what `walk` documents as its
        // precondition. Handing `walk` a raw `dir.path().join("app")` made
        // this test fail on macOS for a reason that had nothing to do with
        // permissions: `FsRoot::new` canonicalises, `/var/folders/…` becomes
        // `/private/var/folders/…`, and `root.relative` (a pure
        // `strip_prefix`) then returned `None` for every entry — so the walk
        // collected nothing at all and the assertion below read as "the
        // unreadable subdirectory aborted the walk". It had not; the test was
        // asking about a tree the root could not name. Linux hid this because
        // `/tmp` canonicalises to itself.
        let base = root.resolve_existing("app").expect("app resolves");

        let mut collected: Vec<(String, std::path::PathBuf, std::fs::Metadata)> = Vec::new();
        let result = walk(&root, &base, true, &mut collected);

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

    /// Direct check of the postcondition `delete_file_blocking` relies on to
    /// catch a drive-prefix `name` — no HTTP request reaches this today (the
    /// full-path resolution ahead of it already refuses `:` via
    /// `platform::check_component`, see
    /// `delete_refuses_a_path_component_containing_a_colon` in
    /// `tests/fs_api.rs`), so this pins the raw `Path` arithmetic the guard
    /// depends on instead of contorting an HTTP test to reach it.
    ///
    /// Deliberately does not call `platform::check_component` at all: the
    /// whole point of checking this as a postcondition of `join` is that it
    /// holds independent of whatever `check_component` currently rejects.
    ///
    /// `#[cfg(windows)]`: the discarding behavior is specific to Windows path
    /// prefixes (a drive letter, or a UNC/verbatim root). `:` has no special
    /// meaning to `Path` on Unix, so `join` there only ever appends.
    #[cfg(windows)]
    #[test]
    fn postcondition_catches_a_drive_prefix_join_even_without_check_component() {
        let parent = std::path::Path::new(r"C:\root\app");
        let named = parent.join("C:evil");
        assert!(
            !named.starts_with(parent),
            "a drive-prefixed name must make `join` discard `parent`, or this guard has nothing to catch"
        );

        // The ordinary case the postcondition must not disturb: a plain
        // filename still extends `parent` as expected.
        let ordinary = parent.join("real.txt");
        assert!(ordinary.starts_with(parent));
    }
}
