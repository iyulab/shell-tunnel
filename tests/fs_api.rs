//! HTTP-level tests for the filesystem API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use shell_tunnel::api::handlers::AppState;
use shell_tunnel::api::router::create_router_with_state;
use shell_tunnel::FsRoot;
use tower::ServiceExt;

/// A temp directory with `app/config.json` in it, wired into an app state.
fn state_with_files(files: &[(&str, &[u8])]) -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, body) in files {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&path, body).expect("write");
    }
    let root = FsRoot::new(dir.path()).expect("root");
    (dir, AppState::new().with_fs_root(root))
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn stat_reports_a_file() {
    let (_dir, state) = state_with_files(&[("app/config.json", b"hello")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/stat?path=app/config.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["path"], "app/config.json");
    assert_eq!(json["size"], 5);
    assert_eq!(json["is_dir"], false);
    // Not just `.is_null()`: `Value`'s `Index` returns `Value::Null` for a
    // missing key too, so that assertion would stay green even if the
    // `skip_serializing_if` on `FsEntry::sha256` were deleted. The key must be
    // genuinely absent.
    assert!(!json.as_object().expect("object").contains_key("sha256"));
}

#[tokio::test]
async fn stat_refuses_a_path_outside_the_root() {
    let (_dir, state) = state_with_files(&[("app/config.json", b"hello")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/stat?path=../outside.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert_eq!(json["error"], "path-escapes-root");
}

#[tokio::test]
async fn stat_reports_a_missing_file_as_not_found() {
    let (_dir, state) = state_with_files(&[("app/config.json", b"hello")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/stat?path=app/absent.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = body_json(response).await;
    assert_eq!(json["error"], "not-found");
}

#[tokio::test]
async fn stat_refuses_a_malformed_path_with_bad_path() {
    // The `Malformed` arc (400 `bad-path`) is otherwise only exercised by
    // `FsRoot`'s own unit tests, which cover the jail, not this handler —
    // nothing at the HTTP level proves `fs_error_response` wires it to 400
    // rather than, say, 500.
    let (_dir, state) = state_with_files(&[("app/config.json", b"hello")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/stat?path=/etc/passwd")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert_eq!(json["error"], "bad-path");
}

#[tokio::test]
async fn the_fs_api_is_off_without_a_root() {
    let app = create_router_with_state(AppState::new());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/stat?path=app/config.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert_eq!(json["error"], "fs-not-enabled");
}

/// Build a secure router around `state`, pre-registered with `token` holding
/// exactly `caps`, with mock connection info attached for the rate limiter.
///
/// `every_fs_route_declares_a_capability` below checks the *table*; it cannot
/// catch a route whose `.route()` string and table key are wrong together
/// (the route silently falls through to `Authenticated`, open to any valid
/// token). Only a live request through the real router closes that gap.
fn secure_app_with_token(state: AppState, token: &str, caps: &[&str]) -> axum::Router {
    use axum::extract::connect_info::MockConnectInfo;
    use shell_tunnel::api::router::{create_secure_router, SecurityConfig};
    use shell_tunnel::security::CapabilitySet;
    use std::net::SocketAddr;

    let (app, store, _rate_limiter) = create_secure_router(state, SecurityConfig::secure());
    let capset: CapabilitySet = caps.iter().copied().collect();
    store.add_key_with_capabilities(token, capset, "test");
    app.layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))))
}

/// A bearer-authenticated GET request.
fn authed_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

/// A bearer-authenticated HEAD request.
///
/// `axum`'s `get()` serves `HEAD` automatically (runs the handler, discards the
/// body), and `required_capability` has no separate `HEAD` entries in its
/// table — it normalises `HEAD` to `GET` before matching. These tests exist
/// because that normalisation is the only thing standing between a
/// `session.read`-only token and a `fs.read`-gated route: without it, `HEAD`
/// falls through the table to the fail-closed default `Authenticated`, which
/// admits any valid token.
fn authed_head(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("HEAD")
        .uri(uri)
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

/// A bearer-authenticated DELETE request.
fn authed_delete(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

/// A bearer-authenticated POST request with a JSON body.
fn authed_post_json(uri: &str, token: &str, json: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json.to_string()))
        .expect("request")
}

/// A bearer-authenticated POST request with an empty body.
fn authed_post_empty(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

/// A bearer-authenticated PATCH request carrying one chunk.
fn authed_patch(
    uri: &str,
    token: &str,
    content_range: &str,
    bytes: impl Into<Body>,
) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .header("content-range", content_range)
        .body(bytes.into())
        .expect("request")
}

/// SHA-256 of b"hello world".
const HELLO_DIGEST: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

/// Create an upload session for `path` sized and hashed to match `payload`,
/// through the *plain* (unsecured) router — session state lives in
/// `AppState.uploads`, shared with whatever router later wraps the same
/// `state`, so fixture setup does not need to go through the router under
/// test.
async fn create_test_upload(state: AppState, path: &str, payload: &[u8]) -> String {
    let digest = {
        let mut hasher = shell_tunnel::fs::sha256::Hasher::new();
        hasher.update(payload);
        hasher.finish()
    };
    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": path,
                        "size": payload.len() as u64,
                        "sha256": digest,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "fixture upload creation must succeed"
    );
    body_json(response).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string()
}

/// An app state with no `--fs-root`, plus a scratch directory to aim at.
///
/// Machine-wide scope takes absolute paths, so the destination is returned as
/// a string in the form the API expects rather than left for each test to
/// assemble.
fn machine_wide_state() -> (tempfile::TempDir, AppState, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir
        .path()
        .canonicalize()
        .expect("canonicalize")
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/");
    (
        dir,
        AppState::new().with_fs_root(FsRoot::machine_wide()),
        base,
    )
}

/// Opening a second upload into a directory must not destroy the first.
///
/// With no `--fs-root`, staging follows the destination, so every upload
/// heading for one directory shares one staging directory. `create` sweeps
/// that directory for orphans left by a previous run — and an unconditional
/// sweep there removes the *live* session's `.part` too. The damage is
/// invisible until the end: the session holds an open handle, so every
/// subsequent chunk still answers 200 with an advancing offset, and only
/// `complete` fails, with `ENOENT`, after the whole file has been sent.
///
/// Found by a real transfer over a relay, not by this suite — a 5 MiB upload
/// reported every chunk accepted and then could not be published. The sweep's
/// age floor is what makes it safe; this test fails without it.
#[tokio::test]
async fn a_second_upload_into_the_same_directory_leaves_the_first_intact() {
    let (_dir, state, base) = machine_wide_state();
    let first =
        create_test_upload(state.clone(), &format!("{base}/first.bin"), b"hello world").await;

    // Same directory, so the same staging directory: this is the call that
    // used to sweep `first`'s staging file out from under it.
    let _second =
        create_test_upload(state.clone(), &format!("{base}/second.bin"), b"hello world").await;

    let patched = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{first}"))
                .header("content-type", "application/octet-stream")
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(patched.status(), StatusCode::OK);

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{first}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    // The assertion that bites: an accepted chunk that cannot be published is
    // worse than a refused one, so this is checked on the publication step
    // rather than on the 200 above.
    assert_eq!(
        completed.status(),
        StatusCode::OK,
        "the first upload must still be publishable after a second one opened"
    );
    assert_eq!(
        std::fs::read(_dir.path().join("first.bin")).expect("published file"),
        b"hello world"
    );
}

/// The staging directory stays hidden and untouchable when no `--fs-root`
/// narrows the scope.
///
/// The guard matched `.shell-tunnel-uploads` as a path *prefix*, which held
/// while every scope was a jail — staging sits directly under the root, so it
/// is always the first segment. Machine-wide it is a segment in the middle of
/// an absolute path, the prefix test stopped matching, and `stat`, `list`,
/// `download`, and `delete` all went back to exposing in-flight staging files.
///
/// Found against a live server: `stat` on the staging directory answered 200
/// and `list` returned it as an ordinary entry. Every test in this suite used
/// a jail, so none of them could see it.
#[tokio::test]
async fn the_staging_directory_stays_reserved_without_a_jail() {
    let (dir, state, base) = machine_wide_state();
    // Opening a session is what creates the staging directory on disk.
    let _id = create_test_upload(state.clone(), &format!("{base}/x.bin"), b"hello world").await;
    let staging = format!("{base}/{}", shell_tunnel::fs::UPLOAD_DIR);
    assert!(
        dir.path().join(shell_tunnel::fs::UPLOAD_DIR).is_dir(),
        "the fixture must have produced a staging directory to hide"
    );

    for uri in [
        format!("/api/v1/fs/stat?path={staging}"),
        format!("/api/v1/fs/file?path={staging}/up-0000000000000000.part"),
    ] {
        let response = create_router_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{uri} must be refused as a reserved path"
        );
    }

    let deleted = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/fs/file?path={staging}/up-0000000000000000.part"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        deleted.status(),
        StatusCode::FORBIDDEN,
        "a staging file must not be deletable through the file API"
    );

    let listed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/fs/list?path={base}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(listed.status(), StatusCode::OK);
    let entries = body_json(listed).await;
    let names: Vec<String> = entries["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["path"].as_str().expect("path").to_string())
        .collect();
    assert!(
        !names
            .iter()
            .any(|p| p.contains(shell_tunnel::fs::UPLOAD_DIR)),
        "list must not report the staging directory: {names:?}"
    );
}

/// Pagination still covers a directory exactly once when entry names are
/// absolute paths.
///
/// The cursor encodes the last path returned, and `list` resumes after it.
/// That string used to be short and root-relative; machine-wide it is an
/// absolute path carrying a drive prefix, `:`, and separators — the same
/// consumer-of-`relative()` shape that broke `is_reserved_path`. Nothing
/// covered it, so this walks a directory two entries at a time and checks the
/// union, which catches a cursor that skips entries, repeats a page, or never
/// terminates.
#[tokio::test]
async fn paginating_a_machine_wide_directory_returns_every_entry_once() {
    let (dir, state, base) = machine_wide_state();
    let expected: Vec<String> = (0..7)
        .map(|i| {
            let name = format!("f{i}.txt");
            std::fs::write(dir.path().join(&name), b"x").expect("write");
            format!("{base}/{name}")
        })
        .collect();

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..20 {
        let uri = match &cursor {
            Some(c) => format!("/api/v1/fs/list?path={base}&limit=2&cursor={c}"),
            None => format!("/api/v1/fs/list?path={base}&limit=2"),
        };
        let response = create_router_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let page = body_json(response).await;
        for entry in page["entries"].as_array().expect("entries") {
            seen.push(entry["path"].as_str().expect("path").to_string());
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }

    let mut deduped = seen.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        seen.len(),
        "pagination repeated an entry: {seen:?}"
    );
    let mut want = expected;
    want.sort();
    assert_eq!(deduped, want, "pagination did not cover the directory once");
}

/// Two spellings of one absolute destination must not open two sessions.
///
/// The claim key is `relative()`'s output for the resolved destination, which
/// is why aliasing is caught at all. The existing coverage
/// (`two_sessions_for_aliased_spellings_of_one_destination_are_refused`) uses
/// jailed spellings; the machine-wide alias set is a different one, and it
/// runs through the same key.
#[tokio::test]
async fn two_sessions_for_aliased_absolute_spellings_are_refused() {
    let (_dir, state, base) = machine_wide_state();
    let digest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let open = |path: String| {
        let state = state.clone();
        async move {
            create_router_with_state(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/fs/uploads")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({"path": path, "size": 11, "sha256": digest})
                                .to_string(),
                        ))
                        .expect("request"),
                )
                .await
                .expect("response")
                .status()
        }
    };

    assert_eq!(open(format!("{base}/dup.bin")).await, StatusCode::CREATED);

    // `.` is stripped while resolving, so this names the file already claimed.
    assert_eq!(
        open(format!("{base}/./dup.bin")).await,
        StatusCode::CONFLICT,
        "a `.` component must not open a second session for one destination"
    );

    // Windows accepts either separator for one file, and canonicalises the
    // drive letter's case — both spellings have to land on the same key.
    #[cfg(windows)]
    {
        assert_eq!(
            open(base.replace('/', "\\") + "\\dup.bin").await,
            StatusCode::CONFLICT,
            "backslashes name the same file on this platform"
        );
        let lowercased = format!("{}{}", base[..1].to_lowercase(), &base[1..]);
        assert_eq!(
            open(format!("{lowercased}/dup.bin")).await,
            StatusCode::CONFLICT,
            "a lower-case drive letter names the same file"
        );
    }
}

#[tokio::test]
async fn stat_forbids_a_token_lacking_fs_read() {
    let (_dir, state) = state_with_files(&[("app/config.json", b"hello")]);
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_get("/api/v1/fs/stat?path=app/config.json", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn stat_allows_a_token_holding_fs_read() {
    let (_dir, state) = state_with_files(&[("app/config.json", b"hello")]);
    let app = secure_app_with_token(state, "reader", &["fs.read"]);

    let response = app
        .oneshot(authed_get("/api/v1/fs/stat?path=app/config.json", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_forbids_a_token_lacking_fs_read() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_get("/api/v1/fs/list?path=app", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_allows_a_token_holding_fs_read() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = secure_app_with_token(state, "reader", &["fs.read"]);

    let response = app
        .oneshot(authed_get("/api/v1/fs/list?path=app", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_reports_entries_sorted_by_path() {
    let (_dir, state) = state_with_files(&[
        ("app/b.txt", b"bb"),
        ("app/a.txt", b"a"),
        ("top.txt", b"ttt"),
    ]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let entries = json["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["path"], "app/a.txt");
    assert_eq!(entries[1]["path"], "app/b.txt");
    assert!(json["next_cursor"].is_null());
}

#[tokio::test]
async fn list_recurses_when_asked() {
    let (_dir, state) = state_with_files(&[("app/nested/deep.txt", b"d"), ("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let json = body_json(response).await;
    let paths: Vec<String> = json["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["path"].as_str().expect("path").to_string())
        .collect();
    assert!(paths.contains(&"app/a.txt".to_string()));
    assert!(paths.contains(&"app/nested/deep.txt".to_string()));
}

#[tokio::test]
async fn list_hashes_only_when_asked() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"abc")]);
    let app = create_router_with_state(state.clone());

    let plain = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let json = body_json(plain).await;
    // Not just `.is_null()`: `Value`'s `Index` returns `Value::Null` for a
    // missing key too, so that assertion would stay green even if the
    // `skip_serializing_if` on `FsEntry::sha256` were deleted. The key must be
    // genuinely absent (see `stat_reports_a_file`'s identical check).
    assert!(!json["entries"][0]
        .as_object()
        .expect("object")
        .contains_key("sha256"));

    let hashed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app&hash=sha256")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let json = body_json(hashed).await;
    // SHA-256 of "abc" — the canonical NIST vector.
    assert_eq!(
        json["entries"][0]["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// Create a symlink for a test, tolerating the privilege some Windows
/// accounts and CI runners lack (`SeCreateSymbolicLinkPrivilege`). Mirrors the
/// helper of the same name in `src/fs/root.rs`'s test module — duplicated
/// rather than exported, since it exists only so a test here can skip
/// cleanly when the runner cannot create one.
///
/// Returns the creation `io::Result` rather than collapsing it to `bool`:
/// `require_symlink` puts the error in its panic message when creation fails
/// on a platform where that should never happen, and `.is_ok()` would have
/// thrown the errno away before it got there.
fn try_symlink(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(std::io::Error::other(
            "symlinks unsupported on this platform",
        ))
    }
}

/// Like `try_symlink`, but for a target that is a directory. Windows
/// distinguishes file-symlinks from directory-symlinks at creation time
/// (`symlink_file` vs `symlink_dir`); Unix does not.
fn try_symlink_dir(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(std::io::Error::other(
            "symlinks unsupported on this platform",
        ))
    }
}

/// Turns a `try_symlink`/`try_symlink_dir` result into "continue" or "stop",
/// visibly either way — an unmarked early return is indistinguishable from
/// the test having run and passed, which is the same silently-vacuous shape
/// this file's `every_get_fs_route_authorizes_head_identically` guards
/// against for a table-driven loop. "Confirmed executing by name" does not
/// prove the body ran either; only an explicit marker does.
///
/// Unix has no equivalent of Windows's `SeCreateSymbolicLinkPrivilege` gate
/// for an ordinary user creating a symlink, so a failure there almost
/// certainly means something is actually broken, not that the privilege is
/// missing — treated as a hard test failure rather than a silent skip, with
/// the underlying `io::Error` in the panic message so it is diagnosable
/// rather than a bare "it failed". Windows commonly denies it to an
/// unprivileged, non-developer-mode account, so that platform gets a
/// clearly marked skip instead. CI's ubuntu and macos runners always have
/// the privilege, so on CI these assertions execute rather than skip; only a
/// privilege-restricted local Windows session skips.
fn require_symlink(created: std::io::Result<()>, test_name: &str) -> bool {
    match created {
        Ok(()) => true,
        #[cfg(windows)]
        Err(e) => {
            // Not necessarily a privilege gap — could be a real failure (disk
            // full, bad target). Carrying `{e}` is what makes this
            // diagnosable instead of a bare "it failed" guess.
            eprintln!("SKIPPED {test_name}: symlink creation failed: {e}");
            false
        }
        #[cfg(not(windows))]
        Err(e) => {
            panic!(
                "{test_name}: symlink creation failed unexpectedly on a non-Windows platform: {e}"
            );
        }
    }
}

#[tokio::test]
async fn list_hash_does_not_follow_a_symlink_out_of_the_root() {
    // `stat` already refuses a path outside the root (403 path-escapes-root).
    // `list`'s hashing must refuse the same *content* even when the path it
    // is asked to hash never left the root lexically — a symlink inside the
    // tree pointing outward is exactly that case, and `walk`'s `relative()`
    // check cannot catch it: it is a lexical strip_prefix, not a
    // canonicalising one.
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);

    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let secret = outside_dir.path().join("secret.txt");
    std::fs::write(&secret, b"outside-secret").expect("write outside file");

    let root = state.fs.as_ref().expect("fs root enabled");
    let link = root
        .jail_path()
        .expect("this fixture builds a jailed root")
        .join("app")
        .join("linked.txt");
    if try_symlink(&secret, &link).is_err() {
        return; // symlink privilege unavailable on this runner; skip
    }

    let app = create_router_with_state(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app&recursive=true&hash=sha256")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let json = body_json(response).await;
    let entries = json["entries"].as_array().expect("entries");
    let linked = entries
        .iter()
        .find(|e| e["path"] == "app/linked.txt")
        .expect("the symlink is still listed — only its hash is refused");

    // Never the outside file's digest, and in fact never any digest at all:
    // `resolve_existing` on this same relative path finds it resolves outside
    // the root and refuses it, exactly as `stat` would.
    assert!(linked["sha256"].is_null());
}

#[tokio::test]
async fn list_paginates_and_the_cursor_covers_everything_once() {
    let files: Vec<(String, Vec<u8>)> = (0..25)
        .map(|i| (format!("app/f{i:03}.txt"), vec![b'x']))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_slice()))
        .collect();
    let (_dir, state) = state_with_files(&borrowed);

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let uri = match &cursor {
            Some(c) => format!("/api/v1/fs/list?path=app&limit=10&cursor={c}"),
            None => "/api/v1/fs/list?path=app&limit=10".to_string(),
        };
        let response = create_router_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let json = body_json(response).await;
        for entry in json["entries"].as_array().expect("entries") {
            seen.push(entry["path"].as_str().expect("path").to_string());
        }
        match json["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }

    assert_eq!(seen.len(), 25, "every entry returned exactly once");
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 25, "no duplicates across pages");
}

#[tokio::test]
async fn list_caps_the_limit() {
    // The exact ceiling and floor are unit-tested directly on the clamp
    // arithmetic (`resolve_limit_clamps_to_the_configured_bounds` in
    // `src/api/fs.rs`): that arithmetic depends only on the `limit` argument,
    // not on how large the tree being listed is, so proving it does not
    // require building a tree above `MAX_LIST_LIMIT` — this test used to
    // build 10,001 files for exactly that reason, costing most of this
    // suite's runtime. This is the end-to-end proof that `list` actually
    // calls that clamp: a handful of files, `limit` above what exists still
    // leaves a `next_cursor`, and `limit=0` does not mean "empty page".
    let (_dir, state) = state_with_files(&[
        ("app/a.txt", b"a"),
        ("app/b.txt", b"b"),
        ("app/c.txt", b"c"),
    ]);

    let response = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app&limit=2")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let entries = json["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 2);
    assert!(
        !json["next_cursor"].is_null(),
        "3 files exist and limit=2; a real page must leave one for the next page"
    );

    // The lower bound is enforced too: `limit=0` must not mean "empty page".
    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app&limit=0")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let json = body_json(response).await;
    let entries = json["entries"].as_array().expect("entries");
    assert_eq!(
        entries.len(),
        1,
        "limit=0 is clamped up to 1, not down to 0"
    );
}

#[tokio::test]
async fn list_cursor_survives_a_plus_in_the_filename_at_a_page_boundary() {
    // Regression: axum's `Query` extractor decodes form-urlencoded input,
    // where `+` means a space, and `+` is a legal, ordinary filename
    // character (`libstdc++`). A cursor built from the raw path would come
    // back decoded to a different (lexically smaller) string than the one
    // that produced it, so the same page would repeat forever. Bounded at 10
    // iterations rather than truly unbounded, so a regression fails loudly
    // instead of hanging the suite.
    let (_dir, state) = state_with_files(&[
        ("app/a.txt", b"a"),
        ("app/data+1.csv", b"b"),
        ("app/z.txt", b"z"),
    ]);

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for page in 0..10 {
        assert!(page < 9, "cursor did not terminate after 10 pages");

        let uri = match &cursor {
            Some(c) => format!("/api/v1/fs/list?path=app&limit=2&cursor={c}"),
            None => "/api/v1/fs/list?path=app&limit=2".to_string(),
        };
        let response = create_router_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let json = body_json(response).await;
        for entry in json["entries"].as_array().expect("entries") {
            seen.push(entry["path"].as_str().expect("path").to_string());
        }
        match json["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }

    assert_eq!(seen, vec!["app/a.txt", "app/data+1.csv", "app/z.txt"]);
}

#[tokio::test]
async fn list_refuses_a_bad_cursor() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app&cursor=not-a-real-cursor")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert_eq!(json["error"], "bad-cursor");
}

#[tokio::test]
async fn list_refuses_a_file_path() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app/a.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_hides_the_upload_staging_directory() {
    let (_dir, state) =
        state_with_files(&[("app/a.txt", b"a"), (".shell-tunnel-uploads/x.part", b"p")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=.&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let json = body_json(response).await;
    let paths: Vec<String> = json["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["path"].as_str().expect("path").to_string())
        .collect();
    // Not vacuously true on an empty list: prove the listing actually ran
    // (`walk` did not simply skip everything) before trusting the negative
    // assertion below.
    assert!(paths.contains(&"app/a.txt".to_string()));
    assert!(paths
        .iter()
        .all(|p| !p.starts_with(".shell-tunnel-uploads")));
}

/// The one authoritative `(method, path, capability)` table for every fs
/// route. Two different guarantees are derived from this single list rather
/// than each keeping its own copy: that the table maps every route here
/// exactly (`every_fs_route_declares_a_capability`), and that `HEAD` on every
/// `GET` row here is authorized identically to that row's `GET`
/// (`every_get_fs_route_authorizes_head_identically`). A ninth route added
/// for Task 5/6 gets both checks by being added to this one list — nobody
/// has to remember a second, hand-maintained list of `GET` routes to keep it
/// in sync with.
fn fs_capability_table() -> Vec<(axum::http::Method, &'static str, &'static str)> {
    use axum::http::Method;

    vec![
        (Method::GET, "/api/v1/fs/list", "fs.read"),
        (Method::GET, "/api/v1/fs/stat", "fs.read"),
        (Method::GET, "/api/v1/fs/file", "fs.read"),
        (Method::DELETE, "/api/v1/fs/file", "fs.write"),
        (Method::POST, "/api/v1/fs/uploads", "fs.write"),
        (Method::GET, "/api/v1/fs/uploads/{id}", "fs.write"),
        (Method::PATCH, "/api/v1/fs/uploads/{id}", "fs.write"),
        (Method::POST, "/api/v1/fs/uploads/{id}/complete", "fs.write"),
        (Method::DELETE, "/api/v1/fs/uploads/{id}", "fs.write"),
    ]
}

/// Guards the fail-closed trap in `required_capability`: an unmapped route
/// silently falls back to `Authenticated`, which would open every fs route to
/// any valid token. The compiler cannot catch it, so this does.
#[test]
fn every_fs_route_declares_a_capability() {
    use shell_tunnel::api::router::{required_capability, RequiredCapability};

    let table = fs_capability_table();
    // Not just the loop: an empty (or accidentally emptied) table would let
    // this pass having asserted nothing at all.
    assert!(!table.is_empty(), "the capability table is empty");

    for (method, path, expected) in table {
        assert_eq!(
            required_capability(&method, path),
            RequiredCapability::Capability(expected),
            "{method} {path} is not mapped; it would fall back to Authenticated"
        );
    }
}

/// `axum`'s `get()` serves `HEAD` automatically, but `required_capability` has
/// no separate `HEAD` entries — it normalises `HEAD` to `GET` once, centrally,
/// rather than needing a twin arm beside every `GET` row (a forgotten twin
/// would silently fall through to the fail-closed default `Authenticated`,
/// admitting any valid token). This derives the check from the same table
/// `every_fs_route_declares_a_capability` uses, so a `GET` route added later
/// is covered without anyone adding a second assertion for it.
#[test]
fn every_get_fs_route_authorizes_head_identically() {
    use axum::http::Method;
    use shell_tunnel::api::router::required_capability;

    let mut checked = 0;
    for (method, path, _) in fs_capability_table() {
        if method == Method::GET {
            assert_eq!(
                required_capability(&Method::HEAD, path),
                required_capability(&Method::GET, path),
                "HEAD {path} does not match GET's capability — HEAD falls through to Authenticated"
            );
            checked += 1;
        }
    }
    // A table with no GET rows would let this pass having checked nothing —
    // the loop's `if` makes that silent, rather than the obvious no-op a
    // zero-iteration loop would be.
    assert!(
        checked > 0,
        "no GET rows in the table — the assertion ran on nothing"
    );
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body")
        .to_vec()
}

#[tokio::test]
async fn download_returns_the_whole_file_with_an_etag() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app/a.bin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes")
    );
    assert!(response.headers().get("etag").is_some());
    assert_eq!(body_bytes(response).await, b"hello world");
}

#[tokio::test]
async fn download_honours_a_range() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app/a.bin")
                .header("range", "bytes=6-10")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes 6-10/11")
    );
    assert_eq!(body_bytes(response).await, b"world");
}

#[tokio::test]
async fn an_unsatisfiable_range_is_refused() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app/a.bin")
                .header("range", "bytes=99-200")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    // Not just the status: a 416 with no `Content-Range` leaves the client
    // unable to learn the file's actual size to retry with. `bytes */<size>`
    // is exactly what RFC 9110 §14.4 asks a 416 to carry.
    assert_eq!(
        response
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes */5")
    );
}

#[tokio::test]
async fn an_unrecognised_range_unit_is_ignored_not_refused() {
    // RFC 9110 §14.2: an unrecognised range unit must be ignored — served as
    // the whole file (200) — not refused with 416. The brief this handler was
    // first built from asserted the opposite for `parse_range` in isolation;
    // this is the HTTP-level proof the corrected behaviour actually ships.
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app/a.bin")
                .header("range", "items=0-4")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await, b"hello world");
}

#[tokio::test]
async fn download_refuses_a_directory_with_not_a_file() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert_eq!(json["error"], "not-a-file");
}

/// Proves `HEAD` skips the content read rather than merely hiding it from the
/// client: a permission-denied file still lets `stat` succeed (metadata is
/// readable independent of read permission on the content), but a `GET` on
/// it fails to `std::fs::read` it. If `HEAD` silently performed that same
/// read and only axum's body-stripping hid the result, this would 404 too;
/// 200 is only reachable if the read was never attempted.
///
/// `#[cfg(unix)]`: removing read permission from a *file* has no direct
/// `std::fs` equivalent on Windows (ACLs, not a mode bit) — same constraint
/// already accepted by `a_symlink_out_of_the_root_is_refused` in
/// `src/fs/root.rs` and `an_unreadable_nested_subdirectory_does_not_abort_the_whole_walk`
/// in `src/api/fs.rs`.
#[cfg(unix)]
#[tokio::test]
async fn download_head_does_not_read_a_file_it_lacks_permission_to_open() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let path = dir.path().join("app/a.bin");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    // A privileged account (root, or a runner that ignores the mode bit) can
    // still open the file — nothing to verify then.
    if std::fs::File::open(&path).is_ok() {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).ok();
        return;
    }

    let app = create_router_with_state(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/api/v1/fs/file?path=app/a.bin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Restore permissions before any assertion can panic and leak a file the
    // temp-dir cleanup would otherwise be unable to remove.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("restore permissions");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "HEAD must succeed without ever attempting to read the file's contents"
    );
}

/// The ranged twin of the test above. That one proves a whole-file `HEAD`
/// skips the read, but axum strips the body from every `HEAD` response at the
/// router level regardless of what the handler does — so a `HEAD` that forced
/// the read anyway would still come back with an empty body and could pass
/// `download_head_honours_a_range_without_reading_the_body` (which never
/// touches an unreadable file) without the skip actually happening.
///
/// A permission-denied file discriminates: the `Satisfiable` arm only calls
/// `read_span` when `include_body` is true. If that guard were lost, a
/// ranged `HEAD` would attempt the read, hit `EACCES`, and this would 404
/// instead of 206 — the same failure mode
/// `download_head_does_not_read_a_file_it_lacks_permission_to_open` catches
/// for the whole-file arm, here for the ranged one.
#[cfg(unix)]
#[tokio::test]
async fn download_head_with_a_range_does_not_read_a_file_it_lacks_permission_to_open() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let path = dir.path().join("app/a.bin");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    // A privileged account (root, or a runner that ignores the mode bit) can
    // still open the file — nothing to verify then.
    if std::fs::File::open(&path).is_ok() {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).ok();
        return;
    }

    let app = create_router_with_state(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/api/v1/fs/file?path=app/a.bin")
                .header("range", "bytes=6-10")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Restore permissions before any assertion can panic and leak a file the
    // temp-dir cleanup would otherwise be unable to remove.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("restore permissions");

    assert_eq!(
        response.status(),
        StatusCode::PARTIAL_CONTENT,
        "a ranged HEAD must succeed without ever attempting to read the file's contents"
    );
}

#[tokio::test]
async fn download_head_reports_content_length_without_reading_the_body() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/api/v1/fs/file?path=app/a.bin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    // The body is never read for HEAD, so `content-length` cannot come from
    // an in-memory `Vec`'s length — it must be set explicitly from metadata.
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("11")
    );
    assert!(body_bytes(response).await.is_empty());
}

#[tokio::test]
async fn download_head_honours_a_range_without_reading_the_body() {
    // The `include_body` branch was added to both the whole-file and the
    // ranged arm; only the whole-file one had a test. This pins that a
    // ranged `HEAD` still 206s (does not collapse to a whole-file 200) and
    // that its `content-length` matches the *range*, not the file.
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/api/v1/fs/file?path=app/a.bin")
                .header("range", "bytes=6-10")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes 6-10/11")
    );
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("5")
    );
    assert!(body_bytes(response).await.is_empty());
}

#[tokio::test]
async fn if_range_falls_back_to_the_whole_file_when_it_changed() {
    let (dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = create_router_with_state(state.clone());

    let first = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app/a.bin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("etag")
        .to_string();

    // Change the file, so the stale validator must be rejected.
    std::fs::write(dir.path().join("app/a.bin"), b"COMPLETELY DIFFERENT").expect("rewrite");

    let second = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app/a.bin")
                .header("range", "bytes=0-4")
                .header("if-range", etag)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // 200, not 206: stitching the old prefix to new content would corrupt silently.
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(body_bytes(second).await, b"COMPLETELY DIFFERENT");
}

#[tokio::test]
async fn if_range_serves_the_range_when_unchanged() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);

    let first = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app/a.bin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("etag")
        .to_string();

    let second = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/file?path=app/a.bin")
                .header("range", "bytes=0-4")
                .header("if-range", etag)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(second.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(body_bytes(second).await, b"hello");
}

#[tokio::test]
async fn download_forbids_a_token_lacking_fs_read() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_get("/api/v1/fs/file?path=app/a.bin", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn download_allows_a_token_holding_fs_read() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = secure_app_with_token(state, "reader", &["fs.read"]);

    let response = app
        .oneshot(authed_get("/api/v1/fs/file?path=app/a.bin", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn download_head_forbids_a_token_lacking_fs_read() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_head("/api/v1/fs/file?path=app/a.bin", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn download_head_allows_a_token_holding_fs_read() {
    let (_dir, state) = state_with_files(&[("app/a.bin", b"hello world")]);
    let app = secure_app_with_token(state, "reader", &["fs.read"]);

    let response = app
        .oneshot(authed_head("/api/v1/fs/file?path=app/a.bin", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn stat_head_forbids_a_token_lacking_fs_read() {
    let (_dir, state) = state_with_files(&[("app/config.json", b"hello")]);
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_head(
            "/api/v1/fs/stat?path=app/config.json",
            "reader",
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn stat_head_allows_a_token_holding_fs_read() {
    let (_dir, state) = state_with_files(&[("app/config.json", b"hello")]);
    let app = secure_app_with_token(state, "reader", &["fs.read"]);

    let response = app
        .oneshot(authed_head(
            "/api/v1/fs/stat?path=app/config.json",
            "reader",
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_head_forbids_a_token_lacking_fs_read() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_head("/api/v1/fs/list?path=app", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_head_allows_a_token_holding_fs_read() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = secure_app_with_token(state, "reader", &["fs.read"]);

    let response = app
        .oneshot(authed_head("/api/v1/fs/list?path=app", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_removes_a_file() {
    let (dir, state) = state_with_files(&[("app/old.dll", b"stale")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app/old.dll")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!dir.path().join("app/old.dll").exists());
}

#[tokio::test]
async fn delete_refuses_a_directory() {
    let (dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Removing a directory now requires `recursive=true` explicitly —
    // `deleting_a_directory_without_recursive_is_refused` below checks the
    // response body's error code; this one is kept for the plain
    // no-query-params case.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(dir.path().join("app/a.txt").exists());
}

#[tokio::test]
async fn delete_refuses_a_path_outside_the_root() {
    // The root is a *subdirectory* here, so `..` names somewhere real that
    // this test owns. With the root at the temp directory itself, `..` points
    // into the shared system temp directory: there is nothing to place there
    // safely, so the refusal could only ever be checked by its status code.
    let (dir, state) = state_with_a_neighbour("outside.txt", b"do not touch");
    let neighbour = dir.path().join("outside.txt");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=../outside.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // The half this test used to leave unchecked. A handler that removed the
    // file and *then* answered `403` passed it, and "refuses" in the name
    // promised otherwise — the reassuring direction.
    assert!(
        neighbour.is_file(),
        "a refusal must leave the file outside the root alone"
    );
    assert_eq!(
        std::fs::read(&neighbour).expect("read neighbour"),
        b"do not touch",
        "and must not have rewritten it either"
    );
}

/// A root with a sibling file beside it, both inside one temp directory.
///
/// Returned so a test can assert on what `..` reaches: escapes are refused by
/// path resolution, and proving that means having something real one level up
/// that the test can look at afterwards.
fn state_with_a_neighbour(
    name: &str,
    body: &[u8],
) -> (tempfile::TempDir, shell_tunnel::api::AppState) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), body).expect("write neighbour");
    let root_dir = dir.path().join("root");
    std::fs::create_dir_all(root_dir.join("app")).expect("mkdir root");
    std::fs::write(root_dir.join("app/a.txt"), b"a").expect("write");
    let root = FsRoot::new(&root_dir).expect("root");
    (dir, AppState::new().with_fs_root(root))
}

/// A request whose final component is `..` passes the full-path resolution
/// (`resolve_existing("app/..")` walks straight back to a real directory —
/// the root itself here — not out of the root), so nothing upstream refuses
/// it. Without an explicit check, `X/..` always naming a directory used to be
/// enough on its own: every directory was refused regardless. Recursive
/// removal changed that — `path=app/..&recursive=true` now reaches the
/// directory branch instead of stopping there, so without this guard it
/// would walk and remove whatever real directory sits one level above
/// `parent`, outside the root, through `remove_tree`. See the comment in
/// `delete_file_blocking` for why a containment check on the joined path
/// cannot substitute for refusing `..` outright.
#[tokio::test]
async fn delete_refuses_a_path_ending_in_dot_dot() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app/..")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert_eq!(json["error"], "path-escapes-root");
}

/// The same request as above, but spelling `recursive=true` too -- this is
/// the exact case the updated comment above describes: the one where the
/// old "every directory is refused" safety net no longer applies, so the
/// explicit `..` guard is what carries all the weight.
#[tokio::test]
async fn delete_refuses_a_path_ending_in_dot_dot_even_with_recursive() {
    let (dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app/..&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert_eq!(json["error"], "path-escapes-root");
    // Nothing above the root was touched -- the fixture directory itself
    // (which sits one level above `app`, exactly the location the guard
    // protects) must still be intact.
    assert!(dir.path().join("app/a.txt").exists());
}

/// The `..` guard's sibling for `.`, and it needs a symlink fixture to mean
/// anything: `path=app/a.txt/.` would 404 on Unix by accident (`ENOTDIR`,
/// since `a.txt` is a plain file) and 204 on Windows by the same accident
/// that motivated this test in the first place — neither tells the guard
/// apart from its absence. A same-root symlink does: `resolve_existing`
/// follows `link/.` straight to `real.txt` (passing the full-path gate), and
/// on Windows that result is a verbatim path on which `PathBuf::join(".")`
/// collapses back onto itself — so without the guard, `parent =
/// resolve_existing("link")` (the followed target) plus `named =
/// parent.join(".")` lands on `real.txt` again, the exact defect the
/// split-then-join approach exists to avoid, reached through `.` instead of
/// through `resolve_existing`'s own symlink-following.
#[tokio::test]
async fn delete_refuses_a_path_ending_in_dot() {
    let (dir, state) = state_with_files(&[("app/real.txt", b"keep me")]);
    let target = dir.path().join("app/real.txt");
    let link = dir.path().join("link");
    if !require_symlink(
        try_symlink(&target, &link),
        "delete_refuses_a_path_ending_in_dot",
    ) {
        return;
    }

    let app = create_router_with_state(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=link/.")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        target.exists(),
        "the symlink's target must survive — `.` does not name it"
    );
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "the symlink itself must survive — the request was refused, not acted on"
    );
}

/// The same request as above, but spelling `recursive=true` too. The `.`
/// guard fires before the directory branch is ever reached, so `recursive`
/// changes nothing here -- unlike the `..` case, this one was never
/// load-bearing only by accident, but it is worth pinning down now that a
/// directory-shaped request can mean something on this route.
#[tokio::test]
async fn delete_refuses_a_path_ending_in_dot_even_with_recursive() {
    let (dir, state) = state_with_files(&[("app/real.txt", b"keep me")]);
    let target = dir.path().join("app/real.txt");
    let link = dir.path().join("link");
    if !require_symlink(
        try_symlink(&target, &link),
        "delete_refuses_a_path_ending_in_dot_even_with_recursive",
    ) {
        return;
    }

    let app = create_router_with_state(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=link/.&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(target.exists());
    assert!(std::fs::symlink_metadata(&link).is_ok());
}

/// A third accident in the same shape as the `..` and `.` guards: `named =
/// parent.join(name)` assumes `name` appends exactly one ordinary component,
/// but `PathBuf::join` discards `parent` entirely for an argument carrying a
/// prefix (`Path::new(r"C:\root\app").join("C:evil")` is `"C:evil"` — the
/// parent is gone). `delete_file_blocking` catches this as a postcondition
/// (`!named.starts_with(&parent)`) rather than by re-running
/// `platform::check_component` on `name` — a precondition re-running that
/// same rule would be defeated by the very future change (relaxing `:` in
/// `check_component`) it exists to guard against, since both calls consult
/// the identical rule; the postcondition does not consult it at all.
///
/// This request is refused before the postcondition is ever reached, though:
/// the full-path `resolve_existing` call at the top of `delete_file_blocking`
/// already runs `check_component` over every component of the full path,
/// `name` included, so `path=app/C:evil` is refused there today (400
/// `bad-path`) regardless of the postcondition below it. Confirmed by
/// disabling the postcondition guard and re-running — still 400, unchanged.
/// This test pins that outcome so a future narrowing of what the full-path
/// resolution validates cannot silently make `path=app/C:evil` succeed; it
/// does not by itself prove the postcondition guard fires, which is not
/// reachable from any request admitted today. See
/// `postcondition_catches_a_drive_prefix_join_even_without_check_component`
/// below for a direct check of that guard's own logic instead.
///
/// `:` is a legal filename character on Unix, so no fixture there can ever
/// contain such a file — the guard must fire on the string alone, which is
/// exactly what this test asserts (400), not a filesystem outcome.
#[tokio::test]
async fn delete_refuses_a_path_component_containing_a_colon() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app/C:evil")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_reports_not_found_for_a_missing_file() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app/absent.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The first `fs.write` route. Every prior fs route only ever checked
/// `fs.read`, so this is the first proof that `required_capability` actually
/// distinguishes the two — a table keyed on path alone (ignoring `DELETE`
/// versus `GET` on the same `/file` string) would let a `fs.read`-only token
/// delete, or would need a second, easy-to-forget row that nobody has
/// exercised yet.
#[tokio::test]
async fn delete_forbids_a_token_lacking_fs_write() {
    let (_dir, state) = state_with_files(&[("app/old.dll", b"stale")]);
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_delete("/api/v1/fs/file?path=app/old.dll", "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_allows_a_token_holding_fs_write() {
    let (dir, state) = state_with_files(&[("app/old.dll", b"stale")]);
    let app = secure_app_with_token(state, "writer", &["fs.write"]);

    let response = app
        .oneshot(authed_delete("/api/v1/fs/file?path=app/old.dll", "writer"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!dir.path().join("app/old.dll").exists());
}

/// The discriminating case the naive `resolve_existing`-only implementation
/// gets backwards: `resolve_existing` follows a symlink to its canonical
/// target, so acting on what it returns would delete `real.txt` (never named
/// in the request) and leave `link` behind, dangling. Both assertions matter
/// — either alone would miss half of that failure.
#[tokio::test]
async fn delete_removes_a_symlink_without_touching_its_target() {
    let (dir, state) = state_with_files(&[("app/real.txt", b"keep me")]);
    let target = dir.path().join("app/real.txt");
    let link = dir.path().join("link");
    if !require_symlink(
        try_symlink(&target, &link),
        "delete_removes_a_symlink_without_touching_its_target",
    ) {
        return;
    }

    let app = create_router_with_state(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=link")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        target.exists(),
        "the symlink's target was never named in the request and must survive"
    );
    assert!(
        std::fs::symlink_metadata(&link).is_err(),
        "the symlink itself is what was named, and must be gone"
    );
}

/// The directory-symlink arm `platform::remove_entry` exists for: a symlink
/// pointing at a directory is not a directory itself (`symlink_metadata`
/// reports the link's own type), so it must be removable — and removing it
/// must not recurse into what it points to.
#[tokio::test]
async fn delete_removes_a_directory_symlink_without_recursing() {
    let (dir, state) = state_with_files(&[("app/real/inside.txt", b"keep me")]);
    let target = dir.path().join("app/real");
    let link = dir.path().join("linkdir");
    if !require_symlink(
        try_symlink_dir(&target, &link),
        "delete_removes_a_directory_symlink_without_recursing",
    ) {
        return;
    }

    let app = create_router_with_state(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=linkdir")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        target.join("inside.txt").exists(),
        "the symlinked directory and its contents must survive"
    );
    assert!(
        std::fs::symlink_metadata(&link).is_err(),
        "the directory symlink itself is what was named, and must be gone"
    );
}

/// Removing a directory needs `recursive` spelled out.
///
/// The threat model is an agent's mistake. This one line is the cheapest
/// guard against it — a call meaning to delete one file cannot take a tree
/// with it. 400, not 403: it's under-specified intent, not unauthorised.
#[tokio::test]
async fn deleting_a_directory_without_recursive_is_refused() {
    let (dir, state) = state_with_files(&[("app/config.json", b"hello")]);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"], "recursive-required");
    assert!(
        body["message"]
            .as_str()
            .expect("message")
            .contains("recursive"),
        "the message should name the flag: {body}"
    );
    // A refusal must not act on the disk at all -- the status code alone
    // does not prove the tree survived.
    assert!(
        dir.path().join("app/config.json").exists(),
        "a refused delete must remove nothing"
    );
}

/// A preview does not change the disk — checked against disk, not response.
#[tokio::test]
async fn a_dry_run_reports_the_tree_and_leaves_it_alone() {
    let (dir, state) = state_with_files(&[("app/a.txt", b"xy"), ("app/deep/b.txt", b"xy")]);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["removed"], 4);
    assert_eq!(body["bytes"], 4);
    assert_eq!(body["dry_run"], true);
    assert!(dir.path().join("app/a.txt").exists(), "the preview deleted");
    assert!(dir.path().join("app/deep/b.txt").exists());
}

/// A preview that cannot enumerate everything is not a partial *delete* --
/// nothing was removed at all, dry-run or not.
///
/// Regression for reusing `partial-delete` unconditionally: an unreadable
/// subdirectory makes `remove_tree` return a non-empty `failures` even under
/// `dry_run`, and the same 500 that means "some entries survived removal"
/// would then also fire when nothing was ever attempted. An operator
/// grepping `partial-delete` for real failed removals would wrongly match a
/// preview, and the response would say "removed"/"bytes" (a lower bound
/// here, per `TreeOutcome`'s own doc) as if they were exact.
///
/// Unix induces the enumeration failure by stripping read permission from
/// the subdirectory; the Windows sibling below opens it exclusively instead,
/// for the same reason `a_partial_removal_is_not_reported_as_success` needs
/// two different inductions above.
#[cfg(unix)]
#[tokio::test]
async fn a_dry_run_that_cannot_enumerate_everything_is_reported_as_incomplete_not_partial() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, state) =
        state_with_files(&[("app/locked/secret.txt", b"x"), ("app/visible.txt", b"yz")]);
    let locked = dir.path().join("app/locked");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("chmod locked");

    // A quiet early return here would pass having proven nothing on a
    // runner that ignores the mode bit (root), the same failure mode this
    // plan already rejected for `require_symlink` in `src/fs/tree.rs`: if the
    // premise a test depends on does not hold, a loud failure on whatever
    // runner hits that is worth more than a silent, untraceable pass
    // everywhere else. Restore the permission before asserting either way,
    // so a failure here does not also break the temp-dir cleanup.
    let locked_is_unreadable = std::fs::read_dir(&locked).is_err();
    if !locked_is_unreadable {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();
    }
    assert!(
        locked_is_unreadable,
        "chmod 0o000 did not block read_dir on this runner (root?); this test needs a \
         different induction here, the same way the Windows sibling below uses one"
    );

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Restore before asserting: a failed assertion here must not leave the
    // temp-dir cleanup unable to remove the locked directory.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
        .expect("restore permissions");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(response).await;
    assert_eq!(
        body["error"], "preview-incomplete",
        "an incomplete preview must not be reported the same way as a real partial delete: {body}"
    );
    assert!(!body["failures"].as_array().expect("failures").is_empty());
    // `docs/openapi.json`'s `PartialDeleteResult` requires `message` for both
    // `preview-incomplete` and `partial-delete` -- a schema-checking client
    // rejects a response missing it.
    assert!(
        body["message"].as_str().is_some_and(|m| !m.is_empty()),
        "message must be present and non-empty: {body}"
    );
    // dry_run really did not touch anything, including the entries it could
    // enumerate.
    assert!(dir.path().join("app/visible.txt").exists());
    assert!(dir.path().join("app/locked/secret.txt").exists());
}

/// Windows counterpart of the test above: opening the subdirectory
/// exclusively blocks `read_dir` deterministically, playing the same role
/// stripping read permission plays on Unix. `FILE_FLAG_BACKUP_SEMANTICS` is
/// required to open a directory at all through `CreateFileW`; `share_mode(0)`
/// (no `FILE_SHARE_READ`/`WRITE`/`DELETE`) is what actually blocks the walk's
/// later `read_dir` call, the same flag
/// `a_partial_removal_is_not_reported_as_success` uses to block a delete.
#[cfg(windows)]
#[tokio::test]
async fn a_dry_run_that_cannot_enumerate_everything_is_reported_as_incomplete_not_partial() {
    use std::os::windows::fs::OpenOptionsExt;

    let (dir, state) =
        state_with_files(&[("app/locked/secret.txt", b"x"), ("app/visible.txt", b"yz")]);
    let locked = dir.path().join("app/locked");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS
        .open(&locked)
        .expect("open directory exclusively");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Close the handle before asserting: a failed assertion here must not
    // leave the temp-dir cleanup unable to remove the still-open directory.
    drop(handle);

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(response).await;
    assert_eq!(
        body["error"], "preview-incomplete",
        "an incomplete preview must not be reported the same way as a real partial delete: {body}"
    );
    assert!(!body["failures"].as_array().expect("failures").is_empty());
    // `docs/openapi.json`'s `PartialDeleteResult` requires `message` for both
    // `preview-incomplete` and `partial-delete` -- a schema-checking client
    // rejects a response missing it.
    assert!(
        body["message"].as_str().is_some_and(|m| !m.is_empty()),
        "message must be present and non-empty: {body}"
    );
    assert!(dir.path().join("app/visible.txt").exists());
    assert!(dir.path().join("app/locked/secret.txt").exists());
}

#[tokio::test]
async fn a_recursive_delete_removes_the_tree() {
    let (dir, state) = state_with_files(&[("app/a.txt", b"xy"), ("app/deep/b.txt", b"xy")]);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["removed"], 4);
    assert_eq!(body["dry_run"], false);
    assert!(!dir.path().join("app").exists());
}

/// A tree holding an upload in flight is refused whole — nothing removed.
///
/// The same shape as 0.12.0's data loss: an invariant depended on the
/// staging location living somewhere else.
#[tokio::test]
async fn a_tree_holding_a_live_upload_is_refused_without_removing_anything() {
    let (dir, state, base) = machine_wide_state();
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("sub/keep.txt"), b"xy").expect("write");
    let _id = create_test_upload(state.clone(), &format!("{base}/sub/x.bin"), b"hello world").await;

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/file?path={base}/sub&recursive=true"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(response).await["error"], "staging-in-tree");
    assert!(
        dir.path().join("sub/keep.txt").exists(),
        "a refusal must remove nothing"
    );
}

/// The design's other half (§4.1): a staging directory holding only an
/// *orphaned* `.part` -- one with no live session, left behind by a previous
/// run -- is not a reason to refuse. `has_live_part_under` answers from the
/// session list, not the disk, precisely so a tree the sweep has not reached
/// yet is not stuck undeletable forever. Removed here means gone: the staging
/// directory and its orphan go with the rest of the tree.
#[tokio::test]
async fn a_tree_holding_only_an_orphaned_staging_file_is_removed_whole() {
    let (dir, state, base) = machine_wide_state();
    let staging = dir.path().join("sub").join(shell_tunnel::fs::UPLOAD_DIR);
    std::fs::create_dir_all(&staging).expect("mkdir staging");
    std::fs::write(staging.join("up-0000000000000000.part"), b"x").expect("write orphan");
    std::fs::write(dir.path().join("sub/keep.txt"), b"xy").expect("write");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/file?path={base}/sub&recursive=true"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!dir.path().join("sub").exists());
}

/// Tree deletion works without `--fs-root` too.
///
/// `remove_tree` is a new consumer of `root.relative()`, and that string's
/// shape depends on scope — two defects in this repo have come from exactly
/// that spot.
#[tokio::test]
async fn a_recursive_delete_works_without_a_jail() {
    let (dir, state, base) = machine_wide_state();
    std::fs::create_dir_all(dir.path().join("sub/deep")).expect("mkdir");
    std::fs::write(dir.path().join("sub/a.txt"), b"xy").expect("write");
    std::fs::write(dir.path().join("sub/deep/b.txt"), b"xy").expect("write");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/file?path={base}/sub&recursive=true"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["removed"], 4);
    // Names must come back as absolute paths, not jail-relative ones.
    let first = body["entries"][0].as_str().expect("entry");
    assert!(
        first.starts_with(&base),
        "entries must be absolute paths: {first}"
    );
    assert!(!dir.path().join("sub").exists());
}

/// A partial removal must not be reported as success.
///
/// Unix and Windows need different inductions for the same shape: stripping
/// write permission on a *directory* blocks removing its children here (a
/// file's own mode bits don't gate `unlink`, its parent's do). The Windows
/// sibling below cannot reuse this — Windows has no mode-bit equivalent, and
/// (verified) marking the file read-only doesn't work either, since
/// `std::fs::remove_file` clears that attribute and retries — so it induces
/// the same partial failure with an exclusive-share open handle instead.
#[cfg(unix)]
#[tokio::test]
async fn a_partial_removal_is_not_reported_as_success() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, state) = state_with_files(&[("app/locked/a.txt", b"xy"), ("app/free.txt", b"xy")]);
    let locked = dir.path().join("app/locked");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555))
        .expect("chmod locked");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Restore before asserting: a failed assertion here must not leave the
    // temp-dir cleanup unable to remove the locked directory.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
        .expect("restore permissions");

    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a 200 on a partial removal reads as success to a caller that does not read the body"
    );
    let body = body_json(response).await;
    assert_eq!(body["error"], "partial-delete");
    // `locked`'s own `read_dir` still succeeds (its own mode still allows
    // read+execute) -- only the two file removals and the two `remove_dir`
    // calls that depend on them fail -- so all four entries (app, locked,
    // a.txt, free.txt) are still counted, matching the same four-entry tree
    // in `a_recursive_delete_removes_the_tree` above.
    assert_eq!(body["removed"], 4);
    assert_eq!(body["bytes"], 4);
    assert!(
        !body["failures"].as_array().expect("failures").is_empty(),
        "it must say what is left: {body}"
    );
    assert!(
        body["message"].as_str().is_some_and(|m| !m.is_empty()),
        "message must be present and non-empty: {body}"
    );
}

/// Windows counterpart of the test above.
///
/// The read-only attribute does **not** work for this induction on current
/// Rust: `std::fs::remove_file` on Windows clears `FILE_ATTRIBUTE_READONLY`
/// and retries before giving up, so a read-only file is removed anyway
/// (verified with a standalone repro against this toolchain — read-only set,
/// `remove_file` still returns `Ok`, the file is gone). What blocks
/// `DeleteFileW` deterministically instead is an exclusive-share open handle:
/// opening with `share_mode(0)` (no `FILE_SHARE_READ`/`WRITE`/`DELETE`) turns
/// the later delete into `ERROR_SHARING_VIOLATION`, with no timing window to
/// race — the handle is held for the entire request, not raced against it.
#[cfg(windows)]
#[tokio::test]
async fn a_partial_removal_is_not_reported_as_success() {
    use std::os::windows::fs::OpenOptionsExt;

    let (dir, state) = state_with_files(&[("app/locked/a.txt", b"xy"), ("app/free.txt", b"xy")]);
    let locked_file = dir.path().join("app/locked/a.txt");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&locked_file)
        .expect("open exclusively");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Close the handle before asserting: a failed assertion here must not
    // leave the temp-dir cleanup unable to remove the still-open file.
    drop(handle);

    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a 200 on a partial removal reads as success to a caller that does not read the body"
    );
    let body = body_json(response).await;
    assert_eq!(body["error"], "partial-delete");
    // Enumeration never fails here (the open handle only blocks the later
    // `DeleteFileW`, not `read_dir`/lstat), so every one of the four entries
    // is still counted despite three of the four removals failing: `a.txt`
    // (sharing violation), `locked` and `app` (both non-empty afterward).
    assert_eq!(body["removed"], 4);
    assert_eq!(body["bytes"], 4);
    assert!(
        !body["failures"].as_array().expect("failures").is_empty(),
        "it must say what is left: {body}"
    );
    assert!(
        body["message"].as_str().is_some_and(|m| !m.is_empty()),
        "message must be present and non-empty: {body}"
    );
}

/// Single-file deletion's existing behaviour is unchanged.
#[tokio::test]
async fn deleting_a_single_file_still_answers_204() {
    let (dir, state) = state_with_files(&[("app/a.txt", b"xy")]);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app/a.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!dir.path().join("app/a.txt").exists());
}

/// A preview of a single file reports it and leaves it alone.
///
/// Checked against the disk, not just the response: a handler that ignores
/// `dry_run` on this branch and deletes the file anyway would still answer
/// 200 with `removed: 1` -- the file's continued existence is what actually
/// proves the preview did not act.
#[tokio::test]
async fn a_dry_run_on_a_single_file_reports_it_and_leaves_it_alone() {
    let (dir, state) = state_with_files(&[("app/a.txt", b"xy")]);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app/a.txt&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["removed"], 1);
    assert_eq!(body["bytes"], 2);
    assert_eq!(body["dry_run"], true);
    assert!(
        dir.path().join("app/a.txt").exists(),
        "the preview must not remove the file"
    );
}

#[tokio::test]
async fn an_upload_round_trips_and_publishes_atomically() {
    let (dir, state) = state_with_files(&[("app/keep.txt", b"k")]);

    let created = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "app/new.bin",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let json = body_json(created).await;
    let id = json["upload_id"].as_str().expect("upload_id").to_string();
    assert_eq!(json["offset"], 0);
    assert_eq!(json["chunk_size"], 4194304);

    // Not published yet.
    assert!(!dir.path().join("app/new.bin").exists());

    let patched = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(body_json(patched).await["offset"], 11);

    // Still not published: only `complete` renames.
    assert!(!dir.path().join("app/new.bin").exists());

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(completed.status(), StatusCode::OK);

    assert_eq!(
        std::fs::read(dir.path().join("app/new.bin")).expect("read"),
        b"hello world"
    );
}

#[tokio::test]
async fn a_resumed_upload_continues_from_the_reported_offset() {
    let (dir, state) = state_with_files(&[("app/keep.txt", b"k")]);

    let created = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "app/resumed.bin",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let id = body_json(created).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-5/11")
                .body(Body::from(&b"hello "[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    // The client "reconnects" and asks where it left off.
    let status = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let offset = body_json(status).await["offset"].as_u64().expect("offset");
    assert_eq!(offset, 6);

    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", format!("bytes {offset}-10/11"))
                .body(Body::from(&b"world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(completed.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(dir.path().join("app/resumed.bin")).expect("read"),
        b"hello world"
    );
}

#[tokio::test]
async fn a_bad_checksum_refuses_and_leaves_no_file() {
    let (dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let wrong = "0".repeat(64);

    let created = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "app/corrupt.bin",
                        "size": 11,
                        "sha256": wrong,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let id = body_json(created).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(completed.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!dir.path().join("app/corrupt.bin").exists());
}

#[tokio::test]
async fn a_second_session_for_the_same_destination_is_refused() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);

    let body = || {
        Body::from(
            serde_json::json!({
                "path": "app/contested.bin",
                "size": 11,
                "sha256": HELLO_DIGEST,
            })
            .to_string(),
        )
    };

    let first = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(body())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(body())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn an_upload_may_not_target_a_path_outside_the_root() {
    let (dir, state) = state_with_a_neighbour("keep.txt", b"k");
    let escape = dir.path().join("escape.bin");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "../escape.bin",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // Refusing the session is not the same as having created nothing. A
    // `create` that opened its staging file before resolving the destination
    // would answer `403` and still have written outside the root, and the
    // status alone could never tell the two apart.
    assert!(
        !escape.exists(),
        "a refused session must not have created anything outside the root"
    );
    // Under a jail the staging directory hangs off the root, not off the
    // destination — so that, and not a directory beside `escape.bin`, is where
    // a session that got past the guard would have left its trace. Checking
    // the wrong one of the two would have made this assertion unfalsifiable.
    assert!(
        !dir.path().join("root/.shell-tunnel-uploads").exists(),
        "nor a staging file for a session that should never have opened"
    );
}

/// The control for the assertion above. If a refused session left no staging
/// directory simply because *no* session ever leaves one at that path, the
/// check would be unfalsifiable — so this opens a legitimate session against
/// the identical fixture and confirms the directory does appear there.
#[tokio::test]
async fn a_permitted_upload_into_the_same_fixture_does_create_staging() {
    let (dir, state) = state_with_a_neighbour("keep.txt", b"k");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "app/fine.bin",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(
        dir.path().join("root/.shell-tunnel-uploads").is_dir(),
        "the path the refusal test watches must be one a real session uses"
    );
}

/// The one small-payload test above cannot catch the axum-core body-limit gap
/// (`DEFAULT_LIMIT` = 2 MiB, `src/api/router.rs`'s `upload_session_routes`):
/// an 11-byte chunk sails under any limit, configured or not. This sends a
/// chunk of the *actual* advertised `chunk_size` (4 MiB) through the real
/// router and proves it reaches `append_chunk` rather than being cut off by
/// axum first.
#[tokio::test]
async fn a_chunk_at_the_advertised_chunk_size_round_trips_through_the_router() {
    let (dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let chunk_size = shell_tunnel::fs::DEFAULT_CHUNK_SIZE;
    let payload = vec![0x5A_u8; chunk_size];
    let digest = {
        let mut hasher = shell_tunnel::fs::sha256::Hasher::new();
        hasher.update(&payload);
        hasher.finish()
    };

    let created = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "app/big.bin",
                        "size": chunk_size as u64,
                        "sha256": digest,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let id = body_json(created).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

    let patched = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header(
                    "content-range",
                    format!("bytes 0-{}/{chunk_size}", chunk_size - 1),
                )
                .body(Body::from(payload))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        patched.status(),
        StatusCode::OK,
        "a chunk of the advertised chunk_size must not be rejected before append_chunk runs"
    );
    assert_eq!(body_json(patched).await["offset"], chunk_size as u64);

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(completed.status(), StatusCode::OK);
    assert_eq!(
        std::fs::metadata(dir.path().join("app/big.bin"))
            .expect("published file")
            .len(),
        chunk_size as u64
    );
}

#[tokio::test]
async fn create_upload_forbids_a_token_lacking_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_post_json(
            "/api/v1/fs/uploads",
            "reader",
            serde_json::json!({"path": "app/new.bin", "size": 11, "sha256": HELLO_DIGEST}),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_upload_allows_a_token_holding_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let app = secure_app_with_token(state, "writer", &["fs.write"]);

    let response = app
        .oneshot(authed_post_json(
            "/api/v1/fs/uploads",
            "writer",
            serde_json::json!({"path": "app/new.bin", "size": 11, "sha256": HELLO_DIGEST}),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn upload_status_forbids_a_token_lacking_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let id = create_test_upload(state.clone(), "app/new.bin", b"hello world").await;
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_get(&format!("/api/v1/fs/uploads/{id}"), "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn upload_status_allows_a_token_holding_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let id = create_test_upload(state.clone(), "app/new.bin", b"hello world").await;
    let app = secure_app_with_token(state, "writer", &["fs.write"]);

    let response = app
        .oneshot(authed_get(&format!("/api/v1/fs/uploads/{id}"), "writer"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn append_chunk_forbids_a_token_lacking_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let id = create_test_upload(state.clone(), "app/new.bin", b"hello world").await;
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_patch(
            &format!("/api/v1/fs/uploads/{id}"),
            "reader",
            "bytes 0-10/11",
            &b"hello world"[..],
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn append_chunk_allows_a_token_holding_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let id = create_test_upload(state.clone(), "app/new.bin", b"hello world").await;
    let app = secure_app_with_token(state, "writer", &["fs.write"]);

    let response = app
        .oneshot(authed_patch(
            &format!("/api/v1/fs/uploads/{id}"),
            "writer",
            "bytes 0-10/11",
            &b"hello world"[..],
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn complete_upload_forbids_a_token_lacking_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let id = create_test_upload(state.clone(), "app/new.bin", b"hello world").await;
    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    let app = secure_app_with_token(state, "reader", &["session.read"]);
    let response = app
        .oneshot(authed_post_empty(
            &format!("/api/v1/fs/uploads/{id}/complete"),
            "reader",
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn complete_upload_allows_a_token_holding_fs_write() {
    let (dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let id = create_test_upload(state.clone(), "app/new.bin", b"hello world").await;
    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    let app = secure_app_with_token(state, "writer", &["fs.write"]);
    let response = app
        .oneshot(authed_post_empty(
            &format!("/api/v1/fs/uploads/{id}/complete"),
            "writer",
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(dir.path().join("app/new.bin")).expect("read"),
        b"hello world"
    );
}

#[tokio::test]
async fn cancel_upload_forbids_a_token_lacking_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let id = create_test_upload(state.clone(), "app/new.bin", b"hello world").await;
    let app = secure_app_with_token(state, "reader", &["session.read"]);

    let response = app
        .oneshot(authed_delete(&format!("/api/v1/fs/uploads/{id}"), "reader"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cancel_upload_allows_a_token_holding_fs_write() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);
    let id = create_test_upload(state.clone(), "app/new.bin", b"hello world").await;
    let app = secure_app_with_token(state, "writer", &["fs.write"]);

    let response = app
        .oneshot(authed_delete(&format!("/api/v1/fs/uploads/{id}"), "writer"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// Review finding: `create_upload_blocking` used to key the destination
/// claim on the raw request string, so `app/x.bin`, `./app/x.bin`, and
/// `app\x.bin` claimed three *different* keys for what `resolve_for_create`
/// resolves to one file. Two sessions under aliased spellings could both
/// reach `complete` and both `rename` onto the same path — the exact
/// last-writer-wins data loss the claim exists to prevent. Fixed by keying
/// on `root.relative(&resolved)` instead of the raw string.
#[tokio::test]
async fn two_sessions_for_aliased_spellings_of_one_destination_are_refused() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);

    let create = |path: &'static str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/fs/uploads")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "path": path,
                    "size": 11,
                    "sha256": HELLO_DIGEST,
                })
                .to_string(),
            ))
            .expect("request")
    };

    let first = create_router_with_state(state.clone())
        .oneshot(create("app/aliased.bin"))
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::CREATED);

    for alias in ["./app/aliased.bin", "app\\aliased.bin", "app/./aliased.bin"] {
        let response = create_router_with_state(state.clone())
            .oneshot(create(alias))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "{alias:?} must claim the same destination as app/aliased.bin"
        );
    }
}

/// Review finding: nothing proved the raised body limit was scoped to only
/// the chunk-upload route. `route_layer` vs. `.layer()` on the wrong router
/// (or the limit hoisted any higher than `upload_session_routes`) would let
/// this leak to unrelated routes, `/api/v1/execute` included, with the
/// suite otherwise staying green — `a_chunk_at_the_advertised_chunk_size_...`
/// only proves the limit was *raised*, not that it was raised nowhere else.
#[tokio::test]
async fn the_upload_body_limit_does_not_leak_to_other_routes() {
    // Comfortably above axum-core's own 2 MiB default, comfortably below
    // MAX_CHUNK_SIZE — if this ever stopped 413ing, the raised limit reached
    // a route it must not have.
    let oversized = || vec![0_u8; 3 * 1024 * 1024];

    let execute_response = create_router_with_state(AppState::new())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/execute")
                .header("content-type", "application/json")
                .body(Body::from(oversized()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(execute_response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // `/execute` alone only catches the limit being hoisted onto `api_v1` or
    // higher. It stays 413 even if `route_layer` on `upload_session_routes`
    // (`src/api/router.rs`) were instead applied to the whole `fs_routes()`
    // router — `/execute` lives outside `fs_routes()` entirely, so that
    // mistake would leave this first assertion green while every sibling
    // fs route quietly gained an 8 MiB limit. `POST /api/v1/fs/uploads` is
    // inside `fs_routes()`, so it closes exactly that gap: it must still
    // 413 at the 2 MiB default too.
    let create_upload_response = create_router_with_state(AppState::new())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(oversized()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        create_upload_response.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

/// Review finding: a real directory at the destination was only ever
/// detected at `complete` time, when `rename` fails `EISDIR`/`ENOTDIR` —
/// after the client has already uploaded the whole file. `create_upload`
/// now refuses it upfront.
#[tokio::test]
async fn create_upload_refuses_a_destination_that_is_already_a_directory() {
    let (_dir, state) = state_with_files(&[("app/existing_dir/inside.txt", b"x")]);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "app/existing_dir",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let json = body_json(response).await;
    assert_eq!(json["error"], "destination-is-directory");
}

/// Review finding: nothing refused a destination inside the upload staging
/// directory. `list` deliberately hides it, so a file published there could
/// never be reported back through this API, and a caller-chosen name shaped
/// like a real staging filename could collide with a future session's own
/// `create_new`.
#[tokio::test]
async fn create_upload_refuses_a_destination_inside_the_staging_directory() {
    let (_dir, state) = state_with_files(&[("app/keep.txt", b"k")]);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": ".shell-tunnel-uploads/sneaky.bin",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert_eq!(json["error"], "reserved-path");
}

/// Whole-branch final review finding: `create_upload` refuses the staging
/// directory as a *destination* and `list` hides it from listings, but
/// `stat`, `GET /fs/file`, and `DELETE /fs/file` checked nothing — a caller
/// could name a `.part` file directly. Session ids are a predictable
/// per-process counter (`up-{serial:016x}`), so this was not a theoretical
/// gap: an `fs.read` token could read another caller's in-progress partial
/// content, and an `fs.write` token could delete another session's staging
/// file out from under it. These three tests reproduce the reviewer's probe
/// against a real file placed in the staging directory the way an in-flight
/// upload actually leaves one, rather than only asserting the route string
/// shape.
///
/// A real staging file, not a plain file dropped in a subdirectory named
/// `.shell-tunnel-uploads` by `state_with_files`: the two are
/// indistinguishable to `is_reserved_path`, but going through the real
/// session lifecycle up to `PATCH` is what proves the guard fires on the
/// exact artifact the finding was about, not merely a similarly-named one.
///
/// The returned path is built from the `upload_id` the server actually
/// handed back, not a hardcoded serial: the counter behind `up-{serial:016x}`
/// is one atomic shared by every test in this binary, so its value here
/// depends on how many other tests already created a session, not on this
/// test alone.
async fn state_with_a_staged_upload() -> (tempfile::TempDir, AppState, String) {
    let (dir, state) = state_with_files(&[]);

    let create = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "app/upload.bin",
                        "size": 6,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(create.status(), StatusCode::CREATED);
    let upload_id = body_json(create).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

    let patch = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{upload_id}"))
                .header("content-range", "bytes 0-5/6")
                .body(Body::from(&b"hello "[..]))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(patch.status(), StatusCode::OK);

    let staging_path = format!(".shell-tunnel-uploads/{upload_id}.part");
    (dir, state, staging_path)
}

#[tokio::test]
async fn stat_refuses_a_path_inside_the_staging_directory() {
    let (_dir, state, staging_path) = state_with_a_staged_upload().await;

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/fs/stat?path={staging_path}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert_eq!(json["error"], "reserved-path");
}

#[tokio::test]
async fn download_refuses_a_path_inside_the_staging_directory() {
    let (_dir, state, staging_path) = state_with_a_staged_upload().await;

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/fs/file?path={staging_path}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert_eq!(json["error"], "reserved-path");
}

#[tokio::test]
async fn delete_refuses_a_path_inside_the_staging_directory() {
    let (_dir, state, staging_path) = state_with_a_staged_upload().await;

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/file?path={staging_path}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert_eq!(json["error"], "reserved-path");
}

/// Audit events written by a state whose sink is a file in `dir`.
fn audited_state(dir: &tempfile::TempDir) -> (AppState, std::path::PathBuf) {
    let log = dir.path().join("audit.jsonl");
    let sink = shell_tunnel::audit::AuditSink::file(&log).expect("sink");
    let root = FsRoot::new(dir.path()).expect("root");
    (
        AppState::new()
            .with_fs_root(root)
            .with_audit(std::sync::Arc::new(sink)),
        log,
    )
}

fn audit_lines(log: &std::path::Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("audit json"))
        .collect()
}

#[tokio::test]
async fn a_completed_upload_is_audited_once_with_its_path_and_size() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, log) = audited_state(&dir);

    let created = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        // Spelled with a "./" prefix deliberately: the audit
                        // trail must record the canonical destination, not
                        // whatever the caller happened to type, or `start`
                        // and `complete` for the same session could carry two
                        // different spellings and never correlate.
                        "path": "./audited.bin",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let id = body_json(created).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

    // Two chunks: the audit trail must not grow with them.
    for (range, chunk) in [
        ("bytes 0-5/11", &b"hello "[..]),
        ("bytes 6-10/11", &b"world"[..]),
    ] {
        create_router_with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/v1/fs/uploads/{id}"))
                    .header("content-range", range)
                    .body(Body::from(chunk))
                    .expect("request"),
            )
            .await
            .expect("response");
    }

    create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let events = audit_lines(&log);
    let kinds: Vec<&str> = events.iter().filter_map(|e| e["kind"].as_str()).collect();
    assert!(kinds.contains(&"upload.start"), "got {kinds:?}");
    assert!(kinds.contains(&"upload.complete"), "got {kinds:?}");
    // Chunks are not recorded: a GB transfer would otherwise bury the trail.
    // Nothing in this codebase emits "upload.chunk" today, so this cannot go
    // red by itself — it is a regression guard against a future per-chunk
    // record being added back, not proof one was ever removed.
    assert!(!kinds.contains(&"upload.chunk"), "got {kinds:?}");

    let start = events
        .iter()
        .find(|e| e["kind"] == "upload.start")
        .expect("start event");
    let complete = events
        .iter()
        .find(|e| e["kind"] == "upload.complete")
        .expect("complete event");
    // Same canonical spelling on both ends, despite the "./" the request used.
    assert_eq!(start["file"], "audited.bin");
    assert_eq!(complete["file"], "audited.bin");
    assert_eq!(complete["bytes"], 11);
    assert_eq!(complete["digest_ok"], true);
    // `upload.start` carries the session's own id: the one thing that also
    // survives on a bare orphaned staging file (see
    // `an_orphaned_staging_file_is_audited_and_correlates_to_its_start_by_upload_id`
    // below), which cannot carry `file` at all and correlates back to this
    // event by `upload_id` alone.
    assert_eq!(start["upload_id"], id);
    // `complete` carries it too: `file` alone is ambiguous the moment a
    // destination is uploaded to more than once over the life of the
    // process, since the path is reused but the id is not.
    assert_eq!(complete["upload_id"], id);
}

#[tokio::test]
async fn an_abandoned_session_is_audited_when_it_is_swept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, log) = audited_state(&dir);

    let created = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "abandoned.bin",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let id = body_json(created).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-5/11")
                .body(Body::from(&b"hello "[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    // Sweep with a zero TTL: everything in flight is stale.
    shell_tunnel::api::fs::sweep_expired_uploads(
        &state.uploads,
        &state.audit,
        std::time::Duration::ZERO,
    );

    let events = audit_lines(&log);
    let expired = events
        .iter()
        .find(|e| e["kind"] == "upload.expired")
        .expect("an abandoned session must leave a terminal event");
    assert_eq!(expired["file"], "abandoned.bin");
    assert_eq!(expired["bytes"], 6);
    // `file` alone is ambiguous the moment "abandoned.bin" is uploaded to
    // more than once over the process's life; `upload_id` disambiguates.
    assert_eq!(expired["upload_id"], id);
}

/// The task brief for this feature names three events explicitly: "Record
/// start, complete, and cancel — never chunks." An explicit `DELETE
/// /api/v1/fs/uploads/{id}` is as terminal as a sweep-driven expiry, and
/// without this the trail would show a session starting and then nothing —
/// indistinguishable from one still in progress.
#[tokio::test]
async fn a_cancelled_upload_is_audited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, log) = audited_state(&dir);

    let created = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "cancelled.bin",
                        "size": 11,
                        "sha256": HELLO_DIGEST,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let id = body_json(created).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-5/11")
                .body(Body::from(&b"hello "[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    let cancelled = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(cancelled.status(), StatusCode::NO_CONTENT);

    let events = audit_lines(&log);
    let kinds: Vec<&str> = events.iter().filter_map(|e| e["kind"].as_str()).collect();
    assert!(kinds.contains(&"upload.start"), "got {kinds:?}");
    let cancel = events
        .iter()
        .find(|e| e["kind"] == "upload.cancel")
        .expect("an explicit cancel must leave a terminal event");
    // Same subject a `sweep`-driven `upload.expired` would carry: a reader
    // grepping the trail for a path must see the session end, not just begin.
    assert_eq!(cancel["file"], "cancelled.bin");
    assert_eq!(cancel["bytes"], 6);
    assert_eq!(cancel["upload_id"], id);
}

/// A checksum mismatch at `complete` is also terminal for the session —
/// `UploadStore::take_for_complete` removes it from the session map before
/// returning the error (`src/fs/transfer.rs`) — so it must leave its own
/// event rather than falling through to look, in the trail, like a session
/// still open.
#[tokio::test]
async fn a_checksum_mismatch_is_audited_as_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, log) = audited_state(&dir);
    let wrong = "0".repeat(64);

    let created = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/fs/uploads")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": "corrupt.bin",
                        "size": 11,
                        "sha256": wrong,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let id = body_json(created).await["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(completed.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let events = audit_lines(&log);
    let rejected = events
        .iter()
        .find(|e| e["kind"] == "upload.rejected")
        .expect("a rejected checksum must leave a terminal event");
    assert_eq!(rejected["digest_ok"], false);
    // `UploadError::Checksum` carries `dest_rel` precisely so this event can
    // name its subject, like every other terminal upload event.
    assert_eq!(rejected["file"], "corrupt.bin");
    assert_eq!(rejected["upload_id"], id);
}

#[tokio::test]
async fn a_deleted_file_is_audited() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("old.dll"), b"stale").expect("write");
    let (state, log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=old.dll")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let events = audit_lines(&log);
    let deleted = events
        .iter()
        .find(|e| e["kind"] == "fs.delete")
        .expect("a deletion must leave an audit event");
    assert_eq!(deleted["file"], "old.dll");
}

/// The audit module's own contract (`src/audit.rs`'s header) is that every
/// event identifies who made the request, not just what happened. Routed
/// through the real capability-checking router (`secure_app_with_token`, used
/// throughout this file for the auth tests above) rather than
/// `create_router_with_state`, which never inserts an identity extension at
/// all — that gap would make this pass even if `delete_file` dropped the
/// extractor entirely.
#[tokio::test]
async fn a_deleted_files_audit_event_carries_the_callers_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("secret.bin"), b"x").expect("write");
    let (state, log) = audited_state(&dir);
    let app = secure_app_with_token(state, "op-token", &["fs.write"]);

    let response = app
        .oneshot(authed_delete("/api/v1/fs/file?path=secret.bin", "op-token"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let events = audit_lines(&log);
    let deleted = events
        .iter()
        .find(|e| e["kind"] == "fs.delete")
        .expect("a deletion must leave an audit event");
    assert_eq!(deleted["identity"]["label"], "test");
}

/// The four `fs.delete*` kinds exist so an operator can grep the trail for
/// exactly one outcome without reading every event's body. Nothing pinned
/// that contract down before this: a mutation collapsing all four kinds to
/// `"fs.delete"` and dropping `event.entries` entirely passed the whole
/// suite, including every test above -- none of them read `kind` off a tree
/// removal or asserted `entries` at all. These four assert both.
#[tokio::test]
async fn a_clean_dry_run_over_a_tree_is_audited_as_fs_delete_dry_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app/deep")).expect("mkdir");
    std::fs::write(dir.path().join("app/a.txt"), b"xy").expect("write");
    std::fs::write(dir.path().join("app/deep/b.txt"), b"xy").expect("write");
    let (state, log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let events = audit_lines(&log);
    let event = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.dry_run")
        .expect("a clean tree preview must be audited as fs.delete.dry_run, not fs.delete");
    // "app", "app/a.txt", "app/deep", "app/deep/b.txt".
    assert_eq!(event["entries"], 4);
}

#[tokio::test]
async fn a_clean_recursive_delete_is_audited_as_fs_delete_with_its_entry_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app/deep")).expect("mkdir");
    std::fs::write(dir.path().join("app/a.txt"), b"xy").expect("write");
    std::fs::write(dir.path().join("app/deep/b.txt"), b"xy").expect("write");
    let (state, log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let events = audit_lines(&log);
    let event = events
        .iter()
        .find(|e| e["kind"] == "fs.delete")
        .expect("a clean tree removal must be audited as fs.delete");
    assert_eq!(event["entries"], 4);
}

#[cfg(unix)]
#[tokio::test]
async fn a_partial_recursive_delete_is_audited_as_fs_delete_partial() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app/locked")).expect("mkdir locked");
    std::fs::write(dir.path().join("app/locked/a.txt"), b"xy").expect("write");
    std::fs::write(dir.path().join("app/free.txt"), b"xy").expect("write");
    let locked = dir.path().join("app/locked");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555))
        .expect("chmod locked");
    let (state, log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
        .expect("restore permissions");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = audit_lines(&log);
    let event = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.partial")
        .expect("a partial tree removal must be audited as fs.delete.partial");
    // "app", "app/locked", "app/locked/a.txt", "app/free.txt" -- all four
    // are still counted even though three of the four removals fail (same
    // reasoning as `a_partial_removal_is_not_reported_as_success` above).
    assert_eq!(event["entries"], 4);
}

/// Windows counterpart, same induction as
/// `a_partial_removal_is_not_reported_as_success`'s Windows sibling: an
/// exclusive-share handle blocks one file's removal deterministically.
#[cfg(windows)]
#[tokio::test]
async fn a_partial_recursive_delete_is_audited_as_fs_delete_partial() {
    use std::os::windows::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app/locked")).expect("mkdir locked");
    std::fs::write(dir.path().join("app/locked/a.txt"), b"xy").expect("write");
    std::fs::write(dir.path().join("app/free.txt"), b"xy").expect("write");
    let locked_file = dir.path().join("app/locked/a.txt");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&locked_file)
        .expect("open exclusively");
    let (state, log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    drop(handle);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = audit_lines(&log);
    let event = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.partial")
        .expect("a partial tree removal must be audited as fs.delete.partial");
    assert_eq!(event["entries"], 4);
}

#[cfg(unix)]
#[tokio::test]
async fn a_dry_run_that_cannot_enumerate_everything_is_audited_as_preview_incomplete() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app/locked")).expect("mkdir locked");
    std::fs::write(dir.path().join("app/locked/secret.txt"), b"x").expect("write");
    std::fs::write(dir.path().join("app/visible.txt"), b"yz").expect("write");
    let locked = dir.path().join("app/locked");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("chmod locked");
    let locked_is_unreadable = std::fs::read_dir(&locked).is_err();
    if !locked_is_unreadable {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();
    }
    assert!(
        locked_is_unreadable,
        "chmod 0o000 did not block read_dir on this runner (root?)"
    );
    let (state, log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
        .expect("restore permissions");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = audit_lines(&log);
    let event = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.preview_incomplete")
        .expect("an incomplete preview must be audited under its own kind, not fs.delete.dry_run");
    // "app", "app/visible.txt" -- "app/locked" itself and everything under
    // it could not be enumerated, so entries is a lower bound, not the real
    // count.
    assert_eq!(event["entries"], 2);
}

/// Windows counterpart, same induction as the enumeration-failure test above:
/// an exclusive-share handle on the subdirectory blocks `read_dir` itself.
#[cfg(windows)]
#[tokio::test]
async fn a_dry_run_that_cannot_enumerate_everything_is_audited_as_preview_incomplete() {
    use std::os::windows::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app/locked")).expect("mkdir locked");
    std::fs::write(dir.path().join("app/locked/secret.txt"), b"x").expect("write");
    std::fs::write(dir.path().join("app/visible.txt"), b"yz").expect("write");
    let locked = dir.path().join("app/locked");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS
        .open(&locked)
        .expect("open directory exclusively");
    let (state, log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    drop(handle);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = audit_lines(&log);
    let event = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.preview_incomplete")
        .expect("an incomplete preview must be audited under its own kind, not fs.delete.dry_run");
    assert_eq!(event["entries"], 2);
}

/// `complete_upload_blocking` has three exit paths after `take_for_complete`
/// succeeds: `resolve_for_create`, `create_dir_all`, and `rename` can each
/// fail. Before this test, none of the three recorded anything — an
/// `upload.start` sat in the log followed by permanent silence, since
/// `take_for_complete` had already removed the session from the map. This
/// covers the `create_dir_all` branch: a plain file already sits where the
/// destination's parent directory needs to be, so `create_dir_all` fails
/// deterministically, no ENOSPC simulation required.
#[tokio::test]
async fn a_directory_creation_failure_at_complete_is_audited_as_failed() {
    let dir = tempfile::tempdir().expect("tempdir");
    // "blocker" already exists as a regular file, so it can never also serve
    // as an ancestor directory of the destination below.
    std::fs::write(dir.path().join("blocker"), b"x").expect("write blocker");
    let (state, log) = audited_state(&dir);

    let id = create_test_upload(state.clone(), "blocker/inner.bin", b"hello world").await;
    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(completed.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = audit_lines(&log);
    let failed = events
        .iter()
        .find(|e| e["kind"] == "upload.failed")
        .expect("a publication failure must leave a terminal event, not silence");
    assert_eq!(failed["file"], "blocker/inner.bin");
    assert_eq!(failed["bytes"], 11);
    assert_eq!(failed["reason"], "directory-creation-failed");
    assert_eq!(failed["status"], 500);
    assert_eq!(failed["upload_id"], id);
}

/// Same failure family as the test above, different branch: `rename` itself
/// fails. Reproduced by racing a directory into existence at the destination
/// after the session was created (`resolve_for_create` and `create_dir_all`
/// both pass — the destination's *parent* is fine — but renaming a file onto
/// an existing directory is refused on every platform this project targets).
#[tokio::test]
async fn a_rename_failure_at_complete_is_audited_as_failed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, log) = audited_state(&dir);

    let id = create_test_upload(state.clone(), "raced.bin", b"hello world").await;
    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    // Simulates an external actor creating a directory at the destination
    // while the upload was in flight — nothing this API exposes can do this,
    // but nothing stops another process on the same filesystem either.
    std::fs::create_dir_all(dir.path().join("raced.bin")).expect("race a directory into place");

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(completed.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = audit_lines(&log);
    let failed = events
        .iter()
        .find(|e| e["kind"] == "upload.failed")
        .expect("a publication failure must leave a terminal event, not silence");
    assert_eq!(failed["file"], "raced.bin");
    assert_eq!(failed["bytes"], 11);
    assert_eq!(failed["reason"], "rename-failed");
    assert_eq!(failed["status"], 500);
    assert_eq!(failed["upload_id"], id);
}

/// The third and hardest-to-reach branch: `resolve_for_create` itself fails
/// at `complete` time, after having already succeeded once at `create` time.
/// Reproduced the same way the jail's own tests do (`src/fs/root.rs`): an
/// intermediate path component that did not exist at `create` time is
/// replaced with a symlink escaping the root before `complete` runs. Skips
/// itself when the platform refuses to create the symlink (unprivileged
/// Windows), matching the existing convention in
/// `src/fs/transfer.rs`'s own symlink test.
#[tokio::test]
async fn a_resolve_failure_at_complete_is_audited_as_failed() {
    let outer = tempfile::tempdir().expect("outer tempdir");
    let root_dir = outer.path().join("root");
    std::fs::create_dir_all(&root_dir).expect("mkdir root");
    let outside = outer.path().join("outside");
    std::fs::create_dir_all(&outside).expect("mkdir outside");

    // Built by hand rather than through `audited_state`: that helper roots
    // the `FsRoot` at the whole `TempDir`, but this test needs `outside` to
    // sit *beside* the root, not inside it, so the root has to be a
    // subdirectory of `outer` instead.
    let log = outer.path().join("audit.jsonl");
    let sink = shell_tunnel::audit::AuditSink::file(&log).expect("sink");
    let root = FsRoot::new(&root_dir).expect("root");
    let state = AppState::new()
        .with_fs_root(root)
        .with_audit(std::sync::Arc::new(sink));

    let id = create_test_upload(state.clone(), "escaped/inner.bin", b"hello world").await;
    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-10/11")
                .body(Body::from(&b"hello world"[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    // "escaped" did not exist at `create` time, so `resolve_for_create` left
    // it in the unresolved tail rather than refusing it. Replacing it with a
    // symlink out of the root now reproduces exactly the same failure a race
    // between `create` and `complete` would.
    let link = root_dir.join("escaped");
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&outside, &link).is_ok();
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_dir(&outside, &link).is_ok();
    #[cfg(not(any(unix, windows)))]
    let linked = false;
    if !linked {
        return; // symlink privilege unavailable on this runner; skip
    }

    let completed = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(completed.status(), StatusCode::FORBIDDEN);

    let events = audit_lines(&log);
    let failed = events
        .iter()
        .find(|e| e["kind"] == "upload.failed")
        .expect("a publication failure must leave a terminal event, not silence");
    assert_eq!(failed["file"], "escaped/inner.bin");
    assert_eq!(failed["bytes"], 11);
    assert_eq!(failed["reason"], "destination-resolve-failed");
    assert_eq!(failed["status"], 403);
    assert_eq!(failed["upload_id"], id);
}

/// `main.rs` runs `sweep_orphaned_uploads` once at startup, after a restart
/// has already discarded every in-memory session — so the only thing left of
/// an interrupted upload is its `.part` file. That function never consults
/// `UploadStore` at all (it is a raw directory scan, same as the
/// `crate::fs::sweep_orphan_parts` it wraps), so calling it directly here,
/// without simulating a real restart, exercises exactly the same code path
/// a restart would.
#[tokio::test]
async fn an_orphaned_staging_file_is_audited_and_correlates_to_its_start_by_upload_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, log) = audited_state(&dir);

    let id = create_test_upload(state.clone(), "orphan.bin", b"hello world").await;
    create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", "bytes 0-5/11")
                .body(Body::from(&b"hello "[..]))
                .expect("request"),
        )
        .await
        .expect("response");

    let root = state.fs.clone().expect("fs root");
    let removed = shell_tunnel::api::fs::sweep_orphaned_uploads(&root, &state.audit);
    assert_eq!(removed, 1);

    let events = audit_lines(&log);
    let start = events
        .iter()
        .find(|e| e["kind"] == "upload.start")
        .expect("start event");
    let orphaned = events
        .iter()
        .find(|e| e["kind"] == "upload.orphaned")
        .expect("an orphaned staging file must leave a terminal event, not silence");

    assert_eq!(orphaned["bytes"], 6);
    // The destination is not recoverable from a bare staging file — the only
    // link back to it is the id, shared with `upload.start`.
    assert_eq!(orphaned["upload_id"], start["upload_id"]);
    assert_eq!(orphaned["upload_id"], id);
    assert!(
        !orphaned.as_object().expect("object").contains_key("file"),
        "the destination is not recoverable here; `file` must be absent, not merely null"
    );
}

/// The delete route's own guards had no trail at all: a caller could be
/// refused and the audit log would show the request had never happened.
/// Every other refusal in the file API leaves one -- the authentication layer
/// writes `denied`, the upload path writes `upload.rejected`/`upload.failed`
/// -- and asking "why did that cleanup not go through" after the fact is what
/// the trail is for. These pin the three refusals this handler decides
/// itself; they are the reason `--audit-log`'s description can name what it
/// records instead of hedging.
///
/// One kind carrying `reason`, not one kind per refusal: the four
/// `fs.delete*` success kinds are split because the *accuracy of their
/// counts* differs, and an operator greps for that. A refusal has no counts,
/// so splitting it would widen the grep surface without distinguishing
/// anything.
#[tokio::test]
async fn a_directory_delete_without_recursive_is_audited_as_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app")).expect("mkdir");
    std::fs::write(dir.path().join("app/a.txt"), b"xy").expect("write");
    let (state, log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let events = audit_lines(&log);
    let refused = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.refused")
        .expect("a refused delete must leave an audit event");
    // The same code the HTTP body carries, so a trail entry and a client's
    // error can be matched without a translation table.
    assert_eq!(refused["reason"], "recursive-required");
    assert_eq!(refused["status"], 400);
    assert_eq!(refused["file"], "app");
    assert!(
        dir.path().join("app/a.txt").exists(),
        "a refusal must remove nothing"
    );
}

#[tokio::test]
async fn a_tree_holding_a_live_upload_is_audited_as_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir
        .path()
        .canonicalize()
        .expect("canonicalize")
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/");
    let log = dir.path().join("audit.jsonl");
    let sink = shell_tunnel::audit::AuditSink::file(&log).expect("sink");
    // Machine-wide, because that is the scope in which staging follows the
    // destination and so lands *inside* the tree being removed. Under a
    // `--fs-root` the staging directory hangs off the root instead, and this
    // refusal never fires for a subdirectory.
    let state = AppState::new()
        .with_fs_root(FsRoot::machine_wide())
        .with_audit(std::sync::Arc::new(sink));
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("sub/keep.txt"), b"xy").expect("write");
    let _id = create_test_upload(state.clone(), &format!("{base}/sub/x.bin"), b"hello world").await;

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/file?path={base}/sub&recursive=true"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let events = audit_lines(&log);
    let refused = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.refused")
        .expect("a tree refused for an upload in flight must leave an audit event");
    assert_eq!(refused["reason"], "staging-in-tree");
    assert_eq!(refused["status"], 409);
    assert!(
        dir.path().join("sub/keep.txt").exists(),
        "a refusal must remove nothing"
    );
}

/// Included deliberately, though it is not a guard a caller trips by
/// accident: an attempt to delete another caller's in-progress staging file
/// is the one refusal here with detection value rather than merely
/// diagnostic value.
#[tokio::test]
async fn deleting_a_reserved_path_is_audited_as_refused() {
    let (_dir, state, staging_path, log) = audited_state_with_a_staged_upload().await;

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/file?path={staging_path}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let events = audit_lines(&log);
    let refused = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.refused")
        .expect("a reserved-path delete must leave an audit event");
    assert_eq!(refused["reason"], "reserved-path");
    assert_eq!(refused["status"], 403);
}

/// The other half of the same hole. A removal that was *attempted* and
/// errored is not a refusal -- nothing said no, the filesystem did -- so it
/// carries its own kind, exactly as `upload.failed` sits beside
/// `upload.rejected`. Without it, the single-entry path stays silent on
/// failure while the tree path already writes `fs.delete.partial`.
#[cfg(unix)]
#[tokio::test]
async fn a_delete_the_filesystem_refuses_is_audited_as_failed() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("locked")).expect("mkdir");
    std::fs::write(dir.path().join("locked/a.txt"), b"xy").expect("write");
    let locked = dir.path().join("locked");
    let (state, log) = audited_state(&dir);
    // Removing an entry needs write permission on its *parent*, so a
    // read-and-execute directory blocks it deterministically while leaving
    // the resolution and lstat above it working.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).expect("chmod");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=locked/a.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("restore");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = audit_lines(&log);
    let failed = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.failed")
        .expect("a removal that errored must leave an audit event");
    assert_eq!(failed["status"], 500);
    assert_eq!(failed["file"], "locked/a.txt");
    assert!(
        failed["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "the trail must say why, not merely that it failed"
    );
}

/// `a_delete_the_filesystem_refuses_is_audited_as_failed`'s Windows sibling:
/// an exclusive-share handle blocks one file's removal deterministically,
/// the same mechanism the partial-tree test above uses.
#[cfg(windows)]
#[tokio::test]
async fn a_delete_the_filesystem_refuses_is_audited_as_failed() {
    use std::os::windows::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("locked")).expect("mkdir");
    let target = dir.path().join("locked/a.txt");
    std::fs::write(&target, b"xy").expect("write");
    let (state, log) = audited_state(&dir);
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&target)
        .expect("open exclusively");

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=locked/a.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    drop(handle);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = audit_lines(&log);
    let failed = events
        .iter()
        .find(|e| e["kind"] == "fs.delete.failed")
        .expect("a removal that errored must leave an audit event");
    assert_eq!(failed["status"], 500);
    assert_eq!(failed["file"], "locked/a.txt");
    assert!(
        failed["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "the trail must say why, not merely that it failed"
    );
}

/// `state_with_a_staged_upload`'s audited twin. Kept separate rather than
/// widening that helper's tuple: every existing caller of it asserts on an
/// HTTP response and has no use for a sink.
async fn audited_state_with_a_staged_upload(
) -> (tempfile::TempDir, AppState, String, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, log) = audited_state(&dir);

    let upload_id = create_test_upload(state.clone(), "app/upload.bin", b"hello!").await;
    // One chunk, so the staging file actually exists on disk: `delete`
    // resolves the path before it consults the reservation, and a path that
    // is not there is a 404 long before it is a refusal.
    let patch = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{upload_id}"))
                .header("content-range", "bytes 0-5/6")
                .body(Body::from(&b"hello "[..]))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(patch.status(), StatusCode::OK);

    let staging_path = format!(".shell-tunnel-uploads/{upload_id}.part");
    (dir, state, staging_path, log)
}

/// The staging directory is this API's own artifact, and nothing removed it:
/// `list` hides it, `stat` and `delete` refuse it, so an upload left a
/// directory behind that the file API itself could not clear. Machine-wide
/// that is one per directory anyone has ever uploaded to.
///
/// Both scopes are asserted, and not because the behaviour differs: staging
/// location is one of the two seams where scope actually changes what happens
/// (`FsRoot::machine_wide` stages beside each destination, a jail stages once
/// at the root), and `release` is a new consumer of it.
#[tokio::test]
async fn completing_an_upload_reclaims_its_staging_directory_in_a_jail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, _log) = audited_state(&dir);
    let staging = dir.path().join(".shell-tunnel-uploads");

    let id = create_test_upload(state.clone(), "app/payload.bin", b"hello world").await;
    assert!(
        staging.is_dir(),
        "the staging directory must exist while a session is live"
    );

    push_and_complete(state.clone(), &id, b"hello world").await;

    assert!(
        dir.path().join("app/payload.bin").is_file(),
        "the upload must still land"
    );
    assert!(
        !staging.exists(),
        "an empty staging directory must not outlive the upload that made it"
    );
}

#[tokio::test]
async fn completing_an_upload_reclaims_its_staging_directory_machine_wide() {
    let (dir, state, base) = machine_wide_state();
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    // Machine-wide staging follows the destination rather than sitting at a
    // root, so the directory to watch is the one beside the file.
    let staging = dir.path().join("sub/.shell-tunnel-uploads");

    let id = create_test_upload(
        state.clone(),
        &format!("{base}/sub/payload.bin"),
        b"hello world",
    )
    .await;
    assert!(
        staging.is_dir(),
        "staging must exist while a session is live"
    );

    push_and_complete(state.clone(), &id, b"hello world").await;

    assert!(
        dir.path().join("sub/payload.bin").is_file(),
        "the upload must still land"
    );
    assert!(
        !staging.exists(),
        "an empty staging directory must not outlive the upload that made it"
    );
}

/// A session that ends without publishing anything is the other half: the
/// issue that prompted this saw directories left behind by abandoned uploads
/// in two subdirectories at once.
#[tokio::test]
async fn cancelling_an_upload_reclaims_its_staging_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, _log) = audited_state(&dir);
    let staging = dir.path().join(".shell-tunnel-uploads");

    let id = create_test_upload(state.clone(), "app/payload.bin", b"hello world").await;
    assert!(
        staging.is_dir(),
        "staging must exist while a session is live"
    );

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert!(
        !staging.exists(),
        "an abandoned session must not leave its directory behind"
    );
}

/// The guard that makes the reclamation safe rather than merely tidy. Two
/// sessions heading for the same directory share one staging directory
/// machine-wide, and the first to finish must not remove it out from under
/// the second — whose `.part` is still open in it.
#[tokio::test]
async fn a_sibling_session_keeps_the_staging_directory_alive() {
    let (dir, state, base) = machine_wide_state();
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    let staging = dir.path().join("sub/.shell-tunnel-uploads");

    let first = create_test_upload(
        state.clone(),
        &format!("{base}/sub/one.bin"),
        b"hello world",
    )
    .await;
    let second = create_test_upload(
        state.clone(),
        &format!("{base}/sub/two.bin"),
        b"hello world",
    )
    .await;

    push_and_complete(state.clone(), &first, b"hello world").await;
    assert!(
        staging.is_dir(),
        "a directory another session is still staging through must survive"
    );

    push_and_complete(state.clone(), &second, b"hello world").await;
    assert!(!staging.exists(), "the last session out must reclaim it");
    assert!(dir.path().join("sub/one.bin").is_file());
    assert!(dir.path().join("sub/two.bin").is_file());
}

/// Send a whole payload as one chunk and complete the session.
async fn push_and_complete(state: AppState, id: &str, payload: &[u8]) {
    let last = payload.len() - 1;
    let total = payload.len();
    let patch = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/fs/uploads/{id}"))
                .header("content-range", format!("bytes 0-{last}/{total}"))
                .body(Body::from(payload.to_vec()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(patch.status(), StatusCode::OK, "chunk must be accepted");

    let complete = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/fs/uploads/{id}/complete"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(complete.status(), StatusCode::OK, "complete must succeed");
}

/// A preview touches nothing, so an upload in flight has nothing to be
/// protected from — and "why can this tree not be removed" is exactly the
/// question a preview exists to answer. It used to be refused with the same
/// `409` as the removal, leaving the caller with no way to learn how large the
/// tree was or that an upload was what held it.
#[tokio::test]
async fn a_preview_is_not_refused_by_an_upload_in_flight() {
    let (dir, state, base) = machine_wide_state();
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("sub/keep.txt"), b"xy").expect("write");
    let _id = create_test_upload(state.clone(), &format!("{base}/sub/x.bin"), b"hello world").await;

    let response = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/fs/file?path={base}/sub&recursive=true&dry_run=true"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["dry_run"], true);
    // The signal that keeps a preview from reading as permission to proceed:
    // the removal itself is still refused while this is true.
    assert_eq!(
        body["staging_in_tree"], true,
        "a preview must say what is holding the tree: {body}"
    );
    assert!(
        body["removed"].as_u64().expect("removed") >= 2,
        "and it must actually count the tree: {body}"
    );
    assert!(
        dir.path().join("sub/keep.txt").exists(),
        "a preview removes nothing"
    );
}

/// The other half. Exempting the preview must not exempt the removal.
#[tokio::test]
async fn the_removal_is_still_refused_by_an_upload_in_flight() {
    let (dir, state, base) = machine_wide_state();
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("sub/keep.txt"), b"xy").expect("write");
    let _id = create_test_upload(state.clone(), &format!("{base}/sub/x.bin"), b"hello world").await;

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/fs/file?path={base}/sub&recursive=true"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(response).await["error"], "staging-in-tree");
    assert!(dir.path().join("sub/keep.txt").exists());
}

/// `staging_in_tree` is present on every tree answer, not only where it is
/// `true`. A field that appears just when it matters is one a client learns to
/// ignore, and its absence then reads the same as `false`.
#[tokio::test]
async fn a_clean_preview_reports_staging_in_tree_as_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app/deep")).expect("mkdir");
    std::fs::write(dir.path().join("app/a.txt"), b"xy").expect("write");
    let (state, _log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app&recursive=true&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(
        body["staging_in_tree"], false,
        "the field must be there and false, not absent: {body}"
    );
}

/// The schema calls `staging_in_tree` required on every `DeleteResult`, and
/// that schema covers a preview of a single non-directory entry as well as a
/// tree. That path built its body separately and left the field out, so a
/// client coded against the contract read `undefined` — the absence-means-false
/// failure the field's always-present rule exists to prevent, on the one route
/// that forgot the rule. Directory previews were covered; this is the sibling
/// nobody looked at.
#[tokio::test]
async fn a_single_entry_preview_carries_staging_in_tree_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("app")).expect("mkdir");
    std::fs::write(dir.path().join("app/a.txt"), b"xyz").expect("write");
    let (state, _log) = audited_state(&dir);

    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/fs/file?path=app/a.txt&dry_run=true")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["removed"], 1);
    assert_eq!(body["dry_run"], true);
    assert!(
        body.get("staging_in_tree").is_some(),
        "the field must be present, not merely falsy by omission: {body}"
    );
    assert_eq!(body["staging_in_tree"], false);
    assert!(
        dir.path().join("app/a.txt").exists(),
        "a preview removes nothing"
    );
}
