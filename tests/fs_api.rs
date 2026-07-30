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
    let link = root.path().join("app").join("linked.txt");
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

    // Recursive directory removal is deliberately out of scope: it belongs
    // with the destructive-operation guards, not with transfer.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(dir.path().join("app/a.txt").exists());
}

#[tokio::test]
async fn delete_refuses_a_path_outside_the_root() {
    let (_dir, state) = state_with_files(&[("app/a.txt", b"a")]);
    let app = create_router_with_state(state);

    let response = app
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
}

/// A request whose final component is `..` passes the full-path resolution
/// (`resolve_existing("app/..")` walks straight back to a real directory —
/// the root itself here — not out of the root), so nothing upstream refuses
/// it. Without an explicit check, the only thing standing between this and
/// deleting the root is that `X/..` always names a directory — an accident
/// that disappears the day recursive directory removal ships. See the
/// comment in `delete_file_blocking` for why a containment check on the
/// joined path cannot substitute for refusing `..` outright.
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

/// A third accident in the same shape as the `..` and `.` guards: `named =
/// parent.join(name)` assumes `name` appends exactly one ordinary component,
/// but `PathBuf::join` discards `parent` entirely for an argument carrying a
/// prefix (`Path::new(r"C:\root\app").join("C:evil")` is `"C:evil"` — the
/// parent is gone).
///
/// Unlike the `..`/`.` cases, this one is not currently reachable: the
/// full-path `resolve_existing` call at the top of `delete_file_blocking`
/// already runs `check_component` (which rejects `:`) over the same last
/// component before this handler's own local guard is ever reached, so
/// removing that local guard does not turn this test red today — confirmed
/// by disabling it and re-running. This test pins the outcome (400) that
/// must hold regardless of which layer produces it, so a future change to
/// `FsRoot::components`'s policy of validating the last component (not to
/// `check_component` itself, but to whether the caller still applies it
/// there) cannot silently make `path=app/C:evil` succeed.
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
