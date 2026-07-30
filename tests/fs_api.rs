//! HTTP-level tests for the filesystem API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use shell_tunnel::api::fs::MAX_LIST_LIMIT;
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
fn try_symlink(target: &std::path::Path, link: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        false
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
    if !try_symlink(&secret, &link) {
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
    // A one-file fixture cannot distinguish "clamped to MAX_LIST_LIMIT" from
    // "limit ignored entirely" or "unpaginated" — all three return the same
    // single entry. Proving the ceiling is real needs a fixture bigger than
    // it.
    let files: Vec<(String, Vec<u8>)> = (0..=MAX_LIST_LIMIT)
        .map(|i| (format!("app/f{i:05}.txt"), vec![b'x']))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_slice()))
        .collect();
    let (_dir, state) = state_with_files(&borrowed);

    let response = create_router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/fs/list?path=app&limit=999999")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Clamped, not refused: a caller asking for too much gets the ceiling,
    // not an error and not the unbounded whole tree.
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let entries = json["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), MAX_LIST_LIMIT);
    assert!(
        !json["next_cursor"].is_null(),
        "MAX_LIST_LIMIT+1 files exist; a real cap must leave one for the next page"
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

    for (method, path, expected) in fs_capability_table() {
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

    for (method, path, _) in fs_capability_table() {
        if method == Method::GET {
            assert_eq!(
                required_capability(&Method::HEAD, path),
                required_capability(&Method::GET, path),
                "HEAD {path} does not match GET's capability — HEAD falls through to Authenticated"
            );
        }
    }
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
