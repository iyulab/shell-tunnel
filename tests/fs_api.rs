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

/// Guards the fail-closed trap in `required_capability`: an unmapped route
/// silently falls back to `Authenticated`, which would open every fs route to
/// any valid token. The compiler cannot catch it, so this does.
#[test]
fn every_fs_route_declares_a_capability() {
    use axum::http::Method;
    use shell_tunnel::api::router::{required_capability, RequiredCapability};

    let routes = [
        (Method::GET, "/api/v1/fs/list", "fs.read"),
        (Method::GET, "/api/v1/fs/stat", "fs.read"),
        (Method::GET, "/api/v1/fs/file", "fs.read"),
        (Method::DELETE, "/api/v1/fs/file", "fs.write"),
        (Method::POST, "/api/v1/fs/uploads", "fs.write"),
        (Method::GET, "/api/v1/fs/uploads/{id}", "fs.write"),
        (Method::PATCH, "/api/v1/fs/uploads/{id}", "fs.write"),
        (Method::POST, "/api/v1/fs/uploads/{id}/complete", "fs.write"),
        (Method::DELETE, "/api/v1/fs/uploads/{id}", "fs.write"),
    ];

    for (method, path, expected) in routes {
        assert_eq!(
            required_capability(&method, path),
            RequiredCapability::Capability(expected),
            "{method} {path} is not mapped; it would fall back to Authenticated"
        );
    }
}
