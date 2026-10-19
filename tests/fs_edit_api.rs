//! `POST /api/v1/fs/mkdir`, `POST /api/v1/fs/move` and `PUT /api/v1/fs/file`
//! through the real router: what each creates, what each refuses to replace,
//! and what the audit trail keeps.

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use shell_tunnel::api::handlers::AppState;
use shell_tunnel::api::router::create_router_with_state;
use shell_tunnel::audit::AuditSink;
use shell_tunnel::FsRoot;
use tower::ServiceExt;

struct Fixture {
    dir: tempfile::TempDir,
    trail: tempfile::NamedTempFile,
    state: AppState,
}

impl Fixture {
    fn new(files: &[(&str, &[u8])]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, body) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
            std::fs::write(&path, body).expect("write");
        }
        let trail = tempfile::NamedTempFile::new().expect("trail");
        let state = AppState::new()
            .with_fs_root(FsRoot::new(dir.path()).expect("root"))
            .with_audit(Arc::new(AuditSink::file(trail.path()).expect("sink")));
        Self { dir, trail, state }
    }

    fn path(&self, rel: &str) -> std::path::PathBuf {
        self.dir.path().join(rel)
    }

    async fn send(&self, method: Method, uri: &str, body: Body) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if uri.contains("/mkdir") || uri.contains("/move") || uri.ends_with("/uploads") {
            request = request.header("content-type", "application/json");
        }
        let response = create_router_with_state(self.state.clone())
            .oneshot(request.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn mkdir(&self, body: Value) -> (StatusCode, Value) {
        self.send(
            Method::POST,
            "/api/v1/fs/mkdir",
            Body::from(body.to_string()),
        )
        .await
    }

    async fn mv(&self, body: Value) -> (StatusCode, Value) {
        self.send(
            Method::POST,
            "/api/v1/fs/move",
            Body::from(body.to_string()),
        )
        .await
    }

    async fn put(&self, query: &str, bytes: Vec<u8>) -> (StatusCode, Value) {
        self.send(
            Method::PUT,
            &format!("/api/v1/fs/file?{query}"),
            Body::from(bytes),
        )
        .await
    }

    fn trail(&self) -> Vec<Value> {
        std::fs::read_to_string(self.trail.path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("a trail line is JSON"))
            .collect()
    }

    fn kinds(&self) -> Vec<String> {
        self.trail()
            .iter()
            .map(|e| e["kind"].as_str().unwrap_or_default().to_string())
            .collect()
    }
}

fn staging_parts(root: &Path) -> Vec<String> {
    std::fs::read_dir(root.join(".shell-tunnel-uploads"))
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------- mkdir

#[tokio::test]
async fn mkdir_creates_a_directory_and_records_it() {
    let fx = Fixture::new(&[]);
    let (status, body) = fx.mkdir(json!({"path": "logs"})).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body, json!({"path": "logs", "created": true}));
    assert!(fx.path("logs").is_dir());
    let trail = fx.trail();
    let entry = trail
        .iter()
        .find(|e| e["kind"] == "fs.mkdir")
        .expect("fs.mkdir");
    assert_eq!(entry["file"], "logs");
}

#[tokio::test]
async fn mkdir_needs_parents_for_a_missing_parent() {
    let fx = Fixture::new(&[]);
    let (status, body) = fx.mkdir(json!({"path": "a/b/c"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(!fx.path("a").exists(), "a refusal creates nothing");

    let (status, body) = fx.mkdir(json!({"path": "a/b/c", "parents": true})).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(fx.path("a/b/c").is_dir());
}

#[tokio::test]
async fn mkdir_on_an_existing_directory_is_a_conflict_unless_parents_accepts_it() {
    let fx = Fixture::new(&[("app/x.txt", b"x")]);
    let (status, body) = fx.mkdir(json!({"path": "app"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "exists");

    let (status, body) = fx.mkdir(json!({"path": "app", "parents": true})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["created"], false);
}

#[tokio::test]
async fn mkdir_refuses_a_file_in_the_way_even_with_parents() {
    let fx = Fixture::new(&[("app", b"a file")]);
    let (status, body) = fx.mkdir(json!({"path": "app", "parents": true})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "exists-not-directory");
    assert!(fx.kinds().contains(&"fs.mkdir.refused".to_string()));
}

#[tokio::test]
async fn mkdir_refuses_the_reserved_staging_directory_and_escapes() {
    let fx = Fixture::new(&[]);
    let (status, body) = fx
        .mkdir(json!({"path": ".shell-tunnel-uploads/x", "parents": true}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "reserved-path");

    let (status, body) = fx
        .mkdir(json!({"path": "../outside", "parents": true}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!fx.dir.path().parent().unwrap().join("outside").exists());
}

#[tokio::test]
async fn mkdir_refuses_an_unknown_field() {
    let fx = Fixture::new(&[]);
    let (status, _) = fx.mkdir(json!({"path": "x", "recursive": true})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!fx.path("x").exists());
}

// ---------------------------------------------------------------- move

#[tokio::test]
async fn move_renames_a_file_and_records_both_paths() {
    let fx = Fixture::new(&[("app/old.txt", b"payload")]);
    let (status, body) = fx
        .mv(json!({"from": "app/old.txt", "to": "app/new.txt"}))
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"from": "app/old.txt", "to": "app/new.txt", "replaced": false})
    );
    assert!(!fx.path("app/old.txt").exists());
    assert_eq!(std::fs::read(fx.path("app/new.txt")).unwrap(), b"payload");
    let trail = fx.trail();
    let entry = trail
        .iter()
        .find(|e| e["kind"] == "fs.move")
        .expect("fs.move");
    assert_eq!(entry["file"], "app/old.txt");
    assert_eq!(entry["target"], "app/new.txt");
}

#[tokio::test]
async fn move_replaces_a_file_only_when_asked() {
    let fx = Fixture::new(&[("a.txt", b"new"), ("b.txt", b"old")]);
    let (status, body) = fx.mv(json!({"from": "a.txt", "to": "b.txt"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "destination-exists");
    assert_eq!(std::fs::read(fx.path("b.txt")).unwrap(), b"old");

    let (status, body) = fx
        .mv(json!({"from": "a.txt", "to": "b.txt", "overwrite": true}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["replaced"], true);
    assert_eq!(std::fs::read(fx.path("b.txt")).unwrap(), b"new");
    assert!(!fx.path("a.txt").exists());
}

#[tokio::test]
async fn move_never_replaces_a_directory() {
    let fx = Fixture::new(&[("a.txt", b"a"), ("dir/keep.txt", b"k")]);
    let (status, body) = fx
        .mv(json!({"from": "a.txt", "to": "dir", "overwrite": true}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "destination-is-directory");
    assert!(fx.path("dir/keep.txt").exists());
}

#[tokio::test]
async fn move_carries_a_directory_and_its_contents() {
    let fx = Fixture::new(&[("src/a/b.txt", b"b")]);
    let (status, body) = fx.mv(json!({"from": "src", "to": "dst"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(std::fs::read(fx.path("dst/a/b.txt")).unwrap(), b"b");
    assert!(!fx.path("src").exists());
}

#[tokio::test]
async fn move_refuses_a_directory_into_itself() {
    let fx = Fixture::new(&[("src/a.txt", b"a")]);
    let (status, body) = fx.mv(json!({"from": "src", "to": "src/inner"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(fx.path("src/a.txt").exists());
}

#[tokio::test]
async fn move_needs_the_destination_parent_to_exist() {
    let fx = Fixture::new(&[("a.txt", b"a")]);
    let (status, body) = fx.mv(json!({"from": "a.txt", "to": "no/such/b.txt"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(fx.path("a.txt").exists());
}

#[tokio::test]
async fn move_refuses_a_missing_source_and_an_escaping_destination() {
    let fx = Fixture::new(&[("a.txt", b"a")]);
    let (status, _) = fx.mv(json!({"from": "nope.txt", "to": "b.txt"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = fx
        .mv(json!({"from": "a.txt", "to": "../escaped.txt"}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(fx.path("a.txt").exists());
    assert!(!fx.dir.path().parent().unwrap().join("escaped.txt").exists());
}

#[tokio::test]
async fn move_refuses_the_reserved_staging_directory() {
    let fx = Fixture::new(&[("a.txt", b"a")]);
    std::fs::create_dir_all(fx.path(".shell-tunnel-uploads")).unwrap();
    let (status, body) = fx
        .mv(json!({"from": "a.txt", "to": ".shell-tunnel-uploads/a.txt"}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "reserved-path");
    assert!(fx.kinds().contains(&"fs.move.refused".to_string()));
}

// ---------------------------------------------------------------- put

#[tokio::test]
async fn put_writes_a_new_file_and_reports_its_digest() {
    let fx = Fixture::new(&[("app/keep.txt", b"k")]);
    let (status, body) = fx.put("path=app/config.json", b"hello".to_vec()).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["path"], "app/config.json");
    assert_eq!(body["bytes"], 5);
    assert_eq!(body["replaced"], false);
    assert_eq!(
        body["sha256"],
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(std::fs::read(fx.path("app/config.json")).unwrap(), b"hello");
    assert!(
        staging_parts(fx.dir.path()).is_empty(),
        "nothing is left in staging after a write"
    );
    let trail = fx.trail();
    let entry = trail
        .iter()
        .find(|e| e["kind"] == "fs.write")
        .expect("fs.write");
    assert_eq!(entry["bytes"], 5);
}

#[tokio::test]
async fn put_replaces_a_file_only_when_asked() {
    let fx = Fixture::new(&[("a.txt", b"old")]);
    let (status, body) = fx.put("path=a.txt", b"new".to_vec()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "destination-exists");
    assert_eq!(std::fs::read(fx.path("a.txt")).unwrap(), b"old");

    let (status, body) = fx.put("path=a.txt&overwrite=true", b"new".to_vec()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["replaced"], true);
    assert_eq!(std::fs::read(fx.path("a.txt")).unwrap(), b"new");
}

#[tokio::test]
async fn put_never_replaces_a_directory_and_needs_a_parent() {
    let fx = Fixture::new(&[("dir/x.txt", b"x")]);
    let (status, body) = fx.put("path=dir&overwrite=true", b"y".to_vec()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "destination-is-directory");

    let (status, body) = fx.put("path=no/such/x.txt", b"y".to_vec()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// Over the per-request limit, the answer names the limit and the route that
/// takes a larger file — and is the handler's own `413`, not axum's bodyless
/// one, which is what the raised body limit on this route is for.
#[tokio::test]
async fn put_refuses_a_body_over_its_limit_and_points_at_uploads() {
    let fx = Fixture::new(&[]);
    let limit = shell_tunnel::fs::DEFAULT_CHUNK_SIZE;
    let (status, body) = fx.put("path=big.bin", vec![b'x'; limit + 1]).await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"], "body-too-large");
    assert_eq!(body["limit"], limit);
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("/api/v1/fs/uploads"));
    assert!(!fx.path("big.bin").exists());
}

#[tokio::test]
async fn put_refuses_the_reserved_staging_directory() {
    let fx = Fixture::new(&[]);
    let (status, body) = fx
        .put("path=.shell-tunnel-uploads/x.part", b"x".to_vec())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

// ---------------------------------------------------------------- capability

#[tokio::test]
async fn the_three_routes_need_fs_write() {
    use shell_tunnel::api::{create_secure_router, SecurityConfig};

    let fx = Fixture::new(&[("a.txt", b"a")]);
    let (router, store, _rl) = create_secure_router(fx.state.clone(), SecurityConfig::secure());
    store.add_key_with_capabilities("r", ["fs.read"].into_iter().collect(), "read-only");
    let router = router.layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 8080)),
    ));

    let requests = [
        (
            Method::POST,
            "/api/v1/fs/mkdir",
            json!({"path": "d"}).to_string(),
        ),
        (
            Method::POST,
            "/api/v1/fs/move",
            json!({"from": "a.txt", "to": "b.txt"}).to_string(),
        ),
        (Method::PUT, "/api/v1/fs/file?path=c.txt", "c".to_string()),
    ];
    for (method, uri, body) in requests {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .header("authorization", "Bearer r")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
    }
    assert!(fx.path("a.txt").exists());
    assert!(!fx.path("d").exists() && !fx.path("c.txt").exists());
}

/// An upload still coming would undo either write when it completes — the
/// put by overwriting it, the move by recreating the old path — so both are
/// refused while it is open, and neither is refused for a path no upload
/// names.
#[tokio::test]
async fn an_upload_in_flight_holds_its_destination_against_put_and_move() {
    let fx = Fixture::new(&[("app/keep.txt", b"k")]);
    let (status, body) = fx
        .send(
            Method::POST,
            "/api/v1/fs/uploads",
            Body::from(
                json!({"path": "app/x.bin", "size": 3, "sha256": "0".repeat(64)}).to_string(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "upload opens: {body}");

    let (status, body) = fx.put("path=app/x.bin", b"abc".to_vec()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "destination-busy");

    let (status, body) = fx.mv(json!({"from": "app", "to": "moved"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "destination-busy");
    assert!(fx.path("app/keep.txt").exists());

    let (status, body) = fx.put("path=app/other.bin", b"abc".to_vec()).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "an unclaimed path is free: {body}"
    );
}

/// With no `--fs-root`, staging sits beside the destination — and a write
/// must not leave that directory behind, the artifact an upload already
/// cleans up after itself.
#[tokio::test]
async fn a_machine_wide_put_leaves_no_staging_directory_beside_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir
        .path()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/");
    let state = AppState::new().with_fs_root(FsRoot::machine_wide());
    let response = create_router_with_state(state)
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/api/v1/fs/file?path={base}/note.txt"))
                .body(Body::from("hi"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(std::fs::read(dir.path().join("note.txt")).unwrap(), b"hi");
    let left: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["note.txt".to_string()], "only the file remains");
}
