//! `/api/v1/processes` through the real router: start a command, read its
//! output by offset while it runs and after, feed its stdin, signal and end it.
//!
//! Every command here is one the platform shell runs itself (`echo`, `sort`,
//! `ping`/`sleep`) — no interpreter whose startup time would decide a test.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use shell_tunnel::api::handlers::AppState;
use shell_tunnel::api::router::create_router_with_state;
use shell_tunnel::audit::AuditSink;
use tower::ServiceExt;

/// A command that runs for a long time and prints nothing, killed by the test.
fn long_running() -> &'static str {
    if cfg!(windows) {
        "ping -n 120 127.0.0.1 >nul"
    } else {
        "sleep 120"
    }
}

/// Whether a pid names a live process — asked of the OS, not of the table.
fn alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .expect("tasklist");
        String::from_utf8_lossy(&out.stdout).contains(&pid.to_string())
    }
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

struct Api {
    state: AppState,
    trail: tempfile::NamedTempFile,
}

impl Api {
    fn new() -> Self {
        let trail = tempfile::NamedTempFile::new().unwrap();
        let state = AppState::new().with_audit(Arc::new(AuditSink::file(trail.path()).unwrap()));
        Self { state, trail }
    }

    async fn call(&self, method: Method, uri: &str, body: Body) -> (StatusCode, Value) {
        let response = create_router_with_state(self.state.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn start(&self, body: Value) -> u64 {
        let (status, info) = self
            .call(
                Method::POST,
                "/api/v1/processes",
                Body::from(body.to_string()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{info}");
        info["id"].as_u64().expect("an id")
    }

    /// Read a stream to completion by following `next`, long-polling.
    async fn read_all(&self, id: u64, stream: &str) -> String {
        let mut since = 0;
        let mut text = String::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (status, read) = self
                .call(
                    Method::GET,
                    &format!(
                        "/api/v1/processes/{id}/output?stream={stream}&since={since}&wait_ms=5000"
                    ),
                    Body::empty(),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{read}");
            assert_eq!(read["start"], since, "no bytes were discarded");
            text.push_str(read["text"].as_str().unwrap());
            since = read["next"].as_u64().unwrap();
            if read["complete"] == true {
                return text;
            }
            assert!(Instant::now() < deadline, "the stream never completed");
        }
    }

    fn kinds(&self) -> Vec<Value> {
        std::fs::read_to_string(self.trail.path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn a_started_command_is_read_to_its_end_by_offset() {
    let api = Api::new();
    let id = api.start(json!({"command": "echo hello-process"})).await;

    let text = api.read_all(id, "stdout").await;
    assert!(text.contains("hello-process"), "{text:?}");

    let (status, info) = api
        .call(
            Method::GET,
            &format!("/api/v1/processes/{id}"),
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["state"], "exited");
    assert_eq!(info["exit_code"], 0);
    assert_eq!(info["output_complete"], true);
    assert_eq!(info["stdout_end"], text.len());

    // Reading past the end answers at once, empty, and still complete.
    let end = info["stdout_end"].as_u64().unwrap();
    let (_, read) = api
        .call(
            Method::GET,
            &format!("/api/v1/processes/{id}/output?since={end}&wait_ms=20000"),
            Body::empty(),
        )
        .await;
    assert_eq!(read["text"], "");
    assert_eq!(read["complete"], true);

    let trail = api.kinds();
    let start = trail.iter().find(|e| e["kind"] == "process.start").unwrap();
    assert_eq!(start["process_id"], id);
    assert_eq!(start["command"], "echo hello-process");
    let exit = trail.iter().find(|e| e["kind"] == "process.exit").unwrap();
    assert_eq!(exit["process_id"], id);
    assert_eq!(exit["exit_code"], 0);
}

#[tokio::test]
async fn stdout_and_stderr_are_separate_streams_with_their_own_offsets() {
    let api = Api::new();
    let id = api
        .start(json!({"command": "echo to-out && echo to-err 1>&2"}))
        .await;
    let out = api.read_all(id, "stdout").await;
    let err = api.read_all(id, "stderr").await;
    assert!(out.contains("to-out") && !out.contains("to-err"), "{out:?}");
    assert!(err.contains("to-err") && !err.contains("to-out"), "{err:?}");
}

/// The point of a handle: output written while nobody was reading is still
/// there when somebody reads.
#[tokio::test]
async fn output_written_before_anyone_reads_is_kept() {
    let api = Api::new();
    let id = api.start(json!({"command": "echo early"})).await;
    // Wait for the exit without reading any output.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let info = api.state.processes.info(id).unwrap();
        if info.output_complete {
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(api.read_all(id, "stdout").await.contains("early"));
}

#[tokio::test]
async fn stdin_written_and_closed_reaches_the_process() {
    let api = Api::new();
    let id = api.start(json!({"command": "sort", "stdin": true})).await;
    let (status, body) = api
        .call(
            Method::POST,
            &format!("/api/v1/processes/{id}/stdin?close=true"),
            Body::from("pear\napple\n"),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let text = api.read_all(id, "stdout").await;
    let apple = text.find("apple").expect("apple");
    let pear = text.find("pear").expect("pear");
    assert!(
        apple < pear,
        "sort read both lines and the end of input: {text:?}"
    );

    let trail = api.kinds();
    let entry = trail.iter().find(|e| e["kind"] == "process.stdin").unwrap();
    assert_eq!(entry["bytes"], 11, "the trail records how much, never what");
    assert!(entry.get("command").is_none());
}

#[tokio::test]
async fn stdin_is_refused_when_it_was_not_asked_for() {
    let api = Api::new();
    let id = api.start(json!({"command": long_running()})).await;
    let (status, body) = api
        .call(
            Method::POST,
            &format!("/api/v1/processes/{id}/stdin"),
            Body::from("x"),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "stdin-unavailable");
    api.state.processes.shutdown();
}

#[tokio::test]
async fn kill_ends_a_running_process_and_its_exit_is_reported() {
    let api = Api::new();
    let id = api.start(json!({"command": long_running()})).await;
    assert!(
        !shell_tunnel::api::activity::is_idle(&api.state),
        "a running process is work a restart would lose"
    );

    let (status, body) = api
        .call(
            Method::POST,
            &format!("/api/v1/processes/{id}/signal"),
            Body::from(json!({"signal": "kill"}).to_string()),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    let deadline = Instant::now() + Duration::from_secs(30);
    while api.state.processes.info(id).unwrap().state == "running" {
        assert!(Instant::now() < deadline, "kill did not end the process");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(shell_tunnel::api::activity::is_idle(&api.state));

    let (status, body) = api
        .call(
            Method::POST,
            &format!("/api/v1/processes/{id}/signal"),
            Body::from(json!({"signal": "kill"}).to_string()),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "process-not-running");
}

#[tokio::test]
async fn interrupt_is_unsupported_on_windows_and_delivered_elsewhere() {
    let api = Api::new();
    let id = api.start(json!({"command": long_running()})).await;
    let (status, body) = api
        .call(
            Method::POST,
            &format!("/api/v1/processes/{id}/signal"),
            Body::from(json!({"signal": "interrupt"}).to_string()),
        )
        .await;
    if cfg!(windows) {
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "signal-unsupported");
    } else {
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    }
    api.state.processes.shutdown();
}

#[tokio::test]
async fn delete_ends_a_running_process_and_forgets_the_handle() {
    let api = Api::new();
    let id = api.start(json!({"command": long_running()})).await;
    let pid = api.state.processes.info(id).unwrap().pid;
    assert!(alive(pid), "the process is running before the delete");
    let (status, _) = api
        .call(
            Method::DELETE,
            &format!("/api/v1/processes/{id}"),
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!alive(pid), "delete ended the process, not only the handle");
    let (status, body) = api
        .call(
            Method::GET,
            &format!("/api/v1/processes/{id}"),
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "process-not-found");
    assert!(shell_tunnel::api::activity::is_idle(&api.state));
    let trail = api.kinds();
    let entry = trail
        .iter()
        .find(|e| e["kind"] == "process.delete")
        .unwrap();
    assert_eq!(entry["reason"], "ended");
}

/// A long-poll answers when output arrives, not when its wait runs out.
#[tokio::test]
async fn a_waiting_read_returns_as_soon_as_output_arrives() {
    let api = Api::new();
    let id = api
        .start(json!({"command": long_running(), "stdin": false}))
        .await;
    // Nothing will arrive from this one: the wait runs to its bound.
    let started = Instant::now();
    let (_, read) = api
        .call(
            Method::GET,
            &format!("/api/v1/processes/{id}/output?wait_ms=300"),
            Body::empty(),
        )
        .await;
    assert_eq!(read["text"], "");
    assert_eq!(read["complete"], false);
    assert!(started.elapsed() >= Duration::from_millis(250));
    api.state.processes.shutdown();

    // This one prints at once; a 20 s wait must not be what the caller pays.
    let id = api.start(json!({"command": "echo prompt"})).await;
    let started = Instant::now();
    let (_, read) = api
        .call(
            Method::GET,
            &format!("/api/v1/processes/{id}/output?wait_ms=20000"),
            Body::empty(),
        )
        .await;
    assert!(read["text"].as_str().unwrap().contains("prompt"), "{read}");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "returned on output, not on the wait bound"
    );
}

#[tokio::test]
async fn shutdown_ends_every_running_process() {
    let api = Api::new();
    let a = api.start(json!({"command": long_running()})).await;
    let b = api.start(json!({"command": long_running()})).await;
    assert_eq!(api.state.processes.running_count(), 2);
    let pids = [
        api.state.processes.info(a).unwrap().pid,
        api.state.processes.info(b).unwrap().pid,
    ];
    drop(api.state.processes.shutdown_on_drop());
    assert_eq!(api.state.processes.running_count(), 0);
    assert!(
        pids.iter().all(|pid| !alive(*pid)),
        "the processes are gone"
    );
    assert!(api.state.processes.info(a).is_err() && api.state.processes.info(b).is_err());
}

#[tokio::test]
async fn an_unknown_field_and_an_unknown_stream_are_refused() {
    let api = Api::new();
    let (status, _) = api
        .call(
            Method::POST,
            "/api/v1/processes",
            Body::from(json!({"command": "echo x", "timeout_secs": 5}).to_string()),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(api.state.processes.list().is_empty(), "nothing was started");

    let id = api.start(json!({"command": "echo x"})).await;
    let (status, _) = api
        .call(
            Method::GET,
            &format!("/api/v1/processes/{id}/output?stream=both"),
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn every_process_route_needs_exec() {
    use shell_tunnel::api::{create_secure_router, SecurityConfig};

    let state = AppState::new();
    let (router, store, _rl) = create_secure_router(state.clone(), SecurityConfig::secure());
    store.add_key_with_capabilities("r", ["fs.read"].into_iter().collect(), "fs-only");
    let router = router.layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 8080)),
    ));
    for (method, uri) in [
        (Method::POST, "/api/v1/processes"),
        (Method::GET, "/api/v1/processes"),
        (Method::GET, "/api/v1/processes/0"),
        (Method::GET, "/api/v1/processes/0/output"),
        (Method::POST, "/api/v1/processes/0/stdin"),
        (Method::POST, "/api/v1/processes/0/signal"),
        (Method::DELETE, "/api/v1/processes/0"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .header("authorization", "Bearer r")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"command": "echo x"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
    }
    assert!(state.processes.list().is_empty());
}
