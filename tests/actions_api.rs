//! `/api/v1/actions` through the real secure router: who may run what, what a
//! refusal looks like, and what the audit trail keeps.
//!
//! The actions run this crate's own binary, because it behaves the same on
//! every platform: `--version` prints and exits 0, and an option it does not
//! know is echoed back verbatim on stderr — which is how a test sees exactly
//! which argument a parameter became.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use shell_tunnel::actions::ActionSet;
use shell_tunnel::api::{create_secure_router, AppState, SecurityConfig};
use shell_tunnel::audit::AuditSink;
use shell_tunnel::security::CapabilitySet;
use tower::ServiceExt;

const BIN: &str = env!("CARGO_BIN_EXE_shell-tunnel");

fn definitions() -> ActionSet {
    ActionSet::from_json(
        &json!({"actions": {
            "version": {"argv": [BIN, "--version"]},
            "probe": {
                "argv": [BIN, "--probe-{n}"],
                "params": {"n": {"type": "name"}},
                "timeout_secs": 20
            }
        }})
        .to_string(),
    )
    .expect("valid definitions")
}

struct App {
    router: axum::Router,
    trail: tempfile::NamedTempFile,
}

impl App {
    fn new(caps: &[&str]) -> Self {
        Self::with(caps.iter().copied().collect())
    }

    fn with(caps: CapabilitySet) -> Self {
        let trail = tempfile::NamedTempFile::new().expect("tempfile");
        let state = AppState::new()
            .with_audit(Arc::new(AuditSink::file(trail.path()).expect("sink")))
            .with_actions(definitions());
        let (router, store, _rl) = create_secure_router(state, SecurityConfig::secure());
        store.add_key_with_capabilities("t", caps, "test");
        let router = router.layer(MockConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))));
        Self { router, trail }
    }

    async fn call(&self, method: Method, uri: &str, body: Option<&str>) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer t")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.map(|b| Body::from(b.to_string())).unwrap_or_default())
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    fn trail(&self) -> Vec<Value> {
        std::fs::read_to_string(self.trail.path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("a trail line is JSON"))
            .collect()
    }
}

#[tokio::test]
async fn a_granted_action_runs_and_is_recorded_as_what_ran() {
    let app = App::new(&["action:version"]);
    let (status, body) = app
        .call(Method::POST, "/api/v1/actions/version", None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["action"], "version");
    assert_eq!(body["exit_code"], 0);
    assert!(
        body["output"]
            .as_str()
            .unwrap()
            .contains(env!("CARGO_PKG_VERSION")),
        "{body}"
    );

    let trail = app.trail();
    let entry = trail
        .iter()
        .find(|e| e["kind"] == "action")
        .expect("an action event");
    assert_eq!(entry["action"], "version");
    assert_eq!(entry["exit_code"], 0);
    assert!(
        entry["command"].as_str().unwrap().contains("--version"),
        "the trail records the argv that ran: {entry}"
    );
}

/// The point of the feature: `exec` is not an action grant, and one action is
/// not another.
#[tokio::test]
async fn a_token_without_the_action_is_refused_before_anything_runs() {
    for caps in [&["exec"][..], &["action:probe"][..], &["fs.read"][..]] {
        let app = App::new(caps);
        let (status, _) = app
            .call(Method::POST, "/api/v1/actions/version", None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "token holding {caps:?}");

        let trail = app.trail();
        assert!(
            trail.iter().any(|e| e["kind"] == "denied"
                && e["status"] == 403
                && e["reason"] == "missing-capability:action:version"),
            "{trail:?}"
        );
        assert!(
            !trail.iter().any(|e| e["kind"] == "action"),
            "nothing ran: {trail:?}"
        );
    }
}

#[tokio::test]
async fn every_action_is_granted_by_the_wildcard_action_and_by_operator() {
    for caps in [
        ["action:*"].into_iter().collect(),
        shell_tunnel::security::preset("operator").unwrap(),
        CapabilitySet::wildcard(),
    ] {
        let app = App::with(caps.clone());
        let (status, body) = app
            .call(Method::POST, "/api/v1/actions/version", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{caps:?}: {body}");
    }
}

/// A parameter becomes exactly one argument. The program echoes an option it
/// does not know, so the response shows what argv[1] was.
#[tokio::test]
async fn a_parameter_arrives_as_the_argument_it_was_defined_into() {
    let app = App::new(&["action:probe"]);
    let (status, body) = app
        .call(
            Method::POST,
            "/api/v1/actions/probe",
            Some(r#"{"params": {"n": "abc.1"}}"#),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["output"].as_str().unwrap().contains("'--probe-abc.1'"),
        "{body}"
    );
    let trail = app.trail();
    let entry = trail.iter().find(|e| e["kind"] == "action").unwrap();
    assert_eq!(entry["params"]["n"], "abc.1", "{entry}");
}

#[tokio::test]
async fn parameters_the_definition_does_not_allow_are_refused_by_name_before_running() {
    let app = App::new(&["action:probe"]);
    let cases = [
        (
            r#"{"params": {"n": "-rf"}}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            r#"{"params": {"n": "a;b"}}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (r#"{"params": {}}"#, StatusCode::UNPROCESSABLE_ENTITY),
        (
            r#"{"params": {"n": "a", "m": "b"}}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            r#"{"params": {"n": "a"}, "shell": true}"#,
            StatusCode::BAD_REQUEST,
        ),
        ("not json", StatusCode::BAD_REQUEST),
    ];
    for (body, expected) in cases {
        let (status, answer) = app
            .call(Method::POST, "/api/v1/actions/probe", Some(body))
            .await;
        assert_eq!(status, expected, "{body} → {answer}");
        if expected == StatusCode::UNPROCESSABLE_ENTITY {
            assert_eq!(answer["code"], "INVALID_PARAMS", "{answer}");
        }
    }
    let trail = app.trail();
    assert!(!trail.iter().any(|e| e["kind"] == "action"), "{trail:?}");
    assert!(
        trail
            .iter()
            .any(|e| e["status"] == 422 && e["reason"] == "invalid-param:n"),
        "{trail:?}"
    );
}

#[tokio::test]
async fn an_undefined_action_is_not_found_and_recorded() {
    let app = App::new(&["action:*"]);
    let (status, body) = app.call(Method::POST, "/api/v1/actions/nope", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ACTION_NOT_FOUND");
    assert!(app
        .trail()
        .iter()
        .any(|e| e["status"] == 404 && e["reason"] == "unknown-action:nope"));
}

/// Authorization and the handler read the id through the same decoding, so an
/// encoded spelling of a granted action is that action — and an encoded
/// spelling of another one is that other one, refused.
#[tokio::test]
async fn the_action_authorized_is_the_action_that_runs() {
    let app = App::new(&["action:version"]);
    let (status, body) = app
        .call(Method::POST, "/api/v1/actions/ver%73ion", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["action"], "version");

    let (status, _) = app
        .call(Method::POST, "/api/v1/actions/pro%62e", None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_list_names_what_this_token_may_run_and_never_how() {
    let app = App::new(&["action:probe"]);
    let (status, body) = app.call(Method::GET, "/api/v1/actions", None).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = body["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["probe"]);
    assert_eq!(body["actions"][0]["params"]["n"]["type"], "name");
    assert!(
        !body.to_string().contains("--probe"),
        "argv is the owner's, not the caller's: {body}"
    );

    let app = App::new(&["exec"]);
    let (_, body) = app.call(Method::GET, "/api/v1/actions", None).await;
    assert_eq!(body["actions"], json!([]));
}
