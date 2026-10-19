//! `/x/<name>/…` through the real secure router, against a fake upstream on
//! loopback that records what it was sent and answers as each test tells it.
//!
//! What is pinned: the service sees its own `Authorization` and never this
//! server's key; the key is read from `X-Shell-Tunnel-Key` and only there;
//! `expose:<name>` / `expose:*` decide; a streamed answer reaches the caller
//! as it is produced, counts as work while it does, and a cut-off answer
//! reaches the caller broken rather than short.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use futures_util::StreamExt;
use serde_json::Value;
use shell_tunnel::api::{create_secure_router, AppState, SecurityConfig};
use shell_tunnel::audit::AuditSink;
use shell_tunnel::expose::ExposeSet;
use shell_tunnel::security::CapabilitySet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

/// What the fake upstream received: its request head, lowercased header
/// names, and body.
#[derive(Debug)]
struct Seen {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// An upstream that answers one request with `parts`, writing each part in
/// turn and waiting on `gate` (when given) before the second.
async fn upstream(
    parts: Vec<&'static [u8]>,
    gate: Option<tokio::sync::oneshot::Receiver<()>>,
) -> (u16, tokio::sync::oneshot::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let head_end = loop {
            let n = socket.read(&mut buf).await.unwrap();
            raw.extend_from_slice(&buf[..n]);
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
        };
        let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap().to_string();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let length: usize = headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap_or(0);
        let mut body = raw[head_end + 4..].to_vec();
        while body.len() < length {
            let n = socket.read(&mut buf).await.unwrap();
            body.extend_from_slice(&buf[..n]);
        }
        let _ = seen_tx.send(Seen {
            request_line,
            headers,
            body,
        });
        let mut gate = gate;
        for (i, part) in parts.into_iter().enumerate() {
            if i == 1 {
                if let Some(gate) = gate.take() {
                    let _ = gate.await;
                }
            }
            socket.write_all(part).await.unwrap();
        }
        socket.shutdown().await.ok();
    });
    (port, seen_rx)
}

struct App {
    router: axum::Router,
    state: AppState,
    trail: tempfile::NamedTempFile,
}

impl App {
    fn new(port: u16, caps: &[&str]) -> Self {
        let trail = tempfile::NamedTempFile::new().unwrap();
        let exposes = ExposeSet::parse(&[format!("llm=http://127.0.0.1:{port}/base")]).unwrap();
        let state = AppState::new()
            .with_audit(Arc::new(AuditSink::file(trail.path()).unwrap()))
            .with_exposes(exposes);
        let (router, store, _rl) = create_secure_router(state.clone(), SecurityConfig::secure());
        let caps: CapabilitySet = caps.iter().copied().collect();
        store.add_key_with_capabilities("st-key", caps, "test");
        let router = router.layer(MockConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))));
        Self {
            router,
            state,
            trail,
        }
    }

    async fn send(&self, request: Request<Body>) -> axum::response::Response {
        self.router.clone().oneshot(request).await.unwrap()
    }

    fn trail(&self) -> Vec<Value> {
        std::fs::read_to_string(self.trail.path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn request(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder().method(method).uri(uri)
}

async fn text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Wait for the trail to hold an entry of `kind` — the `expose` entry is
/// written as the answer's body is dropped, off the request's own task.
async fn entry(app: &App, kind: &str) -> Value {
    for _ in 0..100 {
        if let Some(e) = app.trail().into_iter().find(|e| e["kind"] == kind) {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no {kind} entry in {:?}", app.trail());
}

#[tokio::test]
async fn a_request_reaches_the_service_with_its_own_credential_and_never_this_servers_key() {
    let (port, seen) = upstream(
        vec![b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-type: text/plain\r\n\r\nhello"],
        None,
    )
    .await;
    let app = App::new(port, &["expose:llm"]);

    let response = app
        .send(
            request("POST", "/x/llm/v1/chat?stream=true")
                .header("x-shell-tunnel-key", "st-key")
                .header("authorization", "Bearer service-secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"q":1}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/plain");
    assert_eq!(text(response).await, "hello");

    let seen = seen.await.unwrap();
    assert_eq!(seen.request_line, "POST /base/v1/chat?stream=true HTTP/1.1");
    assert_eq!(seen.header("authorization"), Some("Bearer service-secret"));
    assert_eq!(
        seen.header("host"),
        Some(format!("127.0.0.1:{port}").as_str())
    );
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert!(seen.header("x-shell-tunnel-key").is_none(), "{seen:?}");
    assert_eq!(seen.body, br#"{"q":1}"#);

    let e = entry(&app, "expose").await;
    assert_eq!(e["expose"], "llm");
    assert_eq!(e["status"], 200);
    assert_eq!(e["bytes"], 5);
    assert_eq!(
        e["route"], "POST /x/llm/v1/chat",
        "the query is never recorded"
    );
    assert_eq!(e["identity"]["label"], "test");
}

#[tokio::test]
async fn a_chunked_answer_arrives_whole() {
    let (port, _seen) = upstream(
        vec![b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"],
        None,
    )
    .await;
    let app = App::new(port, &["expose:*"]);
    let response = app
        .send(
            request("GET", "/x/llm/")
                .header("x-shell-tunnel-key", "st-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(text(response).await, "hello world");
}

#[tokio::test]
async fn the_key_is_read_from_its_own_header_and_only_there() {
    let (port, _seen) = upstream(vec![b"HTTP/1.1 204 No Content\r\n\r\n"], None).await;
    let app = App::new(port, &["expose:llm"]);

    // No key at all.
    let response = app
        .send(request("GET", "/x/llm/").body(Body::empty()).unwrap())
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // This server's key in `Authorization` is the service's header there, and
    // is not taken for a key.
    let response = app
        .send(
            request("GET", "/x/llm/")
                .header("authorization", "Bearer st-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .send(
            request("GET", "/x/llm/")
                .header("x-shell-tunnel-key", "st-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_service_is_reached_only_with_its_own_grant_or_the_wildcard() {
    for (caps, expected) in [
        (&["exec", "fs.read", "action:*"][..], StatusCode::FORBIDDEN),
        (&["expose:other"][..], StatusCode::FORBIDDEN),
        (&["expose:llm"][..], StatusCode::NO_CONTENT),
        (&["expose:*"][..], StatusCode::NO_CONTENT),
        (&["*"][..], StatusCode::NO_CONTENT),
    ] {
        let (port, _seen) = upstream(vec![b"HTTP/1.1 204 No Content\r\n\r\n"], None).await;
        let app = App::new(port, caps);
        let response = app
            .send(
                request("GET", "/x/llm")
                    .header("x-shell-tunnel-key", "st-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), expected, "{caps:?}");
        if expected == StatusCode::FORBIDDEN {
            let denied = entry(&app, "denied").await;
            assert_eq!(
                denied["reason"], "missing-capability:expose:llm",
                "{denied}"
            );
        }
    }
}

#[tokio::test]
async fn a_name_nothing_is_exposed_under_answers_404() {
    let (port, _seen) = upstream(vec![b"HTTP/1.1 204 No Content\r\n\r\n"], None).await;
    let app = App::new(port, &["expose:*"]);
    let response = app
        .send(
            request("GET", "/x/nope/")
                .header("x-shell-tunnel-key", "st-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_str(&text(response).await).unwrap();
    assert_eq!(body["error"], "expose-not-found");
}

#[tokio::test]
async fn a_service_that_is_not_running_answers_502_and_says_so() {
    // A port that was free a moment ago and has nothing listening on it.
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let app = App::new(port, &["expose:llm"]);
    let response = app
        .send(
            request("GET", "/x/llm/")
                .header("x-shell-tunnel-key", "st-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = serde_json::from_str(&text(response).await).unwrap();
    assert_eq!(body["error"], "expose-upstream-unreachable");
    assert_eq!(entry(&app, "expose").await["status"], 502);
}

/// An answer the service cuts off after its head reaches the caller broken —
/// never as a short body that reads as complete.
#[tokio::test]
async fn an_answer_cut_off_midway_is_delivered_broken() {
    let (port, _seen) = upstream(
        vec![b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nonly ten b"],
        None,
    )
    .await;
    let app = App::new(port, &["expose:llm"]);
    let response = app
        .send(
            request("GET", "/x/llm/")
                .header("x-shell-tunnel-key", "st-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .is_err(),
        "a body short of its declared length must end in an error"
    );
}

/// A streamed answer arrives as the service sends it, and holds an update off
/// for as long as it is still going — after the handler has returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_answer_arrives_as_sent_and_counts_as_work_until_it_ends() {
    let (gate_tx, gate_rx) = tokio::sync::oneshot::channel();
    let (port, _seen) = upstream(
        vec![
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\nd\r\ndata: first\n\n\r\n",
            b"e\r\ndata: second\n\n\r\n0\r\n\r\n",
        ],
        Some(gate_rx),
    )
    .await;
    let app = App::new(port, &["expose:llm"]);
    let response = app
        .send(
            request("GET", "/x/llm/events")
                .header("x-shell-tunnel-key", "st-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();

    let first = tokio::time::timeout(Duration::from_secs(10), body.next())
        .await
        .expect("the first event should arrive before the service sends the second")
        .unwrap()
        .unwrap();
    assert_eq!(first.as_ref(), b"data: first\n\n");
    assert_eq!(
        app.state.activity.in_flight(),
        1,
        "the handler has returned; the body still streaming is the one unit of work"
    );
    assert!(
        !app.state.activity.latch(),
        "nothing may latch while it streams"
    );

    gate_tx.send(()).unwrap();
    let mut rest = Vec::new();
    while let Some(chunk) = body.next().await {
        rest.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(rest, b"data: second\n\n");
    assert_eq!(app.state.activity.in_flight(), 0);
}
