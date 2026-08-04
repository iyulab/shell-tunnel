//! The audit trail, written by a running server rather than by a unit test.
//!
//! What matters here is not that a struct serializes, but that a real request
//! through the real middleware and handlers leaves the right entry — and that a
//! credential never reaches the file.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use shell_tunnel::audit::{AuditEvent, AuditSink};
use shell_tunnel::{api, api::SecurityConfig, AppState, CapabilitySet};

/// Start a server with auth and an audit trail, returning its address.
async fn start(dir: &Path, key: &str, capabilities: &[&str]) -> (SocketAddr, std::path::PathBuf) {
    let trail = dir.join("audit.jsonl");
    let sink = Arc::new(AuditSink::file(&trail).unwrap());

    let mut security = SecurityConfig::secure().with_api_key(key);
    security.auth.enabled = true;
    if !capabilities.is_empty() {
        security =
            security.with_capabilities(CapabilitySet::from_iter(capabilities.iter().copied()));
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config =
        api::ServerConfig::new("127.0.0.1".to_string(), addr.port()).with_security(security);
    let state = AppState::new().with_audit(sink);

    tokio::spawn(async move {
        api::serve_on(listener, config, state).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, trail)
}

/// Minimal HTTP POST — the crate has no HTTP client dependency.
async fn post(addr: SocketAddr, path: &str, token: Option<&str>, body: &str) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n{auth}\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut raw))
        .await
        .expect("server should answer")
        .unwrap();

    String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// Read the trail, waiting briefly for the entry to land.
async fn events(trail: &Path, expected: usize) -> Vec<AuditEvent> {
    for _ in 0..50 {
        let parsed: Vec<AuditEvent> = std::fs::read_to_string(trail)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if parsed.len() >= expected {
            return parsed;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("expected {expected} audit entries");
}

#[tokio::test]
async fn an_execution_is_recorded_with_who_and_what() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "audit-key", &["exec"]).await;

    let status = post(
        addr,
        "/api/v1/execute",
        Some("audit-key"),
        r#"{"command":"echo audited"}"#,
    )
    .await;
    assert_eq!(status, 200);

    let event = events(&trail, 1).await.remove(0);
    assert_eq!(event.kind, "execute");
    assert_eq!(event.command.as_deref(), Some("echo audited"));
    assert_eq!(event.exit_code, Some(0));
    assert_eq!(event.timed_out, Some(false));
    // "someone called /execute" would be nearly useless; the caller has to be
    // identifiable across entries.
    let identity = event
        .identity
        .expect("an authenticated call has an identity");
    assert!(identity.token_id.starts_with("tok_"), "{identity:?}");

    // Round-tripping through `AuditEvent` (as `events()` does above, and as
    // every test in this file does) cannot tell "absent" from "present but
    // null": every fs-only field is an `Option`, and `serde_json` maps both
    // shapes to `None` on the way in. That makes this file, despite its
    // name, a strong *behaviour* test and a near-worthless *shape* test —
    // dropping `skip_serializing_if` from `file`/`bytes`/`entries`/
    // `digest_ok`/`upload_id` would make every event in this file grow
    // `"file":null,"bytes":null,"entries":null,"digest_ok":null,"upload_id":null`
    // and all six tests here would still pass. Parsing the raw line as a bare
    // `Value` instead — the same `contains_key` pattern `tests/fs_api.rs`
    // already uses to prove `upload.orphaned` omits `file` — is the only way
    // to prove these keys are genuinely missing from an execute event, not
    // merely null.
    let raw_line = std::fs::read_to_string(&trail).unwrap();
    let raw: serde_json::Value = serde_json::from_str(raw_line.lines().next().unwrap()).unwrap();
    let object = raw.as_object().expect("object");
    for key in ["file", "bytes", "entries", "digest_ok", "upload_id"] {
        assert!(
            !object.contains_key(key),
            "an execute event must not carry the fs-only `{key}` key at all"
        );
    }
}

#[tokio::test]
async fn a_refused_request_is_recorded_too() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "audit-key", &["exec"]).await;

    assert_eq!(
        post(addr, "/api/v1/execute", Some("wrong"), r#"{"command":"x"}"#).await,
        401
    );
    assert_eq!(
        post(addr, "/api/v1/execute", None, r#"{"command":"x"}"#).await,
        401
    );

    let recorded = events(&trail, 2).await;
    assert!(recorded.iter().all(|e| e.kind == "denied"));
    assert_eq!(recorded[0].reason.as_deref(), Some("invalid-token"));
    assert_eq!(recorded[1].reason.as_deref(), Some("missing-token"));
}

#[tokio::test]
async fn an_insufficient_capability_names_what_was_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "ro-key", &["session.read"]).await;

    assert_eq!(
        post(
            addr,
            "/api/v1/execute",
            Some("ro-key"),
            r#"{"command":"x"}"#
        )
        .await,
        403
    );

    let event = events(&trail, 1).await.remove(0);
    assert_eq!(event.status, Some(403));
    assert_eq!(event.reason.as_deref(), Some("missing-capability:exec"));
    // A 403 is a known caller doing something they may not; the trail should say
    // which caller.
    assert!(event.identity.is_some());
}

/// Minimal HTTP GET, for the paths that carry no body.
///
/// Takes the target as bytes rather than `&str` so a test can send a request
/// line no `format!` would produce.
async fn get_raw(addr: SocketAddr, target: &[u8]) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = b"GET ".to_vec();
    request.extend_from_slice(target);
    request.extend_from_slice(
        format!(" HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    stream.write_all(&request).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut raw))
        .await
        .expect("server should answer")
        .unwrap();
    String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// Two probes at different paths must leave two distinguishable entries.
///
/// They did not. A path the router does not match carries no `MatchedPath`, and
/// the entry recorded the method alone — so scanning the whole API surface
/// unauthenticated produced N byte-identical lines, and the trail asked about
/// afterwards could not say what had been probed. Measured against a running
/// server: five different requests, five identical lines.
///
/// Asserting merely that each entry *names its own path* would not catch a
/// regression that recorded, say, the method and a constant; the entries have
/// to differ from **each other**, which is the property that was lost.
#[tokio::test]
async fn two_unmatched_paths_leave_two_distinguishable_entries() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "audit-key", &["exec"]).await;

    assert_eq!(get_raw(addr, b"/nope/deep/path").await, 401);
    assert_eq!(get_raw(addr, b"/other/deep/path").await, 401);

    let recorded = events(&trail, 2).await;
    let routes: Vec<&str> = recorded
        .iter()
        .map(|e| e.route.as_deref().expect("a denial names a route"))
        .collect();
    assert_ne!(
        routes[0], routes[1],
        "two different probes must not be indistinguishable: {routes:?}"
    );
    assert_eq!(routes[0], "GET /nope/deep/path", "{routes:?}");
    assert_eq!(routes[1], "GET /other/deep/path", "{routes:?}");
}

/// The raw path is caller-controlled, so the entry it lands in is bounded.
///
/// Four kilobytes of path reaches this layer — hyper accepts it — and without a
/// bound each probe would write as much of the trail as the prober chose. The
/// `tracing` line beside the audit call was already lowered to `debug` over the
/// same worry; a log level cannot silence the trail, so the bound is where the
/// equivalent has to live.
#[tokio::test]
async fn a_long_unmatched_path_is_truncated_in_the_trail() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "audit-key", &["exec"]).await;

    let mut target = vec![b'/'];
    target.extend(std::iter::repeat(b'a').take(4000));
    assert_eq!(get_raw(addr, &target).await, 401);

    let event = events(&trail, 1).await.remove(0);
    let route = event.route.expect("a denial names a route");
    assert!(
        route.len() < 300,
        "a 4000-byte path must not land in the trail whole: {} bytes",
        route.len()
    );
    assert!(
        route.ends_with(" (truncated)"),
        "a shortened path must say it was shortened: {route}"
    );
    // The marker starts with a space, and a space cannot appear in a request
    // path — hyper answers 400 to one. So a caller cannot end a short path with
    // the marker and pass a truncated entry off as a whole one: percent-encoding
    // is what survives to this layer, and it does not decode on the way.
    assert_eq!(get_raw(addr, b"/x%20(truncated)").await, 401);
    let forged = events(&trail, 2).await.remove(1);
    assert_eq!(
        forged.route.as_deref(),
        Some("GET /x%20(truncated)"),
        "the escape must survive verbatim, or the marker is forgeable"
    );
}

/// A matched route stays a template, so entries group instead of exploding into
/// one bucket per session id. Only the unmatched case falls back to a raw path.
#[tokio::test]
async fn a_matched_route_is_recorded_as_its_template() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "ro-key", &["session.read"]).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "DELETE /api/v1/sessions/abc123 HTTP/1.1\r\nHost: {addr}\r\n\
         Authorization: Bearer ro-key\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut raw))
        .await
        .expect("server should answer")
        .unwrap();

    let event = events(&trail, 1).await.remove(0);
    assert_eq!(event.status, Some(403));
    assert_eq!(
        event.route.as_deref(),
        Some("DELETE /api/v1/sessions/{id}"),
        "the id must not reach the trail as part of the route"
    );
}

#[tokio::test]
async fn the_token_never_reaches_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "super-secret-key", &["exec"]).await;

    post(
        addr,
        "/api/v1/execute",
        Some("super-secret-key"),
        r#"{"command":"echo hi"}"#,
    )
    .await;
    post(
        addr,
        "/api/v1/execute",
        Some("guessed-key"),
        r#"{"command":"x"}"#,
    )
    .await;

    events(&trail, 2).await;
    let raw = std::fs::read_to_string(&trail).unwrap();

    // An audit trail is kept, copied, and shipped elsewhere — a credential in it
    // outlives the incident it was meant to explain.
    assert!(!raw.contains("super-secret-key"), "{raw}");
    assert!(!raw.contains("guessed-key"), "{raw}");
    assert!(!raw.contains("Bearer"), "{raw}");
}

#[test]
fn nothing_is_written_when_no_trail_is_configured() {
    // The default has to stay silent: creating files nobody asked for is its
    // own kind of surprise. The previous version of this test asserted
    // `!sink.is_enabled()`, called `record()`, and checked no filesystem
    // state at all afterward — it would have passed unchanged even if
    // `Disabled::record` wrote to some hardcoded path, since nothing was
    // ever compared against anything. `Disabled` takes no path to point it
    // at directly, so the check available here is that a directory nobody
    // told it about stays empty. Plain `#[test]`, not `#[tokio::test]`: the
    // body has never awaited anything — the async marker was a copy
    // artefact from its neighbours in this file.
    let dir = tempfile::tempdir().unwrap();

    let sink = AuditSink::Disabled;
    assert!(!sink.is_enabled());
    sink.record(AuditEvent::new("execute").with_command("echo nothing"));

    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(
        entries.is_empty(),
        "a disabled sink must create nothing, anywhere: {entries:?}"
    );
}

#[tokio::test]
async fn a_websocket_execution_is_recorded_too() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "ws-key", &["exec"]).await;

    let mut request = format!("ws://{addr}/api/v1/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", "Bearer ws-key".parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();

    socket
        .send(Message::Text(
            r#"{"type":"execute","command":"echo over-websocket"}"#.to_string(),
        ))
        .await
        .unwrap();

    // Drain until the result arrives, so the execution has finished.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), socket.next()).await {
            Ok(Some(Ok(Message::Text(text)))) if text.contains("\"result\"") => break,
            Ok(Some(Ok(_))) => continue,
            _ => break,
        }
    }

    // Streaming execution is still execution: a trail that only sees the REST
    // path would miss whichever caller preferred WebSocket.
    let event = events(&trail, 1).await.remove(0);
    assert_eq!(event.kind, "execute");
    assert_eq!(event.command.as_deref(), Some("echo over-websocket"));
    assert_eq!(event.route.as_deref(), Some("WS /api/v1/ws"));
    assert!(event.identity.is_some());
}

#[tokio::test]
async fn a_capped_execution_records_how_much_output_there_was() {
    // The response is not kept anywhere, so once a caller has a short `output`
    // the trail is the only place left to learn whether the command said more.
    // Without this field a truncated result is indistinguishable from a command
    // that simply printed little.
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "audit-key", &["exec"]).await;

    #[cfg(windows)]
    let command = "powershell -NoProfile -Command [Console]::Out.Write(('x'*65536))";
    #[cfg(unix)]
    let command = "printf 'x%.0s' $(seq 1 65536)";

    let body = serde_json::json!({ "command": command, "max_output_bytes": 4096 }).to_string();
    let status = post(addr, "/api/v1/execute", Some("audit-key"), &body).await;
    assert_eq!(status, 200);

    let event = events(&trail, 1).await.remove(0);
    assert_eq!(event.kind, "execute");
    assert_eq!(
        event.output_bytes,
        Some(65536),
        "the trail must carry what the command produced, not what was returned"
    );
}

#[tokio::test]
async fn an_uncapped_execution_carries_no_output_size() {
    // The field's *presence* is the truncation signal, so an execution that
    // returned everything must not carry it. Proven against the raw line: a
    // round-trip through `AuditEvent` cannot tell an absent key from a null
    // one, the same trap the fs-only keys above are checked against.
    let dir = tempfile::tempdir().unwrap();
    let (addr, trail) = start(dir.path(), "audit-key", &["exec"]).await;

    let status = post(
        addr,
        "/api/v1/execute",
        Some("audit-key"),
        r#"{"command":"echo short"}"#,
    )
    .await;
    assert_eq!(status, 200);

    let _ = events(&trail, 1).await;
    let raw_line = std::fs::read_to_string(&trail).unwrap();
    let raw: serde_json::Value = serde_json::from_str(raw_line.lines().next().unwrap()).unwrap();
    assert!(
        !raw.as_object()
            .expect("object")
            .contains_key("output_bytes"),
        "an execution that returned everything must not carry `output_bytes` at all"
    );
}

/// The handlers that record from an async context must keep doing so off the
/// runtime's worker threads.
///
/// `AuditSink::record` opens, writes and flushes a file. The filesystem
/// handlers already thread it into the `spawn_blocking` bodies they run in, so
/// a slow disk cannot starve the pool that also serves `/health` and the accept
/// loop; the execute, WebSocket and denial paths have no blocking body of their
/// own and called it straight from the runtime thread. They now go through
/// `record_async`.
///
/// Read off the source rather than observed at runtime, and that is a real
/// limitation worth stating: nothing here proves a worker was freed. What it
/// does prove is that the correction cannot be silently undone — reintroducing
/// a bare `record` in one of these files compiles and passes every behavioural
/// test, because the behaviour is identical and only *where it runs* differs.
/// This is the same shape as `tests/ci_feature_gates.rs`, which holds two
/// command lines to one rule the compiler cannot see either.
#[test]
fn the_async_handlers_record_without_blocking_the_runtime() {
    for file in [
        "src/api/handlers.rs",
        "src/api/websocket.rs",
        "src/api/router.rs",
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        let source = std::fs::read_to_string(&path).expect("source file is readable");
        assert!(
            !source.contains(".record("),
            "{file} calls the blocking `AuditSink::record` from an async context; \
             use `record_async` (`src/audit.rs`) — `record` belongs inside a \
             `spawn_blocking` body, as `src/api/fs.rs` uses it"
        );
    }
}
