//! `/x/<name>/…`: a request for an exposed service, passed to it over loopback
//! and its answer streamed back (`src/expose.rs` for what may be exposed).
//!
//! The upstream is spoken to in HTTP/1.1 over a fresh connection per request,
//! with `Connection: close`, and its answer is read with the same incremental
//! reader a relay device uses for its own local server (`relay::replay`). No
//! HTTP client dependency: this crate deliberately has none, and the reader is
//! already the part that has to be right.
//!
//! A WebSocket upgrade is the one exception: the service's `101` is passed back
//! and the connection becomes a byte pipe ([`upgrade_to_service`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::fs::error_response;
use super::handlers::AppState;
use crate::audit::{AuditEvent, AuditSink, Identity};
use crate::expose::{Exposure, KEY_HEADER};
use crate::relay::replay::{ReplayError, ReplayEvent, ResponseReader};

/// How long the upstream may take to accept the connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the upstream may take to send its response head.
///
/// The same bound the relay gives a device to its first frame: a service that
/// streams (server-sent events, a model generating tokens) sends its head at
/// once and its body as it goes, and a body has no total limit here.
const HEAD_TIMEOUT: Duration = Duration::from_secs(120);

/// The longest request path an `expose` audit entry carries, as for every
/// other unmatched path in the trail.
const MAX_AUDITED_PATH: usize = 256;

/// Headers this server reads and the service has no business seeing.
fn withheld_from_upstream(name: &str) -> bool {
    name.eq_ignore_ascii_case(KEY_HEADER)
        || name
            .to_ascii_lowercase()
            .starts_with("x-shell-tunnel-relay")
        || name.eq_ignore_ascii_case("content-length")
        || !crate::relay::proxy::is_forwardable(name)
}

/// What the `expose` audit entry for one request will say, written when the
/// answer is finished with — completely, cut off, or never sent.
///
/// Written on drop because the response body is streamed: the handler returns
/// long before the byte count is known, and the body can end by being
/// dropped mid-way when the caller goes away.
struct ExposeRecord {
    sink: Arc<AuditSink>,
    event: Option<AuditEvent>,
    started: Instant,
    bytes: u64,
}

impl ExposeRecord {
    fn finish_with(&mut self, status: u16) {
        if let Some(event) = self.event.as_mut() {
            event.status = Some(status);
        }
    }
}

impl Drop for ExposeRecord {
    fn drop(&mut self) {
        let Some(event) = self.event.take() else {
            return;
        };
        let event = event
            .with_bytes(self.bytes)
            .with_duration(self.started.elapsed().as_millis() as u64);
        let sink = Arc::clone(&self.sink);
        if !sink.is_enabled() {
            return;
        }
        // Off the runtime's workers: a trail write is file I/O.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || sink.record(event));
            }
            Err(_) => sink.record(event),
        }
    }
}

/// The audit `route` for a request: method and raw path, bounded, never the
/// query — which is the caller's and may carry a credential.
fn audited_route(method: &str, path: &str) -> String {
    if path.len() <= MAX_AUDITED_PATH {
        return format!("{method} {path}");
    }
    let mut end = MAX_AUDITED_PATH;
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    format!("{method} {} (truncated)", &path[..end])
}

/// The path the service is asked for: its base path, then whatever followed
/// `/x/<name>` in the request, still percent-encoded as the caller sent it.
fn upstream_target(exposure: &Exposure, request_path: &str, query: Option<&str>) -> String {
    let rest = request_path
        .strip_prefix("/x/")
        .and_then(|p| p.strip_prefix(exposure.name.as_str()))
        .unwrap_or("");
    let mut target = format!("{}{rest}", exposure.base_path);
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    target
}

/// Serve one request for an exposed service.
pub async fn proxy(
    State(state): State<AppState>,
    identity: Option<axum::Extension<Identity>>,
    axum::extract::Path(params): axum::extract::Path<std::collections::HashMap<String, String>>,
    mut request: Request,
) -> Response {
    let identity = identity.map(|axum::Extension(id)| id);
    let name = params.get("name").cloned().unwrap_or_default();
    // Taken before the request is taken apart: the handle that completes an
    // upgrade lives in the request's extensions, and is only useful if the 101
    // is answered.
    let upgrade = crate::relay::is_websocket_upgrade(request.headers())
        .then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();

    let mut record = ExposeRecord {
        sink: Arc::clone(&state.audit),
        event: Some(
            AuditEvent::new("expose")
                .with_identity(identity)
                .with_route(audited_route(&method, &path))
                .with_expose(&name),
        ),
        started: Instant::now(),
        bytes: 0,
    };

    let Some(exposure) = state.exposes.get(&name).cloned() else {
        record.finish_with(404);
        return error_response(
            StatusCode::NOT_FOUND,
            "expose-not-found",
            "this server exposes no service by that name",
        );
    };

    if let Some(upgrade) = upgrade {
        return upgrade_to_service(&state, &exposure, &name, &parts, upgrade, record).await;
    }

    // The body was read whole by the outermost layer already; this only
    // collects it. The route's own limit is that layer's ceiling.
    let body = match axum::body::to_bytes(body, crate::fs::MAX_CHUNK_SIZE).await {
        Ok(body) => body,
        Err(_) => {
            record.finish_with(413);
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body-too-large",
                "the request body exceeds what this server passes to an exposed service",
            );
        }
    };

    let target = upstream_target(&exposure, &path, parts.uri.query());
    let mut head = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    head.extend_from_slice(format!("host: {}\r\n", exposure.authority()).as_bytes());
    head.extend_from_slice(b"connection: close\r\n");
    head.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    for (header, value) in &parts.headers {
        if withheld_from_upstream(header.as_str()) {
            continue;
        }
        head.extend_from_slice(header.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");

    let connected = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(exposure.authority()),
    )
    .await;
    let stream = match connected {
        Ok(Ok(stream)) => stream,
        _ => {
            record.finish_with(502);
            return error_response(
                StatusCode::BAD_GATEWAY,
                "expose-upstream-unreachable",
                &format!(
                    "nothing accepted a connection at {}, where `{name}` is exposed",
                    exposure.url()
                ),
            );
        }
    };
    let (mut read_half, mut write_half) = stream.into_split();

    // Written from its own task, so a service that answers before reading the
    // whole request is read while the write is still going: waiting for the
    // write to finish first would deadlock against one that stops reading.
    // A failed write is not reported on its own — whether the service
    // answered is what decides the outcome.
    //
    // The write half is not shut down when done — some servers drop their
    // answer on reading end-of-file from a client — but handed to the reader,
    // which holds it for exactly as long as it reads.
    let request_bytes = [head, body.to_vec()].concat();
    let (keep_tx, keep_rx) = tokio::sync::oneshot::channel::<tokio::net::tcp::OwnedWriteHalf>();
    tokio::spawn(async move {
        let _ = write_half.write_all(&request_bytes).await;
        let _ = keep_tx.send(write_half);
    });

    // Bounded: a caller reading slowly slows this reader and, through TCP,
    // the service — rather than this server holding the whole answer.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<ReplayEvent, ReplayError>>(64);
    let reading_method = method.clone();
    tokio::spawn(async move {
        let _write_half = keep_rx;
        let mut reader = ResponseReader::for_method(&reading_method);
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // The connection's end is the end of reading, whatever the reader
            // makes of it: it either completes the body or reports it short.
            let (outcome, closed) = match read_half.read(&mut buf).await {
                Ok(0) => (reader.finish(), true),
                Ok(n) => (reader.feed(&buf[..n]), false),
                Err(_) => (Err(ReplayError::CutShort), true),
            };
            let (events, failed, ended) = match outcome {
                Ok(events) => {
                    let ended = closed || events.iter().any(|e| matches!(e, ReplayEvent::End));
                    (events, None, ended)
                }
                Err(error) => (Vec::new(), Some(error), true),
            };
            for event in events {
                if tx.send(Ok(event)).await.is_err() {
                    return;
                }
            }
            if let Some(error) = failed {
                let _ = tx.send(Err(error)).await;
                return;
            }
            if ended {
                return;
            }
        }
    });

    let head = tokio::time::timeout(HEAD_TIMEOUT, rx.recv()).await;
    let (status, headers) = match head {
        Ok(Some(Ok(ReplayEvent::Head { status, headers }))) => (status, headers),
        Err(_) => {
            record.finish_with(504);
            return error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "expose-upstream-timeout",
                &format!(
                    "the service exposed as `{name}` sent no answer within {} s",
                    HEAD_TIMEOUT.as_secs()
                ),
            );
        }
        _ => {
            record.finish_with(502);
            return error_response(
                StatusCode::BAD_GATEWAY,
                "expose-upstream-bad-answer",
                &format!(
                    "the service exposed as `{name}` closed the connection or answered with something that is not HTTP/1.1"
                ),
            );
        }
    };
    record.finish_with(status);

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    for (header, value) in headers {
        if let (Ok(header), Ok(value)) = (
            HeaderName::from_bytes(header.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            response.headers_mut().append(header, value);
        }
    }

    // The request's own count in the activity layer ends when this returns;
    // the body goes on for as long as the service sends it, so it carries a
    // count of its own. `guard` rather than `try_guard`: the request's guard
    // is still held here, so the latch cannot be closed under this one.
    let guard = state.activity.guard();
    let stream = futures_util::stream::unfold(
        (rx, record, guard),
        |(mut rx, mut record, guard)| async move {
            match rx.recv().await {
                Some(Ok(ReplayEvent::Body(bytes))) => {
                    record.bytes += bytes.len() as u64;
                    Some((Ok(axum::body::Bytes::from(bytes)), (rx, record, guard)))
                }
                // `Head` cannot repeat; `End` and a closed channel end the body.
                Some(Ok(_)) | None => None,
                // Cut off after the status went out: end the body with an
                // error, so the caller sees a broken response — never a short
                // one that reads as complete.
                Some(Err(_)) => Some((
                    Err(std::io::Error::other(
                        "the exposed service's answer was cut off",
                    )),
                    (rx, record, guard),
                )),
            }
        },
    );
    *response.body_mut() = Body::from_stream(stream);
    response.into_response()
}

/// The longest head an upstream's answer to an upgrade may have.
const MAX_UPGRADE_HEAD: usize = 64 * 1024;

/// The most of a refusal's body that is passed on when a service answers an
/// upgrade with something other than `101`.
const MAX_REFUSAL_BODY: usize = 1024 * 1024;

/// A service's answer to an upgrade request: status line and headers, and the
/// bytes of whatever followed them in the same read.
struct UpstreamHead {
    status: u16,
    headers: Vec<(String, String)>,
    rest: Vec<u8>,
}

/// Read an answer's head from the service, leaving the stream positioned after
/// the bytes returned in `rest`. `None` for anything that is not a head.
async fn read_upstream_head(stream: &mut tokio::net::TcpStream) -> Option<UpstreamHead> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        if raw.len() > MAX_UPGRADE_HEAD {
            return None;
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    Some(UpstreamHead {
        status,
        headers,
        rest: raw[head_end + 4..].to_vec(),
    })
}

/// Pass a WebSocket upgrade to the service and, if it agrees, become a pipe.
///
/// The service's own handshake is what reaches the caller — its `101`, its
/// accepted sub-protocol, its extensions — because after the head this server
/// reads no more of the connection than it writes on: bytes go both ways
/// untouched. Re-framing the messages here would mean reproducing every
/// negotiation the service might make, and a pipe cannot get one wrong.
///
/// A service that answers with anything but `101` is passed back as the plain
/// answer it gave. The connection counts as work for as long as it lasts, as
/// the WebSocket handlers' do.
async fn upgrade_to_service(
    state: &AppState,
    exposure: &Exposure,
    name: &str,
    parts: &axum::http::request::Parts,
    upgrade: hyper::upgrade::OnUpgrade,
    mut record: ExposeRecord,
) -> Response {
    let unreachable = |record: &mut ExposeRecord| {
        record.finish_with(502);
        error_response(
            StatusCode::BAD_GATEWAY,
            "expose-upstream-unreachable",
            &format!(
                "nothing accepted a connection at {}, where `{name}` is exposed",
                exposure.url()
            ),
        )
    };

    let target = upstream_target(exposure, parts.uri.path(), parts.uri.query());
    let mut head = format!("GET {target} HTTP/1.1\r\n").into_bytes();
    head.extend_from_slice(format!("host: {}\r\n", exposure.authority()).as_bytes());
    // The two hop-by-hop headers an upgrade is made of — withheld from every
    // other request, and written here as this connection's own.
    head.extend_from_slice(b"connection: Upgrade\r\nupgrade: websocket\r\n");
    for (header, value) in &parts.headers {
        if withheld_from_upstream(header.as_str()) {
            continue;
        }
        head.extend_from_slice(header.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");

    let connected = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(exposure.authority()),
    )
    .await;
    let Ok(Ok(mut stream)) = connected else {
        return unreachable(&mut record);
    };
    if stream.write_all(&head).await.is_err() {
        return unreachable(&mut record);
    }

    let answered = tokio::time::timeout(HEAD_TIMEOUT, read_upstream_head(&mut stream)).await;
    let answer = match answered {
        Ok(Some(answer)) => answer,
        Err(_) => {
            record.finish_with(504);
            return error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "expose-upstream-timeout",
                &format!(
                    "the service exposed as `{name}` sent no answer within {} s",
                    HEAD_TIMEOUT.as_secs()
                ),
            );
        }
        Ok(None) => {
            record.finish_with(502);
            return error_response(
                StatusCode::BAD_GATEWAY,
                "expose-upstream-bad-answer",
                &format!(
                    "the service exposed as `{name}` closed the connection or answered with something that is not HTTP/1.1"
                ),
            );
        }
    };
    record.finish_with(answer.status);

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let switching = answer.status == 101;
    for (header, value) in &answer.headers {
        // The body of a refusal is sent with a length of its own below.
        if !switching
            && (header.eq_ignore_ascii_case("content-length")
                || header.eq_ignore_ascii_case("transfer-encoding")
                || header.eq_ignore_ascii_case("connection"))
        {
            continue;
        }
        if let (Ok(header), Ok(value)) = (
            HeaderName::from_bytes(header.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response.headers_mut().append(header, value);
        }
    }

    if !switching {
        // A service that will not upgrade says why in a body that is passed on,
        // as far as it declared one and no further than a refusal needs.
        let declared = answer
            .headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .unwrap_or(answer.rest.len())
            .min(MAX_REFUSAL_BODY);
        let mut body = answer.rest;
        body.truncate(declared);
        let mut buf = [0u8; 4096];
        while body.len() < declared {
            let read = tokio::time::timeout(CONNECT_TIMEOUT, stream.read(&mut buf)).await;
            match read {
                Ok(Ok(n)) if n > 0 => {
                    let take = n.min(declared - body.len());
                    body.extend_from_slice(&buf[..take]);
                }
                _ => break,
            }
        }
        record.bytes = body.len() as u64;
        *response.body_mut() = Body::from(body);
        return response;
    }

    // From here the connection is a pipe, and it is work for as long as it is
    // open: the request's own count ends when this returns.
    let guard = state.activity.guard();
    let rest = answer.rest;
    tokio::spawn(async move {
        // Moved in whole: a closure captures the fields it names, and naming
        // only `record.bytes` would leave the record — whose `Drop` writes the
        // audit entry — behind, to be written as the handler returns.
        let mut record = record;
        let _guard = guard;
        let Ok(upgraded) = upgrade.await else {
            return;
        };
        let mut caller = hyper_util::rt::TokioIo::new(upgraded);
        if !rest.is_empty() {
            // The service may have sent its first frame in the same read as its
            // head; it belongs to the caller.
            if caller.write_all(&rest).await.is_err() {
                return;
            }
            record.bytes += rest.len() as u64;
        }
        if let Ok((to_service, to_caller)) =
            tokio::io::copy_bidirectional(&mut caller, &mut stream).await
        {
            record.bytes += to_service + to_caller;
        }
    });
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exposure(spec: &str) -> Exposure {
        Exposure::parse(spec).unwrap()
    }

    #[test]
    fn the_upstream_path_is_the_base_then_what_followed_the_name() {
        let llm = exposure("llm=http://127.0.0.1:8080");
        assert_eq!(
            upstream_target(&llm, "/x/llm/v1/models", None),
            "/v1/models"
        );
        assert_eq!(upstream_target(&llm, "/x/llm", None), "/");
        assert_eq!(upstream_target(&llm, "/x/llm/", Some("a=1")), "/?a=1");
        let nb = exposure("nb=http://127.0.0.1:8888/lab/");
        assert_eq!(
            upstream_target(&nb, "/x/nb/tree%20x", None),
            "/lab/tree%20x"
        );
        assert_eq!(upstream_target(&nb, "/x/nb", None), "/lab");
    }

    #[test]
    fn the_key_header_and_the_relay_hop_never_reach_the_service() {
        for name in [
            "X-Shell-Tunnel-Key",
            "x-shell-tunnel-relay-hop",
            "x-shell-tunnel-relay-streams",
            "content-length",
            "connection",
            "host",
        ] {
            assert!(withheld_from_upstream(name), "{name}");
        }
        for name in ["authorization", "content-type", "accept", "x-request-id"] {
            assert!(!withheld_from_upstream(name), "{name}");
        }
    }
}
