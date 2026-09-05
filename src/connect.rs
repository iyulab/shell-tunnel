//! `shell-tunnel connect`: a local reverse-proxy to one relay-attached device.
//!
//! Unlike the gateway, this process serves no fs/session API of its own —
//! its one route forwards to the relay's existing public `/d/<device>/...`
//! path (`relay::client::send_to_relay`), the same path an ordinary HTTP
//! client could already reach directly. See
//! `claudedocs/plans/2026-09-04-p2p-direct-transfer-phase2-plan.md`.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::relay::client::{send_to_relay, RelayClientConfig};

/// How long `connect` may sit with no forwarded request before it exits on
/// its own.
///
/// The same hour [`session::IDLE_TTL`](crate::session::IDLE_TTL) and
/// `fs::SESSION_TTL` already use for "how long does an abandoned thing stay
/// alive?" on this product — kept as `connect`'s own constant rather than a
/// third use of either of those, because this is a different resource (a
/// whole local process, not a session or upload) and may need to move
/// independently, exactly as `session::IDLE_TTL`'s own doc comment reasons
/// about the same relationship to `fs::SESSION_TTL`.
///
/// A safety net for a caller script that forgot to stop this process, or
/// died without cleaning it up — not a normal way to end a session, so an
/// hour is deliberately generous rather than tuned tight.
pub const CONNECT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// Shared last-activity clock for the idle-shutdown watchdog: nanoseconds
/// since `epoch`, bumped by [`track_activity`] on every request the router
/// actually handles (including a 404 for the wrong device — anything that
/// reached this process counts as activity; only true silence should exit).
///
/// `epoch` is `tokio::time::Instant`, not `std::time::Instant`: the former is
/// what `tokio::time::pause`/`advance` actually virtualize in tests — the
/// latter reads the real OS clock regardless, which made an early version of
/// `idle_clock_reports_expired_only_after_the_full_timeout` fail: the
/// interval below ticked on virtual time (correctly, near-instantly under
/// `advance`), but each tick's `idle_for()` check read real elapsed
/// microseconds and could never reach a 60-second threshold inside a test
/// that runs in milliseconds. Outside tests `tokio::time::Instant` behaves
/// identically to the real clock, so this costs nothing in production.
#[derive(Clone)]
struct IdleClock {
    epoch: tokio::time::Instant,
    last_activity_nanos: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl IdleClock {
    fn new() -> Self {
        Self {
            epoch: tokio::time::Instant::now(),
            last_activity_nanos: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    fn touch(&self) {
        let nanos = self.epoch.elapsed().as_nanos() as u64;
        self.last_activity_nanos
            .store(nanos, std::sync::atomic::Ordering::Relaxed);
    }

    fn idle_for(&self) -> std::time::Duration {
        let last = self
            .last_activity_nanos
            .load(std::sync::atomic::Ordering::Relaxed);
        self.epoch
            .elapsed()
            .saturating_sub(std::time::Duration::from_nanos(last))
    }

    /// Resolves once no request has arrived for `timeout`. Polls rather than
    /// sleeping once for the full timeout so a request that arrives with 1ms
    /// left still resets the countdown, not just delays a shutdown that was
    /// already decided.
    async fn expired(&self, timeout: std::time::Duration) {
        let mut ticker = tokio::time::interval(timeout / 4);
        loop {
            ticker.tick().await;
            if self.idle_for() >= timeout {
                return;
            }
        }
    }
}

async fn track_activity(
    axum::extract::State(clock): axum::extract::State<IdleClock>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    clock.touch();
    next.run(request).await
}

#[derive(Clone)]
struct ConnectState {
    config: std::sync::Arc<RelayClientConfig>,
    peer: std::sync::Arc<str>,
}

/// Build the router: one catch-all route, forwarding only requests addressed
/// to `peer` and rejecting a WebSocket upgrade (Phase 3 territory — direct
/// connectivity is what makes a long-lived upgrade worth piping through this
/// process; forwarding it over the relay path today would just be another
/// name for the fallback the design already has).
///
/// A bare async function is already a `Handler` for every HTTP method at
/// once, which is what a catch-all needs — `Router::fallback(forward)`
/// directly, no `axum::routing::any(...)` wrapper needed.
pub(crate) fn router(config: RelayClientConfig, peer: String) -> Router {
    let state = ConnectState {
        config: std::sync::Arc::new(config),
        peer: std::sync::Arc::from(peer.as_str()),
    };
    Router::new().fallback(forward).with_state(state)
}

async fn forward(State(state): State<ConnectState>, request: Request) -> Response {
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let Some((device_id, _tail)) = crate::relay::proxy::split_device_path(&path_and_query) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if device_id != &*state.peer {
        return StatusCode::NOT_FOUND.into_response();
    }

    if crate::relay::is_websocket_upgrade(request.headers()) {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "WebSocket forwarding needs direct connectivity (Phase 3); this build only relays plain HTTP",
        )
            .into_response();
    }

    let method = request.method().to_string();
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();

    let body = match axum::body::to_bytes(request.into_body(), crate::relay::MAX_RELAY_FRAME).await
    {
        Ok(body) => body.to_vec(),
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    let (status, resp_headers, resp_body) =
        send_to_relay(&state.config, &method, &path_and_query, &headers, body).await;

    let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers {
        builder = builder.header(name, value);
    }
    builder
        .body(axum::body::Body::from(resp_body))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

/// Run `connect` mode until it is told to stop: bind a local listener,
/// forward everything on it to `peer` via the relay, and attach to the same
/// relay as an ephemeral, unnamed device.
///
/// The ephemeral attach carries no traffic in this phase — nothing addresses
/// this device's URL, since nobody but this process itself knows its
/// identity. It exists now so Phase 3's direct-connectivity signalling has a
/// control channel to run over without this process's lifecycle needing to
/// change shape later. Confirmed safe to leave inert: the relay strips the
/// `/d/<id>` prefix before forwarding anything to an attached device, and
/// this device's own local listener at `config.local` never receives
/// anything but Phase 3 candidate-exchange traffic once that exists — Task
/// 1-3 send it none.
///
/// `bound` reports the address actually bound, once it is known — `None`
/// means nobody's listening, matching `RelayClientConfig::enrolled`'s own
/// "the client used to `println!` the URL itself, which put a piece of the
/// binary's startup banner inside the library" reasoning (`src/relay/client.rs`):
/// `outln!`/`errln!` are defined in `src/main.rs`, not exported from this
/// library crate, so this function cannot print the banner itself even if it
/// wanted to — reporting the event and leaving the wording to the caller is
/// not a style choice here, it is the only option, and it is also what keeps
/// this function callable from a test with no banner at all.
///
/// Returns when the local server task ends (it does not, until the process
/// is asked to stop — see Task 4) or the relay attach loop returns an error.
pub async fn serve(
    mut config: RelayClientConfig,
    peer: String,
    local_port: u16,
    idle_timeout: std::time::Duration,
    bound: Option<tokio::sync::oneshot::Sender<std::net::SocketAddr>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> crate::Result<()> {
    // `relay::client::run` already installs this once it reaches its own
    // first `wss://` dial (`src/relay/client.rs:193`), but `send_to_relay`'s
    // TLS path (Task 2) can be reached by an incoming request the instant the
    // local listener starts serving — which races that dial, not follows it,
    // since both run concurrently in the `tokio::select!` below. Installing
    // it here, before either starts, removes the race rather than hoping the
    // relay attach wins it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(crate::ShellTunnelError::Io)?;
    let local_addr = listener.local_addr().map_err(crate::ShellTunnelError::Io)?;
    config.local = local_addr;

    if let Some(tx) = bound {
        let _ = tx.send(local_addr);
    }

    // Cloned before `router` takes ownership of `peer` below — kept only for
    // the idle-shutdown log line, which is worth naming the peer in ("idle,
    // stopped forwarding to box1" tells an operator which process just
    // exited; "idle, shutting down" on its own does not, once more than one
    // connect process might be running).
    let peer_for_log = peer.clone();
    let clock = IdleClock::new();
    let router = router(config.clone(), peer).layer(axum::middleware::from_fn_with_state(
        clock.clone(),
        track_activity,
    ));
    let idle_watchdog = {
        let clock = clock.clone();
        async move { clock.expired(idle_timeout).await }
    };

    let server = tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async move {
                tokio::select! {
                    _ = shutdown => {}
                    _ = idle_watchdog => {
                        tracing::info!(
                            "connect: idle for {:?}, stopped forwarding to {peer_for_log}",
                            idle_timeout
                        );
                    }
                }
            })
            .await
            .map_err(|e| crate::ShellTunnelError::Io(std::io::Error::other(e.to_string())))
    });

    tokio::select! {
        result = server => result.expect("connect server task panicked"),
        result = crate::relay::client::run(config) => result,
    }
}

/// Attach `config` and serve `peer` until Ctrl-C/SIGTERM or
/// [`CONNECT_IDLE_TIMEOUT`] of inactivity, whichever comes first. What
/// `main.rs`'s `run_connect` actually calls; `bound` lets the caller learn
/// the port before printing the banner (`outln!` lives in `main.rs`, not
/// this library — see `serve`'s own doc comment, Task 3).
pub async fn serve_until_idle(
    config: RelayClientConfig,
    peer: String,
    local_port: u16,
    bound: Option<tokio::sync::oneshot::Sender<std::net::SocketAddr>>,
) -> crate::Result<()> {
    serve(
        config,
        peer,
        local_port,
        CONNECT_IDLE_TIMEOUT,
        bound,
        shutdown_signal_for_connect(),
    )
    .await
}

/// Ctrl-C/SIGTERM, exactly as `api::router::shutdown_signal` — kept as its
/// own small copy rather than a cross-module `pub(crate)` export, since this
/// is the only other place in the crate that needs it and the body is short.
async fn shutdown_signal_for_connect() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::client::RelayClientConfig;

    fn test_config(relay_url: &str) -> RelayClientConfig {
        RelayClientConfig {
            relay_url: relay_url.to_string(),
            enroll_token: "secret".to_string(),
            local: "127.0.0.1:1".parse().unwrap(),
            label: None,
            device_name: None,
            fingerprint: None,
            ca_file: None,
            enrolled: None,
        }
    }

    #[tokio::test(start_paused = true, flavor = "current_thread")]
    async fn idle_clock_reports_expired_only_after_the_full_timeout() {
        let clock = IdleClock::new();
        let timeout = std::time::Duration::from_secs(60);

        let expired = tokio::spawn({
            let clock = clock.clone();
            async move {
                clock.expired(timeout).await;
            }
        });

        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        assert!(!expired.is_finished());
        clock.touch(); // activity resets the countdown
        tokio::time::advance(std::time::Duration::from_secs(45)).await;
        assert!(
            !expired.is_finished(),
            "touch() should have reset the clock"
        );

        tokio::time::advance(std::time::Duration::from_secs(20)).await;
        // Awaiting the handle directly (rather than polling `is_finished()`
        // after a bare `yield_now()`) is what actually proves completion —
        // `is_finished()` reflects whatever the executor has gotten around to
        // scheduling, which one yield does not guarantee even with virtual
        // time already advanced past the deadline. The outer `timeout` is a
        // safety net against a real bug hanging the test, not the thing
        // doing the waiting: with `IdleClock::epoch` as `tokio::time::Instant`
        // (see its doc comment), the paused clock resolves this the instant
        // `expired`'s own interval next ticks — no real wall-clock wait.
        tokio::time::timeout(std::time::Duration::from_secs(5), expired)
            .await
            .expect("expired() should have resolved once the full timeout elapsed")
            .expect("the spawned task should not have panicked");
    }

    #[tokio::test]
    async fn a_request_for_a_different_device_is_404() {
        let router = router(test_config("http://127.0.0.1:1"), "box1".to_string());
        let response = axum::http::Request::builder()
            .uri("/d/other-device/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tower::ServiceExt::oneshot(router, response).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_request_for_the_configured_peer_is_forwarded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = tokio::io::AsyncReadExt::read(&mut socket, &mut buf)
                .await
                .unwrap();
            let head = String::from_utf8_lossy(&buf[..n]);
            assert!(
                head.starts_with("GET /d/box1/health HTTP/1.1\r\n"),
                "{head}"
            );
            tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nOK",
            )
            .await
            .unwrap();
        });

        let router = router(test_config(&format!("http://{addr}")), "box1".to_string());
        let response = axum::http::Request::builder()
            .uri("/d/box1/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tower::ServiceExt::oneshot(router, response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn a_websocket_upgrade_is_refused_not_implemented() {
        let router = router(test_config("http://127.0.0.1:1"), "box1".to_string());
        let response = axum::http::Request::builder()
            .uri("/d/box1/ws")
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tower::ServiceExt::oneshot(router, response).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
