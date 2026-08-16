//! End-to-end tests for the relay's data path.
//!
//! A fake device dials out, enrolls, opens data connections, and answers
//! proxied requests — so routing, header handling, and pool behaviour are
//! verified against a running relay rather than against handlers in isolation.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use shell_tunnel::relay::protocol::{DeviceMessage, RelayMessage, PROTOCOL_VERSION};
use shell_tunnel::relay::proxy::{ProxyRequest, ProxyResponse};
use shell_tunnel::relay::{relay_router, RelayConfig, RelayState, POOL_TARGET};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig::new(addr, "secret").with_public_base("https://relay.test");
    let router = relay_router(RelayState::new(config));
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

async fn recv(socket: &mut Socket) -> RelayMessage {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("relay should answer")
            .expect("stream should stay open")
            .expect("frame should be readable");
        if let Message::Text(text) = message {
            return serde_json::from_str(&text).expect("relay frames are protocol messages");
        }
    }
}

/// Enroll a device; returns its id and the live control connection.
async fn enroll(addr: SocketAddr) -> (String, Socket) {
    let (mut control, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/control"))
            .await
            .expect("control endpoint should accept the upgrade");

    let message = DeviceMessage::Enroll {
        enroll_token: "secret".to_string(),
        version: PROTOCOL_VERSION,
        label: Some("fake-device".to_string()),
        device_name: None,
    };
    control
        .send(Message::Text(serde_json::to_string(&message).unwrap()))
        .await
        .unwrap();

    let RelayMessage::Enrolled { device_id, .. } = recv(&mut control).await else {
        panic!("expected an enrolled message");
    };
    (device_id, control)
}

/// Open one data connection and serve exactly one proxied request on it.
///
/// This is what a real device does: dial out, read the request header and body,
/// reply with a response header, body, then close.
async fn serve_one_request(
    addr: SocketAddr,
    device_id: &str,
    token: &str,
    status: u16,
    reply: &'static str,
) -> tokio::task::JoinHandle<ProxyRequest> {
    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .expect("data connection should be accepted");

    // Credentials go in the first frame, never in the URL.
    let attach = DeviceMessage::Attach {
        device_id: device_id.to_string(),
        enroll_token: token.to_string(),
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();

    tokio::spawn(async move {
        let request: ProxyRequest = loop {
            match conn.next().await {
                Some(Ok(Message::Text(text))) => break serde_json::from_str(&text).unwrap(),
                Some(Ok(_)) => continue,
                other => panic!("expected a request header, got {other:?}"),
            }
        };
        // Request body frame; always sent, empty for GETs.
        let _ = conn.next().await;

        let head = ProxyResponse {
            status,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
        };
        conn.send(Message::Text(serde_json::to_string(&head).unwrap()))
            .await
            .unwrap();
        conn.send(Message::Binary(reply.as_bytes().to_vec()))
            .await
            .unwrap();
        conn.close(None).await.unwrap();
        request
    })
}

/// Minimal HTTP GET — the crate deliberately has no HTTP client dependency.
async fn http_get(url: &str, header: Option<(&str, &str)>) -> (u16, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let extra = header
        .map(|(n, v)| format!("{n}: {v}\r\n"))
        .unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n{extra}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("relay should answer")
        .unwrap();

    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[tokio::test]
async fn a_request_is_proxied_to_the_device_and_answered() {
    let addr = start_relay().await;
    let (device_id, mut control) = enroll(addr).await;

    // The relay asks the device to fill its pool as soon as it enrolls.
    assert_eq!(
        recv(&mut control).await,
        RelayMessage::OpenData { count: POOL_TARGET }
    );

    let device = serve_one_request(addr, &device_id, "secret", 200, "hello from the device").await;

    let (status, body) = http_get(
        &format!("http://{addr}/d/{device_id}/api/v1/execute?x=1"),
        None,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(body, "hello from the device");

    let seen = device.await.unwrap();
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.path, "/api/v1/execute?x=1");
}

#[tokio::test]
async fn the_authorization_header_reaches_the_device_unchanged() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;
    let device = serve_one_request(addr, &device_id, "secret", 200, "ok").await;

    let (status, _body) = http_get(
        &format!("http://{addr}/d/{device_id}/api/v1/sessions"),
        Some(("authorization", "Bearer st_capability_token")),
    )
    .await;
    assert_eq!(status, 200);

    let seen = device.await.unwrap();
    let auth = seen
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.clone());
    // The relay routes; the capability token has to arrive untouched.
    assert_eq!(auth.as_deref(), Some("Bearer st_capability_token"));

    // Hop-by-hop headers describe the client's connection to the relay, not the
    // message, so they must not be replayed onto the device.
    assert!(
        !seen
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("host")),
        "{:?}",
        seen.headers
    );
}

#[tokio::test]
async fn an_unknown_device_is_a_bad_gateway() {
    let addr = start_relay().await;
    let (status, _body) = http_get(&format!("http://{addr}/d/does-not-exist/health"), None).await;
    assert_eq!(status, 502);
}

#[tokio::test]
async fn an_attached_device_with_no_connections_is_unavailable() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;

    // Enrolled but never opened a data connection: the pool is empty.
    let (status, _body) = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn a_data_connection_with_a_bad_token_never_joins_the_pool() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;

    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .expect("the upgrade itself is not the authentication step");
    let attach = DeviceMessage::Attach {
        device_id: device_id.clone(),
        enroll_token: "wrong".to_string(),
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();

    // A connection that cannot prove the secret must not become usable
    // capacity: requests still find an empty pool.
    let (status, _body) = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn credentials_never_appear_in_a_data_connection_url() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;

    // The URL a device dials carries no secret — proxies log query strings.
    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .expect("a credential-free URL must still be accepted");
    let attach = DeviceMessage::Attach {
        device_id: device_id.clone(),
        enroll_token: "secret".to_string(),
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();

    // Give the relay a moment to park it, then prove it became real capacity.
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::spawn(async move {
        let _ = conn.next().await;
    });
    let (status, _body) = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;
    assert_ne!(status, 503, "the connection should have joined the pool");
}

/// Start a relay the same way [`start_relay`] does, but keep the
/// [`RelayState`] handle so a test can trigger a pool recycle directly
/// instead of waiting for the real interval to elapse.
async fn start_relay_with_state() -> (SocketAddr, RelayState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig::new(addr, "secret").with_public_base("https://relay.test");
    let state = RelayState::new(config);
    let router = relay_router(state.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, state)
}

/// A pooled connection nothing has requested yet carries no traffic at all —
/// unlike the control channel, which proves itself alive with a heartbeat.
/// Left alone, a proxy, NAT or firewall between the device and the relay can
/// drop it without either side finding out until a real request tries to use
/// it and fails with a `502`. Recycling closes it — and asks for a
/// replacement — before that can happen.
#[tokio::test]
async fn an_idle_pooled_connection_is_recycled_and_replaced() {
    let (addr, state) = start_relay_with_state().await;
    let (device_id, mut control) = enroll(addr).await;

    // Initial fill.
    assert_eq!(
        recv(&mut control).await,
        RelayMessage::OpenData { count: POOL_TARGET }
    );

    // Open one data connection and never use it — this is what an idle
    // pooled connection looks like.
    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .expect("data connection should be accepted");
    let attach = DeviceMessage::Attach {
        device_id: device_id.clone(),
        enroll_token: "secret".to_string(),
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();
    // Give the relay a moment to park it in the pool before recycling.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let recycled = state.devices().recycle_idle_pools().await;
    assert_eq!(recycled, 1, "the one idle pooled connection should recycle");

    // The relay's end closed; the device's end observes that.
    let ended = tokio::time::timeout(Duration::from_secs(2), conn.next())
        .await
        .expect("the relay should have closed the idle connection");
    assert!(
        matches!(ended, Some(Ok(Message::Close(_))) | None),
        "expected the connection to end, got {ended:?}"
    );

    // And the device must have been asked for a replacement, or the pool
    // drains to nothing every time it is recycled while idle.
    assert!(
        matches!(
            recv(&mut control).await,
            RelayMessage::OpenData { count: 1 }
        ),
        "recycling an idle pooled connection must trigger a refill"
    );
}

#[tokio::test]
async fn consuming_a_connection_asks_the_device_for_another() {
    let addr = start_relay().await;
    let (device_id, mut control) = enroll(addr).await;

    // Initial fill request.
    assert!(matches!(
        recv(&mut control).await,
        RelayMessage::OpenData { .. }
    ));

    let _device = serve_one_request(addr, &device_id, "secret", 200, "ok").await;
    let _ = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;

    // Taking a connection out of the pool must trigger a refill, or the pool
    // drains to nothing after a handful of requests.
    assert!(matches!(
        recv(&mut control).await,
        RelayMessage::OpenData { count: 1 }
    ));
}

// ===========================================================================
// WebSocket through the relay
// ===========================================================================

/// Stand in for a device that answers a WebSocket upgrade: accept the request
/// header, agree with 101, then echo frames back.
async fn serve_one_websocket(addr: SocketAddr, device_id: &str, token: &str) {
    let (mut conn, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/data"))
        .await
        .expect("data connection should be accepted");

    let attach = DeviceMessage::Attach {
        device_id: device_id.to_string(),
        enroll_token: token.to_string(),
    };
    conn.send(Message::Text(serde_json::to_string(&attach).unwrap()))
        .await
        .unwrap();

    tokio::spawn(async move {
        let request: ProxyRequest = loop {
            match conn.next().await {
                Some(Ok(Message::Text(text))) => break serde_json::from_str(&text).unwrap(),
                Some(Ok(_)) => continue,
                other => panic!("expected a request header, got {other:?}"),
            }
        };
        assert!(
            request.websocket,
            "the upgrade intent must survive the hop as a typed field"
        );

        let head = ProxyResponse {
            status: 101,
            headers: Vec::new(),
        };
        conn.send(Message::Text(serde_json::to_string(&head).unwrap()))
            .await
            .unwrap();

        // Echo whatever the client sends, prefixed so the test can tell the
        // frame really made the round trip.
        while let Some(Ok(message)) = conn.next().await {
            match message {
                Message::Text(text) => {
                    if conn
                        .send(Message::Text(format!("echo:{text}")))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => continue,
            }
        }
    });
}

#[tokio::test]
async fn a_websocket_is_piped_through_the_relay() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;
    serve_one_websocket(addr, &device_id, "secret").await;

    let (mut client, response) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/d/{device_id}/api/v1/ws"))
            .await
            .expect("the relay should complete the upgrade");
    assert_eq!(response.status().as_u16(), 101);

    client
        .send(Message::Text("hello".to_string()))
        .await
        .unwrap();

    let reply = tokio::time::timeout(Duration::from_secs(5), client.next())
        .await
        .expect("the device should answer")
        .expect("stream open")
        .expect("frame readable");
    assert_eq!(reply, Message::Text("echo:hello".to_string()));
}

#[tokio::test]
async fn a_websocket_to_an_unknown_device_is_refused() {
    let addr = start_relay().await;
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{addr}/d/nobody/api/v1/ws"))
            .await
            .is_err(),
        "an unattached device cannot carry a websocket"
    );
}

// ===========================================================================
// Device listing — how a caller finds a device without reading its console
// ===========================================================================

#[tokio::test]
async fn the_device_list_reports_attached_devices_with_usable_urls() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;

    let (status, body) = http_get_authed(
        &format!("http://{addr}/relay/v1/devices"),
        Some(("authorization", "Bearer secret")),
    )
    .await;
    assert_eq!(status, 200);

    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    let devices = parsed["devices"].as_array().expect("devices array");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["id"].as_str(), Some(device_id.as_str()));
    assert_eq!(devices[0]["label"].as_str(), Some("fake-device"));
    // The point of the endpoint: a URL you can call, not just an id. The
    // port-less --public-base inherits this relay's listen port, so the URL
    // names the port the caller must actually dial.
    assert_eq!(
        devices[0]["public_url"].as_str(),
        Some(format!("https://relay.test:{}/d/{device_id}", addr.port()).as_str())
    );
    assert!(devices[0]["last_seen_secs"].is_number());
}

#[tokio::test]
async fn the_device_list_requires_the_enroll_token() {
    let addr = start_relay().await;
    let _ = enroll(addr).await;

    let (status, _) = http_get_authed(&format!("http://{addr}/relay/v1/devices"), None).await;
    assert_eq!(status, 401);

    let (status, _) = http_get_authed(
        &format!("http://{addr}/relay/v1/devices"),
        Some(("authorization", "Bearer wrong")),
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn the_device_list_is_empty_before_anything_attaches() {
    let addr = start_relay().await;

    let (status, body) = http_get_authed(
        &format!("http://{addr}/relay/v1/devices"),
        Some(("authorization", "Bearer secret")),
    )
    .await;

    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(parsed["devices"].as_array().unwrap().is_empty());
}

/// `http_get` with an optional header, kept separate so the existing callers
/// stay readable.
async fn http_get_authed(url: &str, header: Option<(&str, &str)>) -> (u16, String) {
    http_get(url, header).await
}

// ===========================================================================
// Rate limiting — the relay is the only place a caller's real IP is visible
// ===========================================================================

/// Start a relay whose limit is low enough to reach in a test.
async fn start_throttled_relay(max_requests: u32) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut config = RelayConfig::new(addr, "secret").with_public_base("https://relay.test");
    config.rate_limit.max_requests = max_requests;

    let router = relay_router(RelayState::new(config));
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn hammering_the_relay_is_throttled() {
    let addr = start_throttled_relay(3).await;
    let url = format!("http://{addr}/relay/v1/devices");
    let auth = Some(("authorization", "Bearer secret"));

    // Within the limit the answers are normal.
    for attempt in 1..=3 {
        let (status, _) = http_get(&url, auth).await;
        assert_eq!(status, 200, "request {attempt} should be allowed");
    }

    // Past it, the relay refuses rather than letting a caller guess forever.
    let (status, _) = http_get(&url, auth).await;
    assert_eq!(status, 429);
}

#[tokio::test]
async fn enrolment_attempts_are_throttled() {
    // A weak enrolment token is only as safe as the number of guesses allowed,
    // and the control endpoint is where those guesses land.
    let addr = start_throttled_relay(2).await;
    let url = format!("ws://{addr}/relay/v1/control");

    for _ in 0..2 {
        let _ = tokio_tungstenite::connect_async(&url).await;
    }

    assert!(
        tokio_tungstenite::connect_async(&url).await.is_err(),
        "a third dial in the window should be refused"
    );
}

/// Infrastructure a device opens after proving the token is not public traffic.
///
/// The limit exists to slow enrolment guessing, and a device that has proven
/// the token is not guessing. Charging it anyway put two unlike things in one
/// budget — and the device's share of that budget is set by whoever calls the
/// device, because the relay has it open a fresh data connection for every
/// proxied request. Public load on an address could therefore starve a device
/// sharing it, which is not hypothetical: four enrolments were refused that way
/// in the field while the device retried in silence.
///
/// Deliberately no sleeps. Each step's refund is already done by the time its
/// observable result arrives — the `Enrolled` frame is sent after enrolment
/// refunds, and a proxied request can only be answered by a connection that
/// reached the pool, which happens after that connection refunds.
#[tokio::test]
async fn a_device_that_proved_the_token_does_not_spend_the_public_budget() {
    let addr = start_throttled_relay(4).await;

    // Charged and refunded: enrolment (1) and one data connection (1).
    let (device_id, _control) = enroll(addr).await;
    let served = serve_one_request(addr, &device_id, "secret", 200, "ok").await;

    // Public traffic, charged and kept: this is also what proves the data
    // connection joined the pool, so its refund has certainly run.
    let (status, _) = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;
    assert_eq!(status, 200);
    served.await.unwrap();

    // Three left of four. Without the refunds only one would be.
    let url = format!("http://{addr}/relay/v1/devices");
    let auth = Some(("authorization", "Bearer secret"));
    for attempt in 1..=3 {
        let (status, _) = http_get(&url, auth).await;
        assert_eq!(
            status, 200,
            "request {attempt} should be allowed: the device's own connections \
             must not have spent the caller's budget"
        );
    }

    // And the budget is a budget still — the refunds did not remove the limit.
    let (status, _) = http_get(&url, auth).await;
    assert_eq!(status, 429, "four public requests is the whole budget");
}

/// When the relay is the one refusing, the numbers are the relay's and are `0`.
///
/// The other tests here cover a device's refusal crossing the relay and a
/// non-rate-limit `429` passing through it. This is the third case in that set
/// and the only one previously argued rather than run: the relay's own bucket
/// empties, the device is never reached, and the caller has to be told about
/// the budget that actually stopped them. Nothing else can tell them — a device
/// that was never asked has no headers to send.
#[tokio::test]
async fn a_refusal_the_relay_itself_made_reports_the_relays_budget() {
    let addr = start_throttled_relay(2).await;
    let (device_id, _control) = enroll(addr).await;
    let served = serve_one_request(addr, &device_id, "secret", 200, "ok").await;

    // Enrolment and the data connection are refunded, so the budget is intact:
    // two proxied requests, then the refusal.
    let url = format!("http://{addr}/d/{device_id}/health");
    let (status, _) = http_get(&url, None).await;
    assert_eq!(status, 200, "the first is within budget");
    served.await.unwrap();
    let (status, _) = http_get(&url, None).await;
    assert_eq!(
        status, 503,
        "the second is within budget too — 503 is the empty pool, not the limiter"
    );

    let (status, head) = http_head_and_status(&url).await;
    assert_eq!(status, 429, "the third exceeds the relay's own budget");
    let head = head.to_ascii_lowercase();
    assert!(
        head.contains("x-ratelimit-remaining: 0"),
        "the relay refused, so the relay's remaining is what the caller needs: {head}"
    );
    assert!(
        head.contains("x-ratelimit-limit: 2"),
        "and the limit is the relay's own, not a device's: {head}"
    );
    assert!(head.contains("retry-after:"), "{head}");
}

/// The device list reports how long a device took to answer — after it has.
///
/// A consumer asked for a way to measure the relay↔device leg, having spent a
/// long time unable to tell a slow device from a slow relay. An endpoint that
/// echoes arbitrary bytes was refused (it would be an unauthenticated bandwidth
/// amplifier on a relay that already answers unauthenticated questions); this is
/// what was offered instead, and it costs nothing new — `proxy_handler` is
/// already holding both ends of the timing.
///
/// The absence half is the load-bearing one. A device nothing has called yet
/// must report no timing at all rather than zero, which reads as answering
/// instantly, and is exactly what a consumer diagnosing slowness would misread.
#[tokio::test]
async fn the_device_list_reports_answer_times_only_once_there_are_any() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;
    let url = format!("http://{addr}/relay/v1/devices");
    let auth = Some(("authorization", "Bearer secret"));

    let (status, body) = http_get(&url, auth).await;
    assert_eq!(status, 200);
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let before = &listed["devices"][0];
    assert!(
        before["exchanges"].is_null() && before["mean_exchange_ms"].is_null(),
        "a device nothing has called has no answer time, and 0 would read as instant: {before}"
    );

    let served = serve_one_request(addr, &device_id, "secret", 200, "ok").await;
    let (status, _) = http_get(&format!("http://{addr}/d/{device_id}/health"), None).await;
    assert_eq!(status, 200);
    served.await.unwrap();

    let (_, body) = http_get(&url, auth).await;
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let after = &listed["devices"][0];
    assert_eq!(
        after["exchanges"], 1,
        "one proxied request is one exchange: {after}"
    );
    for field in [
        "last_exchange_ms",
        "mean_exchange_ms",
        "slowest_exchange_ms",
    ] {
        assert!(
            after[field].is_u64(),
            "{field} must be reported once there is a measurement: {after}"
        );
    }
}

/// A `429` the relay merely carried gets no spare count stamped on it.
///
/// Not every `429` is a rate limit — a device answers one when its upload table
/// is full, and that response carries no limiter headers to preserve. Filling
/// them in from the relay's limiter, which *allowed* this request, rebuilds the
/// contradiction the header pass removed: refused, with room to continue. A
/// caller pacing itself by the header keeps going straight into the refusal.
#[tokio::test]
async fn a_429_from_elsewhere_is_not_given_a_spare_count() {
    let addr = start_relay().await;
    let (device_id, _control) = enroll(addr).await;
    let served = serve_one_request(addr, &device_id, "secret", 429, "too-many-uploads").await;

    let (status, headers) =
        http_head_and_status(&format!("http://{addr}/d/{device_id}/api/v1/fs/uploads")).await;
    served.await.unwrap();

    assert_eq!(status, 429, "the device's refusal reached the caller");
    assert!(
        !headers
            .to_ascii_lowercase()
            .contains("x-ratelimit-remaining"),
        "the relay allowed this request, so it has no remaining count to \
         attach to somebody else's refusal: {headers}"
    );
}

/// `http_get`, keeping the response head instead of the body.
async fn http_head_and_status(url: &str) -> (u16, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("relay should answer")
        .unwrap();

    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let head = text.split("\r\n\r\n").next().unwrap_or("").to_string();
    (status, head)
}

/// The other side of the refund: a guess is still charged.
///
/// This is the assertion that keeps the refund from becoming an exemption. If
/// a wrong token were refunded too, the route the limit exists for would have
/// no limit at all, and the change would have quietly removed the defence it
/// was written to preserve.
#[tokio::test]
async fn a_refused_enrolment_still_spends_its_slot() {
    let addr = start_throttled_relay(2).await;

    let (mut control, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/control"))
            .await
            .expect("the upgrade itself is not the authentication step");
    let guess = DeviceMessage::Enroll {
        enroll_token: "wrong".to_string(),
        version: PROTOCOL_VERSION,
        label: None,
        device_name: None,
    };
    control
        .send(Message::Text(serde_json::to_string(&guess).unwrap()))
        .await
        .unwrap();

    // Waiting for the refusal is what orders this against the budget check.
    let RelayMessage::Rejected { code, .. } = recv(&mut control).await else {
        panic!("expected a rejection");
    };
    assert_eq!(code, "bad-token");

    let url = format!("http://{addr}/relay/v1/devices");
    let auth = Some(("authorization", "Bearer secret"));
    let (status, _) = http_get(&url, auth).await;
    assert_eq!(status, 200, "one of two slots is left");

    let (status, _) = http_get(&url, auth).await;
    assert_eq!(
        status, 429,
        "the guess kept its slot, so the budget is spent"
    );
}

#[tokio::test]
async fn health_is_never_throttled() {
    // Monitoring must not be the thing that trips the limit.
    let addr = start_throttled_relay(1).await;
    let url = format!("http://{addr}/health");

    for attempt in 1..=5 {
        let (status, _) = http_get(&url, None).await;
        assert_eq!(status, 200, "health check {attempt} should always answer");
    }
}
