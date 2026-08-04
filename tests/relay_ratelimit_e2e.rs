//! Rate-limit headers on a response that crossed the relay.
//!
//! Two limiters sit in series on the proxied path — the relay's, keyed on the
//! caller's real address, and the device's, which sees only its own loopback —
//! and both are the *same* middleware. Every existing test drives one of them
//! alone (`tests/api_integration.rs` the device's, directly), which is why the
//! middleware overwriting the device's headers with the relay's survived: on a
//! single-limiter path there is nothing to overwrite.
//!
//! The defect it hid was a `429` arriving with `X-RateLimit-Remaining: 92` —
//! the relay's spare budget, printed over the empty bucket that had actually
//! refused the request. A consumer pacing itself by that header reads a refusal
//! as room to continue. So the assertions below are about *whose* numbers come
//! back, not merely that some header exists.

#![cfg(feature = "relay-client")]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use shell_tunnel::relay::client::{run, RelayClientConfig};
use shell_tunnel::relay::{relay_router, RelayConfig, RelayState};
use shell_tunnel::security::RateLimitConfig;
use shell_tunnel::{api, AppState, ServerConfig};

/// The device's budget. Small enough to empty in a few requests.
const DEVICE_BUDGET: u32 = 3;

/// The relay's budget. Deliberately nothing like the device's: if the relay's
/// numbers ever reach the caller they are unmistakable, rather than coinciding
/// with the device's the way two defaulted 100s did in the field.
const RELAY_BUDGET: u32 = 500;

/// Start a relay on an ephemeral port; returns its address.
///
/// Mirrors `tests/fs_relay_e2e.rs::start_relay` — same shape, duplicated
/// rather than shared, matching how the existing relay test files each carry
/// their own copy of this helper.
async fn start_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = RelayConfig::new(addr, "secret");
    config.rate_limit = RateLimitConfig::custom(RELAY_BUDGET, 60);
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

/// Start a real API server whose limiter empties after `DEVICE_BUDGET`.
///
/// No auth and no `--fs-root`: this test is about which limiter's numbers reach
/// the caller, and `/api/v1/sessions` answers `200` without either.
async fn start_device_server() -> SocketAddr {
    let mut config = ServerConfig::new("127.0.0.1", 0).without_graceful_shutdown();
    config.security.rate_limit = RateLimitConfig::custom(DEVICE_BUDGET, 60);

    let listener = api::bind(&config).await.expect("bind local server");
    let local_addr = listener.local_addr().expect("local addr");
    tokio::spawn(api::serve_on(listener, config, AppState::new()));

    local_addr
}

/// Dial the relay as a real device would, serving `local_addr` behind it.
fn spawn_device(relay_addr: SocketAddr, local_addr: SocketAddr, device_name: &str) {
    let config = RelayClientConfig {
        relay_url: format!("ws://{relay_addr}"),
        enroll_token: "secret".to_string(),
        local: local_addr,
        label: None,
        device_name: Some(device_name.to_string()),
        fingerprint: None,
        ca_file: None,
        enrolled: None,
    };
    tokio::spawn(run(config));
}

/// One response: status plus its headers, lowercased.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A minimal hand-rolled HTTP/1.1 client — the crate deliberately has no HTTP
/// client dependency, and this is the same trade `tests/fs_relay_e2e.rs` makes,
/// kept here because that one discards headers and headers are the subject.
async fn http_get(url: &str) -> Answer {
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let head = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("relay should answer")
        .unwrap();

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();

    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();

    Answer { status, headers }
}

/// Poll the device's own `/health` through the relay until it answers.
///
/// `/health` is exempt from the device's limiter, so the poll cannot spend the
/// budget this test is about — which is why it is the route used here.
async fn wait_until_attached(base: &str) {
    for _ in 0..50 {
        if http_get(&format!("{base}/health")).await.status == 200 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("device never became reachable through the relay");
}

/// Bring up relay + device and return the device's public base URL.
async fn attached_device(name: &str) -> String {
    let relay = start_relay().await;
    let device = start_device_server().await;
    spawn_device(relay, device, name);

    let base = format!("http://{relay}/d/{name}");
    wait_until_attached(&base).await;
    base
}

/// A refusal that crossed the relay reports the empty bucket, not the full one.
#[tokio::test]
async fn a_relayed_429_carries_the_refusing_limiters_numbers() {
    let base = attached_device("rl-refused").await;

    // Spend the device's budget. Every one of these also spends a slot of the
    // relay's, which is the point: the two counters diverge from here on.
    for _ in 0..DEVICE_BUDGET {
        let answer = http_get(&format!("{base}/api/v1/sessions")).await;
        assert_eq!(answer.status, 200, "budget should not be spent yet");
    }

    let refused = http_get(&format!("{base}/api/v1/sessions")).await;

    assert_eq!(refused.status, 429, "the device's bucket is empty");
    assert_eq!(
        refused.header("x-ratelimit-remaining"),
        Some("0"),
        "a refusal must not report spare capacity; the relay's own remaining \
         here is upwards of {}",
        RELAY_BUDGET - DEVICE_BUDGET - 2
    );
    assert_eq!(
        refused.header("x-ratelimit-limit"),
        Some(DEVICE_BUDGET.to_string().as_str()),
        "the limit belongs to whoever refused"
    );
    assert!(
        refused.header("retry-after").is_some(),
        "Retry-After survived the relay before this fix and must still"
    );
}

/// The same rule on the path that is not a refusal.
///
/// Written separately because the middleware handles allowed and refused
/// responses in different branches, and only the allowed branch was overwriting
/// anything. A test that only ever looked at `429` would leave the branch that
/// carries every successful proxied response unasserted.
#[tokio::test]
async fn a_relayed_200_counts_down_the_devices_budget() {
    let base = attached_device("rl-allowed").await;

    let first = http_get(&format!("{base}/api/v1/sessions")).await;

    assert_eq!(first.status, 200);
    assert_eq!(
        first.header("x-ratelimit-limit"),
        Some(DEVICE_BUDGET.to_string().as_str()),
        "the caller is told the budget that will actually refuse it"
    );
    assert_eq!(
        first.header("x-ratelimit-remaining"),
        Some((DEVICE_BUDGET - 1).to_string().as_str()),
        "one request spent, counted against the device's bucket"
    );
}

/// A device with no limiter of its own does not borrow the relay's silence.
///
/// The suppression added for `--no-rate-limit` is on the *device*; the relay
/// here still limits. Whoever is counting is entitled to say so, so the relay's
/// numbers fill the gap the device left — that is the one case where the header
/// describes the relay, and it is true of the relay.
#[tokio::test]
async fn an_unlimited_device_lets_the_relays_numbers_through() {
    let relay = start_relay().await;

    let mut config = ServerConfig::new("127.0.0.1", 0).without_graceful_shutdown();
    config.security.rate_limit = RateLimitConfig::disabled();
    let listener = api::bind(&config).await.expect("bind local server");
    let device = listener.local_addr().expect("local addr");
    tokio::spawn(api::serve_on(listener, config, AppState::new()));

    spawn_device(relay, device, "rl-unlimited");
    let base = format!("http://{relay}/d/rl-unlimited");
    wait_until_attached(&base).await;

    let answer = http_get(&format!("{base}/api/v1/sessions")).await;

    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.header("x-ratelimit-limit"),
        Some(RELAY_BUDGET.to_string().as_str()),
        "with the device silent, the limit in force is the relay's"
    );
}
