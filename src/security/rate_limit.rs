//! Rate limiting implementation.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window.
    pub max_requests: u32,
    /// Time window duration.
    pub window: Duration,
    /// Whether rate limiting is enabled.
    pub enabled: bool,
    /// Maximum number of tracked IPs (memory limit).
    pub max_tracked_ips: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
            enabled: true,
            max_tracked_ips: 10000,
        }
    }
}

impl RateLimitConfig {
    /// Create a disabled rate limiter config.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Create a strict rate limiter (10 req/min).
    pub fn strict() -> Self {
        Self {
            max_requests: 10,
            window: Duration::from_secs(60),
            ..Default::default()
        }
    }

    /// Create a relaxed rate limiter (1000 req/min).
    pub fn relaxed() -> Self {
        Self {
            max_requests: 1000,
            window: Duration::from_secs(60),
            ..Default::default()
        }
    }

    /// Custom rate limit.
    pub fn custom(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
            ..Default::default()
        }
    }
}

/// Request record for an IP.
#[derive(Debug, Clone)]
struct RequestRecord {
    /// Timestamps of requests in the current window.
    timestamps: Vec<Instant>,
}

impl RequestRecord {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    /// Clean up old timestamps and return current count.
    fn clean_and_count(&mut self, window: Duration) -> u32 {
        let now = Instant::now();
        let cutoff = now - window;

        // Remove timestamps older than the window
        self.timestamps.retain(|&t| t > cutoff);

        self.timestamps.len() as u32
    }

    /// Record a new request, returning the slot it took.
    fn record(&mut self) -> Instant {
        let now = Instant::now();
        self.timestamps.push(now);
        now
    }
}

/// What the limiter decided about one request.
///
/// Three variants rather than `Result<remaining, retry_after>` because a
/// limiter that is switched off has no remaining count to report, and folding
/// that case into `Ok(max_requests)` is what put `X-RateLimit-Remaining: 100`
/// on every response of a server started with `--no-rate-limit`. A limit that
/// does not exist cannot be advertised if it cannot be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// No limit was applied — the limiter is disabled.
    Unlimited,
    /// Allowed, with this many requests left in the current window.
    Allowed {
        /// Requests left in the current window.
        remaining: u32,
        /// The slot this request took, for a handler that may refund it.
        charge: RateLimitCharge,
    },
    /// Refused; the window frees up after this long.
    Limited { retry_after: Duration },
}

impl RateLimitDecision {
    /// Requests left in the window, where a count exists at all.
    pub fn remaining(&self) -> Option<u32> {
        match self {
            Self::Allowed { remaining, .. } => Some(*remaining),
            _ => None,
        }
    }
}

/// One slot in one address's window, identifying the request that took it.
///
/// Carried in the request's extensions so a handler can hand back the slot the
/// middleware charged *it* — see [`RateLimiter::refund`]. Naming the slot is
/// what keeps a refund from returning somebody else's: an opaque "give one
/// back" cannot tell the difference once the charge it meant has aged out of
/// the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitCharge(Instant);

/// Thread-safe rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    records: RwLock<HashMap<IpAddr, RequestRecord>>,
    config: RateLimitConfig,
    last_cleanup: RwLock<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            config,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Create a disabled rate limiter.
    pub fn disabled() -> Self {
        Self::new(RateLimitConfig::disabled())
    }

    /// Check if rate limiting is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if a request from the given IP should be allowed.
    pub fn check(&self, ip: IpAddr) -> RateLimitDecision {
        if !self.config.enabled {
            return RateLimitDecision::Unlimited;
        }

        // Periodic cleanup
        self.maybe_cleanup();

        let mut records = match self.records.write() {
            Ok(r) => r,
            // Fail open on lock error. `Unlimited` rather than a remaining
            // count, because no limit was applied to this request and saying
            // otherwise would put a number on the wire that nothing counted.
            Err(_) => return RateLimitDecision::Unlimited,
        };

        let record = records.entry(ip).or_insert_with(RequestRecord::new);
        let current_count = record.clean_and_count(self.config.window);

        if current_count >= self.config.max_requests {
            // Calculate retry-after
            let oldest = record.timestamps.first().copied();
            let retry_after = oldest
                .map(|t| self.config.window.saturating_sub(t.elapsed()))
                .unwrap_or(self.config.window);
            return RateLimitDecision::Limited { retry_after };
        }

        // Record this request
        let charge = RateLimitCharge(record.record());
        let remaining = self.config.max_requests - current_count - 1;

        RateLimitDecision::Allowed { remaining, charge }
    }

    /// Give back the exact slot `charge` took.
    ///
    /// For a request whose legitimacy is only established *after* the limiter
    /// has already had to decide. A device proves its enrolment token in the
    /// first WebSocket frame, long after the middleware ran on the upgrade
    /// request, so the choice is between not limiting those routes at all —
    /// which is where an enrolment token could be guessed at line speed — and
    /// charging every attempt and refunding the ones that turn out to be
    /// authenticated. This is the second: what accumulates in the bucket is
    /// failed and abandoned attempts, which is exactly what the limit is for.
    ///
    /// Removing the slot *by identity* rather than dropping the newest one is
    /// what keeps this from handing out credit. The two differ whenever the
    /// charge being refunded has already aged out of the window — a device may
    /// take seconds to send its first frame — and dropping the newest would
    /// then free a live slot belonging to whoever else is calling from that
    /// address. A charge that is already gone refunds nothing, which is right:
    /// the window has released it once already.
    pub fn refund(&self, ip: IpAddr, charge: RateLimitCharge) {
        if !self.config.enabled {
            return;
        }

        let Ok(mut records) = self.records.write() else {
            return;
        };

        if let Some(record) = records.get_mut(&ip) {
            if let Some(at) = record.timestamps.iter().position(|t| *t == charge.0) {
                record.timestamps.remove(at);
            }
        }
    }

    /// Perform cleanup of old records if needed.
    fn maybe_cleanup(&self) {
        let should_cleanup = self
            .last_cleanup
            .read()
            .map(|t| t.elapsed() > self.config.window * 2)
            .unwrap_or(false);

        if !should_cleanup {
            return;
        }

        // Try to acquire write lock for cleanup
        if let Ok(mut last) = self.last_cleanup.write() {
            // Double-check after acquiring lock
            if last.elapsed() <= self.config.window * 2 {
                return;
            }

            *last = Instant::now();

            if let Ok(mut records) = self.records.write() {
                let cutoff = Instant::now() - self.config.window * 2;

                // Remove IPs with no recent activity
                records.retain(|_, record| {
                    record
                        .timestamps
                        .last()
                        .map(|&t| t > cutoff)
                        .unwrap_or(false)
                });

                // If still too many, remove oldest entries
                if records.len() > self.config.max_tracked_ips {
                    let mut entries: Vec<_> = records
                        .iter()
                        .map(|(ip, r)| (*ip, r.timestamps.last().copied()))
                        .collect();

                    entries.sort_by_key(|(_, t)| *t);

                    let to_remove = records.len() - self.config.max_tracked_ips;
                    for (ip, _) in entries.into_iter().take(to_remove) {
                        records.remove(&ip);
                    }
                }
            }
        }
    }

    /// Get current stats.
    pub fn stats(&self) -> RateLimitStats {
        let tracked_ips = self.records.read().map(|r| r.len()).unwrap_or(0);
        RateLimitStats {
            tracked_ips,
            max_requests: self.config.max_requests,
            window_secs: self.config.window.as_secs(),
            enabled: self.config.enabled,
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

/// Rate limit statistics.
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub tracked_ips: usize,
    pub max_requests: u32,
    pub window_secs: u64,
    pub enabled: bool,
}

/// Rate limit middleware for axum.
pub async fn rate_limit_middleware(
    State(limiter): State<std::sync::Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    // Skip rate limiting for health endpoint
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }

    match limiter.check(addr.ip()) {
        // Nothing counted this request, so nothing is advertised about it.
        RateLimitDecision::Unlimited => next.run(request).await,
        RateLimitDecision::Allowed { remaining, charge } => {
            // A handler that can establish, later than this, that the request
            // should not have been charged needs to name the slot to give back.
            // Passing it down the request is the only way it can: by the time
            // such a handler knows, this middleware has long returned.
            request.extensions_mut().insert(charge);

            let mut response = next.run(request).await;

            // Only where nobody upstream already answered the question. The
            // relay wraps this middleware around `/d/*` too, so a proxied
            // response arrives carrying the *device's* headers — and `insert`
            // replaced them, which is how a `429` from a device with an empty
            // bucket reached its caller saying 92 requests remained. Whoever
            // refused is the one whose budget the caller has to wait on.
            //
            // The pair moves together: a `Limit` from one limiter beside a
            // `Remaining` from another describes no budget that exists.
            //
            // And never onto somebody else's refusal. A `429` that reached
            // here is one *this* limiter allowed — a full upload table, or a
            // device's own limit answering through a relay — so stamping a
            // spare count on it rebuilds the contradiction the rest of this
            // avoids: refused, with room to continue. A refusal this limiter
            // made takes the branch below and says `0` there.
            let refused_elsewhere = response.status() == StatusCode::TOO_MANY_REQUESTS;
            let headers = response.headers_mut();
            if !refused_elsewhere
                && !headers.contains_key("X-RateLimit-Limit")
                && !headers.contains_key("X-RateLimit-Remaining")
            {
                headers.insert(
                    "X-RateLimit-Limit",
                    limiter.config.max_requests.to_string().parse().unwrap(),
                );
                headers.insert(
                    "X-RateLimit-Remaining",
                    remaining.to_string().parse().unwrap(),
                );
            }

            response
        }
        RateLimitDecision::Limited { retry_after } => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later.",
            )
                .into_response();

            response.headers_mut().insert(
                "Retry-After",
                retry_after.as_secs().to_string().parse().unwrap(),
            );
            response.headers_mut().insert(
                "X-RateLimit-Limit",
                limiter.config.max_requests.to_string().parse().unwrap(),
            );
            response
                .headers_mut()
                .insert("X-RateLimit-Remaining", "0".parse().unwrap());

            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.window, Duration::from_secs(60));
        assert!(config.enabled);
    }

    #[test]
    fn test_rate_limit_config_disabled() {
        let config = RateLimitConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_rate_limit_config_custom() {
        let config = RateLimitConfig::custom(50, 30);
        assert_eq!(config.max_requests, 50);
        assert_eq!(config.window, Duration::from_secs(30));
    }

    fn allowed(decision: RateLimitDecision) -> bool {
        matches!(decision, RateLimitDecision::Allowed { .. })
    }

    fn limited(decision: RateLimitDecision) -> bool {
        matches!(decision, RateLimitDecision::Limited { .. })
    }

    #[test]
    fn test_rate_limiter_allows_requests() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(5, 60));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First 5 requests should be allowed
        for i in 0..5 {
            let result = limiter.check(ip);
            assert!(allowed(result), "Request {} should be allowed", i);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(3, 60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 requests allowed
        assert!(allowed(limiter.check(ip)));
        assert!(allowed(limiter.check(ip)));
        assert!(allowed(limiter.check(ip)));

        // 4th request should be blocked
        assert!(limited(limiter.check(ip)));
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(2, 60));
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Each IP gets its own quota
        assert!(allowed(limiter.check(ip1)));
        assert!(allowed(limiter.check(ip1)));
        assert!(limited(limiter.check(ip1))); // ip1 blocked

        assert!(allowed(limiter.check(ip2))); // ip2 still allowed
        assert!(allowed(limiter.check(ip2)));
        assert!(limited(limiter.check(ip2))); // ip2 now blocked
    }

    /// A disabled limiter reports *no limit*, never a full bucket.
    ///
    /// The distinction is the whole reason this is an enum: the middleware
    /// prints whatever count it is handed, so `Allowed { remaining: 100 }`
    /// here would advertise a 100-request budget on a server started with
    /// `--no-rate-limit`, and a client that paces itself by the header would
    /// throttle to a limit that does not exist.
    #[test]
    fn test_rate_limiter_disabled() {
        let limiter = RateLimiter::disabled();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        for _ in 0..100 {
            assert_eq!(limiter.check(ip), RateLimitDecision::Unlimited);
        }
    }

    /// The charge a decision hands back, for tests that then refund it.
    fn charge_of(decision: RateLimitDecision) -> RateLimitCharge {
        match decision {
            RateLimitDecision::Allowed { charge, .. } => charge,
            other => panic!("expected an allowed decision, got {other:?}"),
        }
    }

    /// A refunded slot goes back into the same window it came out of.
    #[test]
    fn a_refund_returns_the_slot_it_was_charged() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(2, 60));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        let first = limiter.check(ip);
        assert_eq!(first.remaining(), Some(1));
        limiter.refund(ip, charge_of(first));

        assert_eq!(
            limiter.check(ip).remaining(),
            Some(1),
            "the refunded slot is available again"
        );

        // And the limit still exists: two spent, no more refunds.
        assert!(allowed(limiter.check(ip)));
        assert!(limited(limiter.check(ip)));
    }

    /// Refunding a slot that is no longer there must not take somebody else's.
    ///
    /// This is the case the identity check exists for. A device can take
    /// seconds to send the frame that proves its token, and a window can be
    /// short enough that its charge has already expired by then — meanwhile
    /// another caller on the same address has been charged. A refund that
    /// simply dropped the newest entry would free *that* caller's live slot,
    /// handing out credit nobody paid for.
    #[test]
    fn a_refund_of_an_expired_charge_takes_nothing_from_anyone_else() {
        // A window short enough to roll over inside the test.
        let limiter = RateLimiter::new(RateLimitConfig::custom(2, 1));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        let stale = charge_of(limiter.check(ip));
        std::thread::sleep(Duration::from_millis(1100));

        // A different caller on the same address, inside the fresh window.
        assert_eq!(limiter.check(ip).remaining(), Some(1));

        limiter.refund(ip, stale);

        // One slot is left, not two: the expired charge refunded nothing.
        assert!(allowed(limiter.check(ip)), "the second slot is still free");
        assert!(
            limited(limiter.check(ip)),
            "an expired charge must not have bought a third"
        );
    }

    /// Refunding what was never charged must not create credit.
    ///
    /// A handler refunds without knowing whether the middleware charged — a
    /// disabled limiter and an exempt route both reach it — and a limiter that
    /// could go negative would be a way to bank slots.
    #[test]
    fn a_refund_without_a_charge_creates_nothing() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(1, 60));
        let unseen = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        let elsewhere = charge_of(
            RateLimiter::new(RateLimitConfig::custom(9, 60))
                .check(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
        );

        for _ in 0..5 {
            limiter.refund(unseen, elsewhere);
        }

        assert!(allowed(limiter.check(unseen)), "one request is the budget");
        limiter.refund(unseen, elsewhere);
        assert!(
            limited(limiter.check(unseen)),
            "a charge this limiter never issued banked nothing"
        );
    }

    #[test]
    fn test_rate_limiter_ipv6() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(2, 60));
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        assert!(allowed(limiter.check(ip)));
        assert!(allowed(limiter.check(ip)));
        assert!(limited(limiter.check(ip)));
    }

    #[test]
    fn test_rate_limiter_stats() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(10, 30));
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        limiter.check(ip);

        let stats = limiter.stats();
        assert_eq!(stats.tracked_ips, 1);
        assert_eq!(stats.max_requests, 10);
        assert_eq!(stats.window_secs, 30);
        assert!(stats.enabled);
    }

    #[test]
    fn test_rate_limiter_remaining_count() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(5, 60));
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

        for expected in [4, 3, 2, 1, 0] {
            assert_eq!(limiter.check(ip).remaining(), Some(expected));
        }
        assert!(limited(limiter.check(ip))); // Now blocked
    }
}
