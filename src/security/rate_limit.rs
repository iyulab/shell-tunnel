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

    /// Record a new request.
    fn record(&mut self) {
        self.timestamps.push(Instant::now());
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
    Allowed { remaining: u32 },
    /// Refused; the window frees up after this long.
    Limited { retry_after: Duration },
}

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
        record.record();
        let remaining = self.config.max_requests - current_count - 1;

        RateLimitDecision::Allowed { remaining }
    }

    /// Give back a slot this IP was charged for.
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
    /// Drops the *newest* timestamp rather than hunting for the one this
    /// caller was charged. Concurrent requests from one address are
    /// interchangeable as far as the count goes, and dropping the newest can
    /// only make the window expire sooner — dropping the oldest would extend
    /// it, which is the direction that must not be got wrong.
    pub fn refund(&self, ip: IpAddr) {
        if !self.config.enabled {
            return;
        }

        let Ok(mut records) = self.records.write() else {
            return;
        };

        if let Some(record) = records.get_mut(&ip) {
            record.timestamps.pop();
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
    request: Request,
    next: Next,
) -> Response {
    // Skip rate limiting for health endpoint
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }

    match limiter.check(addr.ip()) {
        // Nothing counted this request, so nothing is advertised about it.
        RateLimitDecision::Unlimited => next.run(request).await,
        RateLimitDecision::Allowed { remaining } => {
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
            let headers = response.headers_mut();
            if !headers.contains_key("X-RateLimit-Limit")
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

    /// A refunded slot goes back into the same window it came out of.
    #[test]
    fn a_refund_returns_the_slot_it_was_charged() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(2, 60));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        assert_eq!(
            limiter.check(ip),
            RateLimitDecision::Allowed { remaining: 1 }
        );
        limiter.refund(ip);
        assert_eq!(
            limiter.check(ip),
            RateLimitDecision::Allowed { remaining: 1 },
            "the refunded slot is available again"
        );

        // And the limit still exists: two spent, no more refunds.
        assert!(allowed(limiter.check(ip)));
        assert!(limited(limiter.check(ip)));
    }

    /// Refunding what was never charged must not create credit.
    ///
    /// An address with no record at all, and one whose window has already been
    /// emptied, both reach this — a handler refunds without knowing whether the
    /// middleware charged, and a limiter that went negative would be a way to
    /// bank slots.
    #[test]
    fn a_refund_without_a_charge_creates_nothing() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(1, 60));
        let unseen = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));

        for _ in 0..5 {
            limiter.refund(unseen);
        }

        assert!(allowed(limiter.check(unseen)), "one request is the budget");
        limiter.refund(unseen);
        limiter.refund(unseen);
        assert!(allowed(limiter.check(unseen)), "the one refund applies");
        assert!(
            limited(limiter.check(unseen)),
            "the extra refunds banked nothing"
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
            assert_eq!(
                limiter.check(ip),
                RateLimitDecision::Allowed {
                    remaining: expected
                }
            );
        }
        assert!(limited(limiter.check(ip))); // Now blocked
    }
}
