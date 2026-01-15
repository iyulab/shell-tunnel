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
    ///
    /// Returns `Ok(remaining)` if allowed, `Err(retry_after)` if rate limited.
    pub fn check(&self, ip: IpAddr) -> Result<u32, Duration> {
        if !self.config.enabled {
            return Ok(self.config.max_requests);
        }

        // Periodic cleanup
        self.maybe_cleanup();

        let mut records = match self.records.write() {
            Ok(r) => r,
            Err(_) => return Ok(self.config.max_requests), // Fail open on lock error
        };

        let record = records.entry(ip).or_insert_with(RequestRecord::new);
        let current_count = record.clean_and_count(self.config.window);

        if current_count >= self.config.max_requests {
            // Calculate retry-after
            let oldest = record.timestamps.first().copied();
            let retry_after = oldest
                .map(|t| self.config.window.saturating_sub(t.elapsed()))
                .unwrap_or(self.config.window);
            return Err(retry_after);
        }

        // Record this request
        record.record();
        let remaining = self.config.max_requests - current_count - 1;

        Ok(remaining)
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
        Ok(remaining) => {
            let mut response = next.run(request).await;

            // Add rate limit headers
            let headers = response.headers_mut();
            headers.insert(
                "X-RateLimit-Limit",
                limiter.config.max_requests.to_string().parse().unwrap(),
            );
            headers.insert(
                "X-RateLimit-Remaining",
                remaining.to_string().parse().unwrap(),
            );

            response
        }
        Err(retry_after) => {
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

    #[test]
    fn test_rate_limiter_allows_requests() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(5, 60));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First 5 requests should be allowed
        for i in 0..5 {
            let result = limiter.check(ip);
            assert!(result.is_ok(), "Request {} should be allowed", i);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(3, 60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 requests allowed
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());

        // 4th request should be blocked
        let result = limiter.check(ip);
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(2, 60));
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Each IP gets its own quota
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_err()); // ip1 blocked

        assert!(limiter.check(ip2).is_ok()); // ip2 still allowed
        assert!(limiter.check(ip2).is_ok());
        assert!(limiter.check(ip2).is_err()); // ip2 now blocked
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let limiter = RateLimiter::disabled();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        // Should always allow when disabled
        for _ in 0..100 {
            assert!(limiter.check(ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_ipv6() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(2, 60));
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_err());
    }

    #[test]
    fn test_rate_limiter_stats() {
        let limiter = RateLimiter::new(RateLimitConfig::custom(10, 30));
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        limiter.check(ip).ok();

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

        assert_eq!(limiter.check(ip).unwrap(), 4); // 5-1 = 4 remaining
        assert_eq!(limiter.check(ip).unwrap(), 3);
        assert_eq!(limiter.check(ip).unwrap(), 2);
        assert_eq!(limiter.check(ip).unwrap(), 1);
        assert_eq!(limiter.check(ip).unwrap(), 0);
        assert!(limiter.check(ip).is_err()); // Now blocked
    }
}
