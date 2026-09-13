//! Security module for shell-tunnel.
//!
//! **Two of the three things here are defences this server applies; the third is
//! a primitive it offers and does not use.** They were listed together as
//! "provided for the API layer", which reads as three active defences and is
//! not what happens.
//!
//! ## Applied by the server, on every request
//!
//! - **API key authentication** — bearer tokens, scoped by capability
//!   ([`auth`], [`capability`]).
//! - **Rate limiting** — per-address sliding window ([`rate_limit`]).
//!
//! ## Offered, and not applied
//!
//! - **Command validation** ([`validation`]) — [`CommandValidator`],
//!   [`looks_like_injection`] and the rest are **not called from any execute
//!   path**. A command sent to `/execute` reaches the shell without passing
//!   through them, and nothing here is a barrier between a caller and the
//!   machine; the barriers are the two above, plus [`crate::fs::FsRoot`] on the
//!   filesystem routes.
//!
//!   Whether to wire it is an open product question rather than an oversight: a
//!   substring blocklist on by default is a trade a run-anything tool has to
//!   choose deliberately. Until it is chosen, this stays a primitive a consumer
//!   may apply to its own input before calling — which is a real use, and the
//!   reason it is still exported.
//!
//! ## Example
//!
//! ```rust
//! use shell_tunnel::security::{ApiKeyStore, RateLimiter, CommandValidator};
//!
//! // Applied by the server: authentication …
//! let auth = ApiKeyStore::default();
//! auth.add_key("my-secret-key");
//!
//! // … and rate limiting (100 req/min).
//! let limiter = RateLimiter::default();
//!
//! // Offered, not applied: a consumer may run this over its own input before
//! // calling the API. The server does not.
//! let validator = CommandValidator::default();
//! assert!(validator.validate_command("echo hello").is_ok());
//! ```

pub mod auth;
pub mod capability;
pub mod rate_limit;
pub mod validation;

// Re-export commonly used types
pub use auth::{auth_middleware, generate_api_key, ApiKeyStore, AuthConfig, TokenRecord};
pub use capability::{preset, CapabilitySet, KNOWN_CAPABILITIES, WILDCARD};
pub use rate_limit::{
    rate_limit_middleware, RateLimitCharge, RateLimitConfig, RateLimitDecision, RateLimitStats,
    RateLimiter, RELAY_HOP_HEADER,
};
pub use validation::{
    looks_like_injection, sanitize_for_display, CommandValidator, ValidationConfig, ValidationError,
};

/// Compare secrets without leaking their contents through timing.
///
/// The token is short and comparisons are rare, but an early-exit `==` on a
/// shared secret is the kind of detail that is cheap to get right and awkward
/// to retrofit. Shared by the relay's enrol-token checks and the rate limiter's
/// relay-hop marker, which is why it lives here rather than in either.
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
