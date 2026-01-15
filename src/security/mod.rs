//! Security module for shell-tunnel.
//!
//! This module provides authentication, rate limiting, and input validation
//! for the API layer.
//!
//! ## Features
//!
//! - **API Key Authentication**: Simple Bearer token authentication
//! - **Rate Limiting**: IP-based sliding window rate limiter
//! - **Input Validation**: Command sanitization and dangerous pattern detection
//!
//! ## Example
//!
//! ```rust
//! use shell_tunnel::security::{ApiKeyStore, RateLimiter, CommandValidator};
//!
//! // Create authentication store
//! let auth = ApiKeyStore::default();
//! auth.add_key("my-secret-key");
//!
//! // Create rate limiter (100 req/min)
//! let limiter = RateLimiter::default();
//!
//! // Create command validator
//! let validator = CommandValidator::default();
//! assert!(validator.validate_command("echo hello").is_ok());
//! ```

pub mod auth;
pub mod rate_limit;
pub mod validation;

// Re-export commonly used types
pub use auth::{auth_middleware, generate_api_key, ApiKeyStore, AuthConfig};
pub use rate_limit::{rate_limit_middleware, RateLimitConfig, RateLimiter, RateLimitStats};
pub use validation::{
    looks_like_injection, sanitize_for_display, CommandValidator, ValidationConfig,
    ValidationError,
};
