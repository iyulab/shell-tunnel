//! API Key authentication.

use std::collections::HashSet;
use std::sync::RwLock;

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};

/// API key configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Whether authentication is enabled.
    pub enabled: bool,
    /// Header name for API key (default: "Authorization").
    pub header_name: String,
    /// Prefix for the API key (default: "Bearer ").
    pub prefix: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            header_name: AUTHORIZATION.to_string(),
            prefix: "Bearer ".to_string(),
        }
    }
}

impl AuthConfig {
    /// Create a disabled auth config (for development).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Create auth config with custom prefix.
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            ..Default::default()
        }
    }
}

/// Thread-safe API key store.
#[derive(Debug)]
pub struct ApiKeyStore {
    keys: RwLock<HashSet<String>>,
    config: AuthConfig,
}

impl ApiKeyStore {
    /// Create a new API key store.
    pub fn new(config: AuthConfig) -> Self {
        Self {
            keys: RwLock::new(HashSet::new()),
            config,
        }
    }

    /// Create a store with authentication disabled.
    pub fn disabled() -> Self {
        Self::new(AuthConfig::disabled())
    }

    /// Add an API key.
    pub fn add_key(&self, key: impl Into<String>) {
        if let Ok(mut keys) = self.keys.write() {
            keys.insert(key.into());
        }
    }

    /// Remove an API key.
    pub fn remove_key(&self, key: &str) -> bool {
        self.keys
            .write()
            .map(|mut keys| keys.remove(key))
            .unwrap_or(false)
    }

    /// Check if a key is valid.
    pub fn is_valid(&self, key: &str) -> bool {
        self.keys
            .read()
            .map(|keys| keys.contains(key))
            .unwrap_or(false)
    }

    /// Get the number of registered keys.
    pub fn count(&self) -> usize {
        self.keys.read().map(|k| k.len()).unwrap_or(0)
    }

    /// Check if authentication is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Extract API key from authorization header.
    pub fn extract_key(&self, header_value: &str) -> Option<String> {
        if header_value.starts_with(&self.config.prefix) {
            Some(header_value[self.config.prefix.len()..].to_string())
        } else {
            None
        }
    }
}

impl Default for ApiKeyStore {
    fn default() -> Self {
        Self::new(AuthConfig::default())
    }
}

/// Authentication middleware for axum.
pub async fn auth_middleware(
    State(store): State<std::sync::Arc<ApiKeyStore>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth if disabled
    if !store.is_enabled() {
        return Ok(next.run(request).await);
    }

    // Skip auth for health endpoint
    if request.uri().path() == "/health" {
        return Ok(next.run(request).await);
    }

    // Extract and validate API key
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) => {
            if let Some(key) = store.extract_key(header) {
                if store.is_valid(&key) {
                    return Ok(next.run(request).await);
                }
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Generate a random API key.
pub fn generate_api_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Simple but unique key generation
    // Format: st_<timestamp_hex>_<random_hex>
    let random: u64 = (timestamp as u64)
        .wrapping_mul(0x5DEECE66D)
        .wrapping_add(0xB);
    format!("st_{:x}_{:016x}", timestamp as u64, random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();
        assert!(config.enabled);
        assert_eq!(config.prefix, "Bearer ");
    }

    #[test]
    fn test_auth_config_disabled() {
        let config = AuthConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_api_key_store_add_remove() {
        let store = ApiKeyStore::default();

        store.add_key("test-key-123");
        assert!(store.is_valid("test-key-123"));
        assert!(!store.is_valid("invalid-key"));
        assert_eq!(store.count(), 1);

        assert!(store.remove_key("test-key-123"));
        assert!(!store.is_valid("test-key-123"));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_api_key_store_extract() {
        let store = ApiKeyStore::default();

        let key = store.extract_key("Bearer my-secret-key");
        assert_eq!(key, Some("my-secret-key".to_string()));

        let no_key = store.extract_key("Basic credentials");
        assert!(no_key.is_none());
    }

    #[test]
    fn test_api_key_store_disabled() {
        let store = ApiKeyStore::disabled();
        assert!(!store.is_enabled());
    }

    #[test]
    fn test_generate_api_key() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();

        assert!(key1.starts_with("st_"));
        assert!(key2.starts_with("st_"));
        // Keys should be unique (unless generated in same nanosecond)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_api_key_store_multiple_keys() {
        let store = ApiKeyStore::default();

        store.add_key("key1");
        store.add_key("key2");
        store.add_key("key3");

        assert_eq!(store.count(), 3);
        assert!(store.is_valid("key1"));
        assert!(store.is_valid("key2"));
        assert!(store.is_valid("key3"));
    }
}
