//! API Key authentication.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::SystemTime;

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};

use super::capability::CapabilitySet;

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

/// A registered token: the capabilities it grants plus provenance metadata.
///
/// The store maps an opaque bearer-token string to one of these records
/// (spec §9). The token string itself stays the wire credential
/// (`Authorization: Bearer <token>`); the record is the server-side authority
/// on what that token may do.
#[derive(Debug, Clone)]
pub struct TokenRecord {
    /// Identifier for the audit trail.
    ///
    /// Assigned at registration and unrelated to the token's value, so a trail
    /// can name the caller without containing the credential. Per-process:
    /// tokens are not persisted, so neither is this.
    pub id: String,
    /// Capabilities this token grants (spec §2 mechanism).
    pub capabilities: CapabilitySet,
    /// Human-readable label for provenance (e.g. `"legacy"`, `"operator"`).
    pub label: String,
    /// When the token was registered.
    pub created_at: SystemTime,
}

impl TokenRecord {
    /// Create a token record with the given capabilities and label.
    pub fn new(capabilities: CapabilitySet, label: impl Into<String>) -> Self {
        Self {
            id: generate_token_id(),
            capabilities,
            label: label.into(),
            created_at: SystemTime::now(),
        }
    }

    /// Create a full-control (wildcard) token — the legacy-key mapping target
    /// and the `full-control` preset (spec §4, §6).
    pub fn full_control(label: impl Into<String>) -> Self {
        Self::new(CapabilitySet::wildcard(), label)
    }
}

/// Thread-safe token store, keyed by opaque bearer-token string.
#[derive(Debug)]
pub struct ApiKeyStore {
    tokens: RwLock<HashMap<String, TokenRecord>>,
    config: AuthConfig,
}

impl ApiKeyStore {
    /// Create a new token store.
    pub fn new(config: AuthConfig) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Create a store with authentication disabled.
    pub fn disabled() -> Self {
        Self::new(AuthConfig::disabled())
    }

    /// Add a legacy full-control API key.
    ///
    /// Backward-compatibility path (spec §4): a bare key with no declared
    /// capabilities maps to a `full-control` token holding the wildcard, so any
    /// existing `--api-key` / `--require-auth` consumer is unaffected and can
    /// never trigger a 403.
    pub fn add_key(&self, key: impl Into<String>) {
        self.add_token(key, TokenRecord::full_control("legacy"));
    }

    /// Register a token string with an explicit capability record.
    pub fn add_token(&self, key: impl Into<String>, record: TokenRecord) {
        if let Ok(mut tokens) = self.tokens.write() {
            tokens.insert(key.into(), record);
        }
    }

    /// Register a token with the given capabilities and label.
    pub fn add_key_with_capabilities(
        &self,
        key: impl Into<String>,
        capabilities: CapabilitySet,
        label: impl Into<String>,
    ) {
        self.add_token(key, TokenRecord::new(capabilities, label));
    }

    /// Remove a token.
    pub fn remove_key(&self, key: &str) -> bool {
        self.tokens
            .write()
            .map(|mut tokens| tokens.remove(key).is_some())
            .unwrap_or(false)
    }

    /// Check if a token is registered (valid).
    pub fn is_valid(&self, key: &str) -> bool {
        self.tokens
            .read()
            .map(|tokens| tokens.contains_key(key))
            .unwrap_or(false)
    }

    /// Look up the capabilities a token grants, if it is registered.
    ///
    /// This is the store surface the scope-aware middleware consumes
    /// (spec §5 step 2): token → `TokenRecord` → capability check.
    pub fn capabilities(&self, key: &str) -> Option<CapabilitySet> {
        self.tokens
            .read()
            .ok()
            .and_then(|tokens| tokens.get(key).map(|record| record.capabilities.clone()))
    }

    /// Identify a token for the audit trail, without revealing it.
    pub fn identity(&self, key: &str) -> Option<crate::audit::Identity> {
        self.tokens.read().ok().and_then(|tokens| {
            tokens.get(key).map(|record| crate::audit::Identity {
                token_id: record.id.clone(),
                label: record.label.clone(),
            })
        })
    }

    /// Get the number of registered tokens.
    pub fn count(&self) -> usize {
        self.tokens.read().map(|t| t.len()).unwrap_or(0)
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

/// Short identifier for an audit trail entry.
///
/// Random rather than derived from the token: a derived value would let anyone
/// holding the log test guesses against it.
fn generate_token_id() -> String {
    let full = generate_api_key();
    format!("tok_{}", &full[full.len().saturating_sub(12)..])
}

/// Generate a random API key.
pub fn generate_api_key() -> String {
    // 128 bits of OS entropy, printed in the shape keys have always had
    // (`st_<16 hex>_<16 hex>`). The shape is all that survives of the old
    // scheme: its second half was an affine function of its first (a
    // timestamp), which made every issued key recoverable from a guess at
    // the clock. An entropy source that fails stops key issuance here,
    // rather than shipping a credential weaker than it looks.
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the OS entropy source is unavailable");
    let (a, b) = bytes.split_at(8);
    format!(
        "st_{:016x}_{:016x}",
        u64::from_be_bytes(a.try_into().expect("split_at(8) yields 8 bytes")),
        u64::from_be_bytes(b.try_into().expect("split_at(8) yields 8 bytes"))
    )
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
        assert_ne!(key1, key2);
    }

    #[test]
    fn the_secret_half_is_not_a_function_of_the_printed_half() {
        // The vulnerability this pins down: keys were
        // `st_<timestamp>_<timestamp * 0x5DEECE66D + 0xB>`, so the "secret"
        // half was recoverable from the half printed next to it — and the
        // whole key from a guess at the clock. The halves must be
        // independent; under a random key this relation holds with
        // probability 2^-64.
        let key = generate_api_key();
        let mut halves = key.trim_start_matches("st_").split('_');
        let printed = u64::from_str_radix(halves.next().unwrap(), 16).unwrap();
        let secret = u64::from_str_radix(halves.next().unwrap(), 16).unwrap();
        assert_ne!(
            secret,
            printed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB),
            "the second half of {key} is derived from the first"
        );
    }

    #[test]
    fn keys_generated_back_to_back_are_all_distinct() {
        // The macOS CI failure: two calls inside one clock tick produced the
        // same key, because the clock was the only entropy. A tight loop must
        // never collide.
        let keys: std::collections::HashSet<String> =
            (0..1000).map(|_| generate_api_key()).collect();
        assert_eq!(keys.len(), 1000);
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

    #[test]
    fn test_legacy_key_maps_to_full_control() {
        // spec §4: a bare `add_key` maps to a wildcard token so legacy
        // consumers can never trigger a 403.
        let store = ApiKeyStore::default();
        store.add_key("legacy-key");

        let caps = store.capabilities("legacy-key").expect("token registered");
        assert!(caps.is_wildcard());
        assert!(caps.satisfies("exec"));
        assert!(caps.satisfies("session.manage"));
    }

    #[test]
    fn test_add_key_with_capabilities() {
        let store = ApiKeyStore::default();
        let caps: CapabilitySet = ["exec", "session.read"].into_iter().collect();
        store.add_key_with_capabilities("fine-grained", caps, "operator");

        assert!(store.is_valid("fine-grained"));
        let caps = store
            .capabilities("fine-grained")
            .expect("token registered");
        assert!(caps.satisfies("exec"));
        assert!(caps.satisfies("session.read"));
        // Fine-grained token is NOT wildcard and lacks unlisted capabilities.
        assert!(!caps.is_wildcard());
        assert!(!caps.satisfies("session.manage"));
    }

    #[test]
    fn test_capabilities_of_unknown_key_is_none() {
        let store = ApiKeyStore::default();
        assert!(store.capabilities("nope").is_none());
    }

    #[test]
    fn test_token_record_full_control() {
        let record = TokenRecord::full_control("legacy");
        assert!(record.capabilities.is_wildcard());
        assert_eq!(record.label, "legacy");
    }
}
