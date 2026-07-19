//! Configuration management for shell-tunnel.
//!
//! Configuration is loaded with the following priority (highest to lowest):
//! 1. Command-line arguments
//! 2. Environment variables
//! 3. Configuration file (JSON)
//! 4. Default values

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::api::{CorsConfig, SecurityConfig, ServerConfig};
use crate::cli::Args;
use crate::security::{AuthConfig, CapabilitySet, RateLimitConfig};

/// Application configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Server configuration.
    pub server: ServerSection,
    /// Security configuration.
    pub security: SecuritySection,
    /// Logging configuration.
    pub logging: LoggingSection,
}

/// Server configuration section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    /// Host address to bind to.
    pub host: String,
    /// Port to listen on.
    pub port: u16,
    /// Enable graceful shutdown.
    pub graceful_shutdown: bool,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            graceful_shutdown: true,
        }
    }
}

/// Security configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecuritySection {
    /// Authentication settings.
    pub auth: AuthSection,
    /// Rate limiting settings.
    pub rate_limit: RateLimitSection,
    /// CORS settings.
    pub cors: CorsSection,
}

/// CORS configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CorsSection {
    /// Allow any origin (permissive CORS). Off by default; enable only for
    /// trusted browser-based UIs.
    pub allow_any: bool,
}

/// Authentication configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthSection {
    /// Enable authentication.
    pub enabled: bool,
    /// API keys.
    pub api_keys: Vec<String>,
    /// Capability strings scoping the keys (empty = full-control).
    pub capabilities: Vec<String>,
    /// Role preset scoping the keys (operator/read-only/full-control).
    pub preset: Option<String>,
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitSection {
    /// Enable rate limiting.
    pub enabled: bool,
    /// Requests per window.
    pub requests_per_window: u32,
    /// Window size in seconds.
    pub window_secs: u64,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_window: 100,
            window_secs: 60,
        }
    }
}

/// Logging configuration section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingSection {
    /// Log level (error, warn, info, debug, trace).
    pub level: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from a JSON file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        serde_json::from_str(&content).map_err(ConfigError::Json)
    }

    /// Apply environment variable overrides.
    pub fn apply_env(&mut self) {
        if let Ok(host) = std::env::var("SHELL_TUNNEL_HOST") {
            self.server.host = host;
        }

        if let Ok(port) = std::env::var("SHELL_TUNNEL_PORT") {
            if let Ok(port) = port.parse() {
                self.server.port = port;
            }
        }

        if let Ok(key) = std::env::var("SHELL_TUNNEL_API_KEY") {
            if !key.is_empty() {
                self.security.auth.enabled = true;
                if !self.security.auth.api_keys.contains(&key) {
                    self.security.auth.api_keys.push(key);
                }
            }
        }

        if let Ok(level) = std::env::var("SHELL_TUNNEL_LOG_LEVEL") {
            self.logging.level = level;
        } else if let Ok(level) = std::env::var("RUST_LOG") {
            self.logging.level = level;
        }
    }

    /// Apply CLI argument overrides.
    pub fn apply_args(&mut self, args: &Args) {
        self.server.host = args.host.to_string();
        self.server.port = args.port;

        if let Some(ref key) = args.api_key {
            self.security.auth.enabled = true;
            if !self.security.auth.api_keys.contains(key) {
                self.security.auth.api_keys.push(key.clone());
            }
        }

        // Enable auth on request (a key is auto-generated at startup if none is set).
        // Applied before `no_auth` so an explicit `--no-auth` still wins.
        if args.require_auth {
            self.security.auth.enabled = true;
        }

        // Token scoping (fine-grained capabilities / preset). Specifying a scope
        // implies auth-on — otherwise the scope would be silently ignored and the
        // server would start open, the opposite of what `--preset read-only` asks
        // for. Applied before `no_auth` so an explicit `--no-auth` still wins.
        if !args.capabilities.is_empty() {
            self.security.auth.capabilities = args.capabilities.clone();
            self.security.auth.enabled = true;
        }
        if let Some(ref preset) = args.preset {
            self.security.auth.preset = Some(preset.clone());
            self.security.auth.enabled = true;
        }

        if args.no_auth {
            self.security.auth.enabled = false;
        }

        if args.no_rate_limit {
            self.security.rate_limit.enabled = false;
        }

        if args.cors_allow_any {
            self.security.cors.allow_any = true;
        }

        if let Some(ref level) = args.log_level {
            self.logging.level = level.clone();
        }
    }

    /// Load configuration with full priority chain.
    ///
    /// Priority: CLI args > env vars > config file > defaults
    pub fn load(args: &Args) -> Result<Self, ConfigError> {
        // Start with defaults
        let mut config = Config::default();

        // Load from config file if specified
        if let Some(ref path) = args.config {
            config = Config::from_file(path)?;
        }

        // Apply environment variable overrides
        config.apply_env();

        // Apply CLI argument overrides (highest priority)
        config.apply_args(args);

        Ok(config)
    }

    /// Convert to ServerConfig for the API server.
    pub fn to_server_config(&self) -> Result<ServerConfig, ConfigError> {
        let host: IpAddr = self
            .server
            .host
            .parse()
            .map_err(|_| ConfigError::InvalidHost(self.server.host.clone()))?;

        let mut security = if self.security.auth.enabled {
            SecurityConfig::secure()
        } else {
            SecurityConfig::development()
        };

        // Apply auth settings
        security.auth = AuthConfig {
            enabled: self.security.auth.enabled,
            ..AuthConfig::default()
        };

        // Apply rate limit settings
        security.rate_limit = RateLimitConfig {
            enabled: self.security.rate_limit.enabled,
            max_requests: self.security.rate_limit.requests_per_window,
            window: std::time::Duration::from_secs(self.security.rate_limit.window_secs),
            max_tracked_ips: 10000,
        };

        // Apply CORS settings (restrictive by default)
        security.cors = CorsConfig {
            allow_any: self.security.cors.allow_any,
        };

        // Resolve fine-grained token scoping (preset + capabilities).
        if let Some(capabilities) = resolve_capabilities(
            self.security.auth.preset.as_deref(),
            &self.security.auth.capabilities,
        )? {
            security = security.with_capabilities(capabilities);
        }

        // Add API keys
        for key in &self.security.auth.api_keys {
            security = security.with_api_key(key);
        }

        let mut server_config = ServerConfig::new(host.to_string(), self.server.port);
        server_config = server_config.with_security(security);

        if !self.server.graceful_shutdown {
            server_config = server_config.without_graceful_shutdown();
        }

        Ok(server_config)
    }

    /// Get the log level filter string.
    pub fn log_filter(&self) -> &str {
        &self.logging.level
    }
}

/// Resolve a `preset` name + explicit `capabilities` list into a capability set.
///
/// Returns `Ok(None)` when neither is given (full-control default). The preset
/// (if any) forms the base set and the explicit capabilities are unioned on top.
/// An unknown preset name is an error.
fn resolve_capabilities(
    preset: Option<&str>,
    capabilities: &[String],
) -> Result<Option<CapabilitySet>, ConfigError> {
    if preset.is_none() && capabilities.is_empty() {
        return Ok(None); // Full-control (legacy-compatible) default.
    }

    let mut set = match preset {
        Some(name) => crate::security::preset(name)
            .ok_or_else(|| ConfigError::InvalidPreset(name.to_string()))?,
        None => CapabilitySet::new(),
    };
    for capability in capabilities {
        set.insert(capability.clone());
    }
    Ok(Some(set))
}

/// Configuration errors.
#[derive(Debug)]
pub enum ConfigError {
    /// IO error reading config file.
    Io(std::io::Error),
    /// JSON parsing error.
    Json(serde_json::Error),
    /// Invalid host address.
    InvalidHost(String),
    /// Unknown role preset name.
    InvalidPreset(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read config file: {}", e),
            Self::Json(e) => write!(f, "failed to parse config file: {}", e),
            Self::InvalidHost(host) => write!(f, "invalid host address: {}", host),
            Self::InvalidPreset(name) => write!(
                f,
                "unknown role preset: '{}' (expected operator, read-only, or full-control)",
                name
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 3000);
        assert!(!config.security.auth.enabled);
        assert!(config.security.rate_limit.enabled);
    }

    #[test]
    fn test_config_from_json() {
        let json = r#"{
            "server": {
                "host": "0.0.0.0",
                "port": 8080
            },
            "security": {
                "auth": {
                    "enabled": true,
                    "api_keys": ["key1", "key2"]
                }
            }
        }"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert!(config.security.auth.enabled);
        assert_eq!(config.security.auth.api_keys.len(), 2);
    }

    #[test]
    fn test_config_partial_json() {
        let json = r#"{
            "server": {
                "port": 9000
            }
        }"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.server.host, "127.0.0.1"); // Default
        assert_eq!(config.server.port, 9000);
    }

    #[test]
    fn test_apply_args() {
        let mut config = Config::default();
        let args = Args {
            host: "192.168.1.1".parse().unwrap(),
            port: 5000,
            api_key: Some("test-key".to_string()),
            no_rate_limit: true,
            ..Args::default()
        };

        config.apply_args(&args);

        assert_eq!(config.server.host, "192.168.1.1");
        assert_eq!(config.server.port, 5000);
        assert!(config.security.auth.enabled);
        assert!(config
            .security
            .auth
            .api_keys
            .contains(&"test-key".to_string()));
        assert!(!config.security.rate_limit.enabled);
    }

    #[test]
    fn test_apply_no_auth() {
        let mut config = Config::default();
        config.security.auth.enabled = true;

        let args = Args {
            no_auth: true,
            ..Args::default()
        };

        config.apply_args(&args);
        assert!(!config.security.auth.enabled);
    }

    #[test]
    fn test_apply_require_auth() {
        let mut config = Config::default();
        assert!(!config.security.auth.enabled); // disabled by default

        config.apply_args(&Args {
            require_auth: true,
            ..Args::default()
        });
        assert!(config.security.auth.enabled);
    }

    #[test]
    fn test_no_auth_overrides_require_auth() {
        let mut config = Config::default();

        // Contradictory flags: explicit --no-auth wins.
        config.apply_args(&Args {
            require_auth: true,
            no_auth: true,
            ..Args::default()
        });
        assert!(!config.security.auth.enabled);
    }

    #[test]
    fn test_to_server_config() {
        let config = Config::default();
        let server_config = config.to_server_config().unwrap();

        assert_eq!(server_config.host, "127.0.0.1");
        assert_eq!(server_config.port, 3000);
    }

    #[test]
    fn test_apply_args_capabilities_and_preset() {
        let mut config = Config::default();
        config.apply_args(&Args {
            capabilities: vec!["exec".to_string(), "session.read".to_string()],
            preset: Some("operator".to_string()),
            ..Args::default()
        });
        assert_eq!(
            config.security.auth.capabilities,
            vec!["exec", "session.read"]
        );
        assert_eq!(config.security.auth.preset, Some("operator".to_string()));
    }

    #[test]
    fn test_scope_implies_auth_on() {
        // Specifying a scope (preset or capabilities) with no --api-key/--require-auth
        // still turns auth on, so the server does not start open with the scope ignored.
        let mut by_preset = Config::default();
        by_preset.apply_args(&Args {
            preset: Some("read-only".to_string()),
            ..Args::default()
        });
        assert!(by_preset.security.auth.enabled);

        let mut by_caps = Config::default();
        by_caps.apply_args(&Args {
            capabilities: vec!["session.read".to_string()],
            ..Args::default()
        });
        assert!(by_caps.security.auth.enabled);
    }

    #[test]
    fn test_no_auth_overrides_scope_implied_auth() {
        // Explicit --no-auth wins even when a scope is given.
        let mut config = Config::default();
        config.apply_args(&Args {
            preset: Some("read-only".to_string()),
            no_auth: true,
            ..Args::default()
        });
        assert!(!config.security.auth.enabled);
    }

    #[test]
    fn test_config_from_json_with_capabilities_and_preset() {
        // The new AuthSection fields deserialize from a config file and flow
        // through to a scoped SecurityConfig.
        let json = r#"{
            "security": {
                "auth": {
                    "enabled": true,
                    "api_keys": ["scoped"],
                    "preset": "read-only",
                    "capabilities": ["exec"]
                }
            }
        }"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.security.auth.preset, Some("read-only".to_string()));
        assert_eq!(config.security.auth.capabilities, vec!["exec"]);

        let server_config = config.to_server_config().unwrap();
        let caps = server_config
            .security
            .capabilities
            .expect("capabilities scoped from file");
        assert!(caps.satisfies("session.read")); // from read-only preset
        assert!(caps.satisfies("exec")); // unioned explicit capability
        assert!(!caps.satisfies("session.manage"));
    }

    #[test]
    fn test_resolve_capabilities_none_by_default() {
        // No preset, no capabilities -> full-control (None).
        assert!(resolve_capabilities(None, &[]).unwrap().is_none());
    }

    #[test]
    fn test_resolve_capabilities_preset_plus_extra() {
        // read-only preset unioned with an explicit `exec`.
        let set = resolve_capabilities(Some("read-only"), &["exec".to_string()])
            .unwrap()
            .unwrap();
        assert!(set.satisfies("session.read"));
        assert!(set.satisfies("exec"));
        assert!(!set.satisfies("session.manage"));
    }

    #[test]
    fn test_resolve_capabilities_invalid_preset_errors() {
        let err = resolve_capabilities(Some("superuser"), &[]);
        assert!(matches!(err, Err(ConfigError::InvalidPreset(_))));
    }

    #[test]
    fn test_to_server_config_scopes_capabilities() {
        let mut config = Config::default();
        config.security.auth.enabled = true;
        config.security.auth.api_keys = vec!["scoped".to_string()];
        config.security.auth.preset = Some("read-only".to_string());

        let server_config = config.to_server_config().unwrap();
        let caps = server_config
            .security
            .capabilities
            .expect("capabilities scoped");
        assert!(caps.satisfies("session.read"));
        assert!(!caps.satisfies("exec"));
    }

    #[test]
    fn test_to_server_config_invalid_preset_errors() {
        let mut config = Config::default();
        config.security.auth.preset = Some("root".to_string());
        assert!(matches!(
            config.to_server_config(),
            Err(ConfigError::InvalidPreset(_))
        ));
    }

    #[test]
    fn test_invalid_host() {
        let mut config = Config::default();
        config.server.host = "not-an-ip".to_string();

        let result = config.to_server_config();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("\"host\""));
        assert!(json.contains("\"port\""));
    }
}
