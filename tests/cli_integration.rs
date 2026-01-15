//! CLI integration tests.
//!
//! These tests verify the CLI argument parsing and configuration loading.

use std::ffi::OsString;
use std::io::Write;
use tempfile::NamedTempFile;

use shell_tunnel::cli::{parse_args_from, Args};
use shell_tunnel::config::Config;

fn args(args: &[&str]) -> Vec<OsString> {
    std::iter::once("shell-tunnel")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect()
}

// ============================================================================
// CLI Argument Tests
// ============================================================================

#[test]
fn test_cli_defaults() {
    let result = parse_args_from(args(&[])).unwrap();

    assert_eq!(result.host.to_string(), "127.0.0.1");
    assert_eq!(result.port, 3000);
    assert!(!result.no_auth);
    assert!(!result.no_rate_limit);
    assert!(result.config.is_none());
    assert!(result.api_key.is_none());
}

#[test]
fn test_cli_full_options() {
    let result = parse_args_from(args(&[
        "-H",
        "0.0.0.0",
        "-p",
        "8080",
        "-k",
        "my-api-key",
        "-l",
        "debug",
        "--no-rate-limit",
    ]))
    .unwrap();

    assert_eq!(result.host.to_string(), "0.0.0.0");
    assert_eq!(result.port, 8080);
    assert_eq!(result.api_key, Some("my-api-key".to_string()));
    assert_eq!(result.log_level, Some("debug".to_string()));
    assert!(result.no_rate_limit);
    assert!(!result.no_auth);
}

#[test]
fn test_cli_config_file() {
    let result = parse_args_from(args(&["-c", "/etc/shell-tunnel.json"])).unwrap();

    assert!(result.config.is_some());
    assert_eq!(
        result.config.unwrap().to_str().unwrap(),
        "/etc/shell-tunnel.json"
    );
}

#[test]
fn test_cli_invalid_port() {
    let result = parse_args_from(args(&["-p", "not-a-number"]));
    assert!(result.is_err());
}

#[test]
fn test_cli_invalid_host() {
    let result = parse_args_from(args(&["-H", "not-an-ip"]));
    assert!(result.is_err());
}

// ============================================================================
// Configuration Loading Tests
// ============================================================================

#[test]
fn test_config_from_json_file() {
    let json = r#"{
        "server": {
            "host": "192.168.1.100",
            "port": 9000,
            "graceful_shutdown": false
        },
        "security": {
            "auth": {
                "enabled": true,
                "api_keys": ["key1", "key2"]
            },
            "rate_limit": {
                "enabled": true,
                "requests_per_window": 50,
                "window_secs": 30
            }
        },
        "logging": {
            "level": "debug"
        }
    }"#;

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(json.as_bytes()).unwrap();

    let config = Config::from_file(file.path()).unwrap();

    assert_eq!(config.server.host, "192.168.1.100");
    assert_eq!(config.server.port, 9000);
    assert!(!config.server.graceful_shutdown);
    assert!(config.security.auth.enabled);
    assert_eq!(config.security.auth.api_keys.len(), 2);
    assert!(config.security.rate_limit.enabled);
    assert_eq!(config.security.rate_limit.requests_per_window, 50);
    assert_eq!(config.logging.level, "debug");
}

#[test]
fn test_config_priority_cli_over_file() {
    // Create config file
    let json = r#"{
        "server": {
            "host": "10.0.0.1",
            "port": 5000
        }
    }"#;

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(json.as_bytes()).unwrap();

    // CLI args should override file
    let args = Args {
        host: "192.168.1.1".parse().unwrap(),
        port: 8080,
        config: Some(file.path().to_path_buf()),
        ..Args::default()
    };

    let config = Config::load(&args).unwrap();

    // CLI values should win
    assert_eq!(config.server.host, "192.168.1.1");
    assert_eq!(config.server.port, 8080);
}

#[test]
fn test_config_api_key_enables_auth() {
    let args = Args {
        api_key: Some("secret-key".to_string()),
        ..Args::default()
    };

    let config = Config::load(&args).unwrap();

    assert!(config.security.auth.enabled);
    assert!(config
        .security
        .auth
        .api_keys
        .contains(&"secret-key".to_string()));
}

#[test]
fn test_config_no_auth_disables() {
    let json = r#"{
        "security": {
            "auth": {
                "enabled": true,
                "api_keys": ["key1"]
            }
        }
    }"#;

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(json.as_bytes()).unwrap();

    let args = Args {
        config: Some(file.path().to_path_buf()),
        no_auth: true,
        ..Args::default()
    };

    let config = Config::load(&args).unwrap();

    // --no-auth should disable even if config has it enabled
    assert!(!config.security.auth.enabled);
}

#[test]
fn test_config_to_server_config() {
    let args = Args {
        host: "0.0.0.0".parse().unwrap(),
        port: 8080,
        api_key: Some("test-key".to_string()),
        ..Args::default()
    };

    let config = Config::load(&args).unwrap();
    let server_config = config.to_server_config().unwrap();

    assert_eq!(server_config.host, "0.0.0.0");
    assert_eq!(server_config.port, 8080);
    assert!(server_config.security.auth.enabled);
}

// ============================================================================
// Configuration Serialization Tests
// ============================================================================

#[test]
fn test_config_roundtrip() {
    let original = Config::default();
    let json = serde_json::to_string(&original).unwrap();
    let loaded: Config = serde_json::from_str(&json).unwrap();

    assert_eq!(original.server.host, loaded.server.host);
    assert_eq!(original.server.port, loaded.server.port);
}

#[test]
fn test_config_partial_deserialization() {
    // Only specify some fields, others should use defaults
    let json = r#"{"server": {"port": 9999}}"#;
    let config: Config = serde_json::from_str(json).unwrap();

    assert_eq!(config.server.port, 9999);
    assert_eq!(config.server.host, "127.0.0.1"); // Default
    assert!(config.server.graceful_shutdown); // Default
}
