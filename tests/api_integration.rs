//! API integration tests.
//!
//! These tests verify the complete API flow end-to-end using axum's test utilities.
//! Note: Tests that execute commands are marked as ignored because they require PTY.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use serde_json::{json, Value};
use shell_tunnel::api::{create_router, create_router_with_state, AppState};
use tower::ServiceExt;

/// Helper to create a JSON request.
fn json_request(method: Method, uri: &str, body: Option<Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");

    match body {
        Some(json) => builder.body(Body::from(json.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// Helper to extract body as string.
async fn response_text(response: axum::response::Response) -> String {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&body).to_string()
}

/// Helper to extract JSON from response.
async fn response_json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

// ============================================================================
// Health & Info Tests
// ============================================================================

#[tokio::test]
async fn test_health_endpoint() {
    let app = create_router();

    let response = app
        .oneshot(json_request(Method::GET, "/health", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_text(response).await, "OK");
}

#[tokio::test]
async fn test_api_info_endpoint() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    // Try both with and without trailing slash
    let response = app
        .oneshot(json_request(Method::GET, "/api/v1", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = response_json(response).await;
    assert_eq!(json["name"], "shell-tunnel");
    assert_eq!(json["status"], "running");
}

// ============================================================================
// Session Management Tests
// ============================================================================

#[tokio::test]
async fn test_list_sessions_empty() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let response = app
        .oneshot(json_request(Method::GET, "/api/v1/sessions", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = response_json(response).await;
    assert!(json["sessions"].is_array());
    assert_eq!(json["count"], 0);
}

#[tokio::test]
async fn test_create_session() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/v1/sessions",
            Some(json!({})),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let json = response_json(response).await;
    // session_id is u64, session_id_str is the string version
    assert!(json["session_id"].is_u64());
    assert!(json["session_id_str"].is_string());
}

#[tokio::test]
async fn test_create_session_with_env() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/v1/sessions",
            Some(json!({
                "env": {
                    "MY_VAR": "my_value"
                }
            })),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_get_session_not_found() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let response = app
        .oneshot(json_request(
            Method::GET,
            "/api/v1/sessions/99999",
            None,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_session_not_found() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let response = app
        .oneshot(json_request(
            Method::DELETE,
            "/api/v1/sessions/99999",
            None,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ============================================================================
// Execution Tests (require PTY - ignored by default)
// ============================================================================

#[tokio::test]
#[ignore = "Requires PTY execution"]
async fn test_execute_oneshot() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/v1/execute",
            Some(json!({
                "command": "echo hello"
            })),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_invalid_json_body() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/sessions")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{ invalid json }"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return 422 Unprocessable Entity for invalid JSON
    assert!(response.status().is_client_error());
}

#[tokio::test]
async fn test_method_not_allowed() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let response = app
        .oneshot(json_request(Method::PUT, "/health", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_not_found_route() {
    let state = AppState::new();
    let app = create_router_with_state(state);

    let response = app
        .oneshot(json_request(Method::GET, "/nonexistent", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ============================================================================
// Security Unit Tests (no server required)
// ============================================================================

#[test]
fn test_security_config_creation() {
    use shell_tunnel::api::SecurityConfig;

    let config = SecurityConfig::secure().with_api_key("test-key");
    assert!(config.auth.enabled);
    assert_eq!(config.api_keys.len(), 1);
}

#[test]
fn test_security_config_development() {
    use shell_tunnel::api::SecurityConfig;

    let config = SecurityConfig::development();
    assert!(!config.auth.enabled);
    assert!(config.rate_limit.enabled);
}

#[test]
fn test_api_key_store_validation() {
    use shell_tunnel::security::{ApiKeyStore, AuthConfig};

    let store = ApiKeyStore::new(AuthConfig::default());
    store.add_key("valid-key");

    assert!(store.is_valid("valid-key"));
    assert!(!store.is_valid("invalid-key"));
}

#[test]
fn test_command_validator_basics() {
    use shell_tunnel::security::{CommandValidator, ValidationConfig};

    let validator = CommandValidator::new(ValidationConfig::default());

    // Valid commands
    assert!(validator.validate_command("ls -la").is_ok());
    assert!(validator.validate_command("echo hello").is_ok());

    // Invalid commands
    assert!(validator.validate_command("").is_err());
    assert!(validator.validate_command("   ").is_err());
}

#[test]
fn test_dangerous_command_detection() {
    use shell_tunnel::security::{CommandValidator, ValidationConfig};

    let validator = CommandValidator::new(ValidationConfig::default());

    // Dangerous patterns should be blocked
    assert!(validator.validate_command("rm -rf /").is_err());
    assert!(validator.validate_command(":(){ :|:& };:").is_err());
    assert!(validator.validate_command("shutdown -h now").is_err());
}
