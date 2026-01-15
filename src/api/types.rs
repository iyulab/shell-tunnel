//! API request and response types.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::session::{SessionId, SessionState};

/// Request to create a new session.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CreateSessionRequest {
    /// Shell command to use (e.g., "bash", "powershell.exe").
    #[serde(default)]
    pub shell: Option<String>,
    /// Initial working directory.
    #[serde(default)]
    pub working_dir: Option<String>,
    /// Environment variables to set.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Response for session creation.
#[derive(Debug, Clone, Serialize)]
pub struct CreateSessionResponse {
    /// The assigned session ID.
    pub session_id: u64,
    /// Human-readable session ID string.
    pub session_id_str: String,
}

impl CreateSessionResponse {
    pub fn new(id: SessionId) -> Self {
        Self {
            session_id: id.as_u64(),
            session_id_str: id.to_string(),
        }
    }
}

/// Response for session status query.
#[derive(Debug, Clone, Serialize)]
pub struct SessionStatusResponse {
    /// Session ID.
    pub session_id: u64,
    /// Current state.
    pub state: String,
    /// Working directory (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Last exit code (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exit_code: Option<i32>,
    /// Total commands executed.
    pub execution_count: u64,
    /// Idle duration in seconds.
    pub idle_seconds: f64,
}

impl SessionStatusResponse {
    pub fn from_session(session: &crate::session::Session) -> Self {
        Self {
            session_id: session.id.as_u64(),
            state: format!("{:?}", session.state),
            working_dir: session
                .context
                .cwd()
                .map(|p| p.to_string_lossy().to_string()),
            last_exit_code: session.context.last_exit_code(),
            execution_count: session.context.execution_count(),
            idle_seconds: session.idle_duration().as_secs_f64(),
        }
    }
}

/// Request to execute a command.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecuteCommandRequest {
    /// The command line to execute.
    pub command: String,
    /// Optional working directory override.
    #[serde(default)]
    pub working_dir: Option<String>,
    /// Optional environment variables.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Timeout in seconds.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

impl ExecuteCommandRequest {
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout_secs.map(Duration::from_secs)
    }
}

/// Response for command execution.
#[derive(Debug, Clone, Serialize)]
pub struct ExecuteCommandResponse {
    /// Whether execution was successful.
    pub success: bool,
    /// Exit code (if process completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Cleaned output text.
    pub output: String,
    /// Raw output (base64 encoded if binary content detected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<String>,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the command timed out.
    pub timed_out: bool,
}

impl ExecuteCommandResponse {
    pub fn from_result(result: &crate::execution::ExecutionResult) -> Self {
        Self {
            success: result.exit_code.map(|c| c == 0).unwrap_or(false) && !result.timed_out,
            exit_code: result.exit_code,
            output: result.text_output.clone(),
            raw_output: None, // Only include if requested
            duration_ms: result.duration.as_millis() as u64,
            timed_out: result.timed_out,
        }
    }

    pub fn with_raw_output(mut self, include: bool, raw: &[u8]) -> Self {
        if include {
            // Convert to string, lossy if non-UTF8
            self.raw_output = Some(String::from_utf8_lossy(raw).to_string());
        }
        self
    }
}

/// Generic API error response.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// Error code (e.g., "SESSION_NOT_FOUND").
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Additional details (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    pub fn session_not_found(id: &str) -> Self {
        Self::new("SESSION_NOT_FOUND", format!("Session '{}' not found", id))
    }

    pub fn invalid_state(state: SessionState) -> Self {
        Self::new(
            "INVALID_STATE",
            format!(
                "Session is in {:?} state and cannot execute commands",
                state
            ),
        )
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new("INTERNAL_ERROR", message)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("BAD_REQUEST", message)
    }
}

/// WebSocket message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// Client sends command to execute.
    Execute {
        command: String,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// Server sends output chunk.
    Output {
        data: String,
        /// Whether this is the final chunk.
        #[serde(default)]
        is_final: bool,
    },
    /// Server sends execution result.
    Result {
        success: bool,
        exit_code: Option<i32>,
        duration_ms: u64,
        timed_out: bool,
    },
    /// Error message.
    Error {
        code: String,
        message: String,
    },
    /// Ping/pong for connection health.
    Ping,
    Pong,
}

/// List sessions response.
#[derive(Debug, Clone, Serialize)]
pub struct ListSessionsResponse {
    /// Total number of sessions.
    pub count: usize,
    /// Session summaries.
    pub sessions: Vec<SessionSummary>,
}

/// Brief session summary for listing.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub session_id: u64,
    pub state: String,
    pub idle_seconds: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_request_default() {
        let req: CreateSessionRequest = serde_json::from_str("{}").unwrap();
        assert!(req.shell.is_none());
        assert!(req.working_dir.is_none());
        assert!(req.env.is_empty());
    }

    #[test]
    fn test_create_session_request_with_fields() {
        let json = r#"{"shell": "bash", "working_dir": "/tmp"}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.shell, Some("bash".to_string()));
        assert_eq!(req.working_dir, Some("/tmp".to_string()));
    }

    #[test]
    fn test_execute_command_request() {
        let json = r#"{"command": "echo hello", "timeout_secs": 30}"#;
        let req: ExecuteCommandRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.command, "echo hello");
        assert_eq!(req.timeout(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_error_response_serialization() {
        let err = ErrorResponse::new("TEST_ERROR", "Test message");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("TEST_ERROR"));
        assert!(json.contains("Test message"));
        assert!(!json.contains("details")); // skip_serializing_if
    }

    #[test]
    fn test_ws_message_execute() {
        let msg = WsMessage::Execute {
            command: "ls".to_string(),
            timeout_secs: Some(10),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("execute"));
        assert!(json.contains("ls"));
    }

    #[test]
    fn test_ws_message_output() {
        let msg = WsMessage::Output {
            data: "hello\n".to_string(),
            is_final: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("output"));
    }
}
