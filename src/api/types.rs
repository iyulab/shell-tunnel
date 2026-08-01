//! API request and response types.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::session::{SessionId, SessionState};

/// Request to create a new session.
///
/// Strict about field names — see `ExecuteCommandRequest` for why every request
/// type here is.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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
///
/// A misspelled field is refused rather than ignored, and that is a safety
/// property rather than pedantry. Every optional field on this API either asks
/// for something *safer* (`timeout_secs`, `dry_run` on the delete route) or
/// says *where* to act (`working_dir`). Serde's default is to drop a field it
/// does not recognise, which leaves the less safe default in place and reports
/// success — a caller who wrote `timeoutSecs` got no timeout and a
/// `timed_out: false` that looked like the command finished within one, and a
/// caller who wrote `workingDir` had their command run somewhere else entirely.
/// The same slip on `?dryRun=true` deleted the file it was asked to preview.
///
/// The refusal names the offending field and lists the accepted ones, so the
/// caller can fix it from the response alone.
///
/// Note for callers coming from `spawn`-style APIs: `command` is the whole
/// command line, and there is no `args` array. Sending one used to start a
/// bare shell and report `success: true` without ever running the command.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Cap on the output this response carries, in bytes.
    ///
    /// Omitted means the server default. A value above the server's ceiling is
    /// clamped rather than refused: the caller asked for "as much as possible",
    /// and `total_bytes` reports what the command actually produced either way.
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
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
    /// Bytes the command produced, including any this response does not carry.
    ///
    /// Equal to the size of `output` unless `truncated` is set.
    pub total_bytes: u64,
    /// Whether `output` is a prefix of what the command produced.
    ///
    /// Always present, including when false: a caller must not have to infer
    /// completeness from the absence of a field.
    pub truncated: bool,
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
            total_bytes: result.total_bytes,
            truncated: result.truncated,
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

/// A message the server accepts from a WebSocket client.
///
/// Split from `WsServerMessage` because the two directions want opposite
/// strictness, and one shared type could only have one. Input is refused when
/// it carries a field this server does not know — `timeoutSecs` for
/// `timeout_secs` otherwise runs the command with no timeout at all and reports
/// `timed_out: false`, which reads as "finished within the limit". Output stays
/// permissive, so a client built against an older version of this crate keeps
/// working when a later server adds a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WsClientMessage {
    /// Run a command and stream its output back.
    Execute {
        command: String,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// Connection health. The server answers `Ping` with `Pong`.
    Ping,
    Pong,
}

/// A message the server sends to a WebSocket client.
///
/// Deliberately *not* `deny_unknown_fields`: this is the type a consumer
/// deserialises the server's output with, and a new field on a later server
/// must not make an older consumer reject the whole message. The strictness
/// that fixes silently-dropped input belongs on `WsClientMessage` only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsServerMessage {
    /// One chunk of a running command's output.
    Output {
        data: String,
        /// Whether this is the final chunk.
        #[serde(default)]
        is_final: bool,
    },
    /// Terminal result of an execution.
    ///
    /// Carries `total_bytes` but not `truncated`, unlike the REST response:
    /// every chunk reaches a streaming consumer as it arrives, so there is
    /// nothing here for a cap to discard. The figure is what a consumer needs
    /// to confirm it received the whole stream.
    Result {
        success: bool,
        exit_code: Option<i32>,
        duration_ms: u64,
        timed_out: bool,
        total_bytes: u64,
    },
    /// Error message.
    Error {
        code: String,
        message: String,
    },
    /// Connection health.
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
        let msg = WsClientMessage::Execute {
            command: "ls".to_string(),
            timeout_secs: Some(10),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("execute"));
        assert!(json.contains("ls"));
    }

    #[test]
    fn test_ws_message_output() {
        let msg = WsServerMessage::Output {
            data: "hello\n".to_string(),
            is_final: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("output"));
    }

    // --- Unknown fields are refused, not dropped. ---
    //
    // Each of these asserts the *pair*: the correct spelling parses and the
    // near-miss is refused. Asserting only the refusal would pass just as well
    // against a type that refuses everything.

    #[test]
    fn execute_request_refuses_an_unknown_field() {
        let good = r#"{"command":"cd","working_dir":"/tmp","timeout_secs":1}"#;
        let req: ExecuteCommandRequest = serde_json::from_str(good).unwrap();
        assert_eq!(req.working_dir.as_deref(), Some("/tmp"));
        assert_eq!(req.timeout_secs, Some(1));

        // The two that ran wrong and reported success before this was strict.
        for bad in [
            r#"{"command":"cd","workingDir":"/tmp"}"#,
            r#"{"command":"cd","timeoutSecs":1}"#,
            // No `args` array exists on this API; sending one used to start a
            // bare shell and answer `success: true`.
            r#"{"command":"cmd","args":["/c","echo","hi"]}"#,
        ] {
            let err = serde_json::from_str::<ExecuteCommandRequest>(bad).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown field"),
                "expected a refusal naming the field, got: {msg}"
            );
        }
    }

    #[test]
    fn create_session_request_refuses_an_unknown_field() {
        let req: CreateSessionRequest = serde_json::from_str(r#"{"working_dir":"/tmp"}"#).unwrap();
        assert_eq!(req.working_dir.as_deref(), Some("/tmp"));
        assert!(serde_json::from_str::<CreateSessionRequest>(r#"{"workingDir":"/tmp"}"#).is_err());
    }

    #[test]
    fn ws_client_message_refuses_an_unknown_field() {
        let good = r#"{"type":"execute","command":"ls","timeout_secs":5}"#;
        assert!(serde_json::from_str::<WsClientMessage>(good).is_ok());

        let typo = r#"{"type":"execute","command":"ls","timeoutSecs":5}"#;
        let err = serde_json::from_str::<WsClientMessage>(typo).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    /// The other half of the split: server output must stay permissive so a
    /// consumer built against this version keeps parsing a later server that
    /// added a field. Locking this down would trade one silent failure for
    /// another.
    #[test]
    fn ws_server_message_tolerates_an_unknown_field() {
        let from_a_later_server = r#"{"type":"result","success":true,"exit_code":0,
            "duration_ms":1,"timed_out":false,"total_bytes":0,"some_new_field":"x"}"#;
        assert!(serde_json::from_str::<WsServerMessage>(from_a_later_server).is_ok());
    }
}
