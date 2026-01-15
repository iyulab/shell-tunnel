//! Execution result types.

use std::time::Duration;

/// Result of command execution.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Raw output from the terminal.
    pub raw_output: Vec<u8>,
    /// Sanitized text output (ANSI codes stripped).
    pub text_output: String,
    /// Exit code (if command completed).
    pub exit_code: Option<i32>,
    /// Execution duration.
    pub duration: Duration,
    /// Whether execution timed out.
    pub timed_out: bool,
}

impl ExecutionResult {
    /// Create a new execution result.
    pub fn new(raw_output: Vec<u8>, text_output: String, duration: Duration) -> Self {
        Self {
            raw_output,
            text_output,
            exit_code: None,
            duration,
            timed_out: false,
        }
    }

    /// Create a result indicating timeout.
    pub fn timeout(raw_output: Vec<u8>, text_output: String, duration: Duration) -> Self {
        Self {
            raw_output,
            text_output,
            exit_code: None,
            duration,
            timed_out: true,
        }
    }

    /// Set the exit code.
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Check if command succeeded (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// Check if command failed (non-zero exit code or timeout).
    pub fn failed(&self) -> bool {
        self.timed_out || matches!(self.exit_code, Some(c) if c != 0)
    }

    /// Get output as string, trimmed.
    pub fn output_trimmed(&self) -> &str {
        self.text_output.trim()
    }

    /// Get output lines.
    pub fn output_lines(&self) -> impl Iterator<Item = &str> {
        self.text_output.lines()
    }
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self {
            raw_output: Vec::new(),
            text_output: String::new(),
            exit_code: None,
            duration: Duration::ZERO,
            timed_out: false,
        }
    }
}

/// Streaming output chunk from execution.
#[derive(Debug, Clone)]
pub struct OutputChunk {
    /// Raw bytes.
    pub raw: Vec<u8>,
    /// Decoded text (best effort).
    pub text: String,
    /// Stream source.
    pub source: OutputSource,
}

/// Source of output data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputSource {
    /// Standard output.
    Stdout,
    /// Standard error (if separate).
    Stderr,
    /// Combined output.
    Combined,
}

impl OutputChunk {
    /// Create a new output chunk.
    pub fn new(raw: Vec<u8>, source: OutputSource) -> Self {
        let text = String::from_utf8_lossy(&raw).into_owned();
        Self { raw, text, source }
    }

    /// Create a stdout chunk.
    pub fn stdout(raw: Vec<u8>) -> Self {
        Self::new(raw, OutputSource::Stdout)
    }

    /// Create a combined output chunk.
    pub fn combined(raw: Vec<u8>) -> Self {
        Self::new(raw, OutputSource::Combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_new() {
        let result = ExecutionResult::new(
            b"hello\n".to_vec(),
            "hello\n".to_string(),
            Duration::from_millis(100),
        );

        assert_eq!(result.raw_output, b"hello\n");
        assert_eq!(result.text_output, "hello\n");
        assert_eq!(result.duration, Duration::from_millis(100));
        assert!(!result.timed_out);
        assert!(result.exit_code.is_none());
    }

    #[test]
    fn test_execution_result_success() {
        let result = ExecutionResult::default().with_exit_code(0);
        assert!(result.success());
        assert!(!result.failed());
    }

    #[test]
    fn test_execution_result_failed() {
        let result = ExecutionResult::default().with_exit_code(1);
        assert!(!result.success());
        assert!(result.failed());
    }

    #[test]
    fn test_execution_result_timeout() {
        let result = ExecutionResult::timeout(vec![], String::new(), Duration::from_secs(30));
        assert!(result.timed_out);
        assert!(result.failed());
    }

    #[test]
    fn test_output_trimmed() {
        let result = ExecutionResult::new(vec![], "  hello world  \n".to_string(), Duration::ZERO);
        assert_eq!(result.output_trimmed(), "hello world");
    }

    #[test]
    fn test_output_lines() {
        let result =
            ExecutionResult::new(vec![], "line1\nline2\nline3".to_string(), Duration::ZERO);
        let lines: Vec<_> = result.output_lines().collect();
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
    }

    #[test]
    fn test_output_chunk_stdout() {
        let chunk = OutputChunk::stdout(b"test output".to_vec());
        assert_eq!(chunk.source, OutputSource::Stdout);
        assert_eq!(chunk.text, "test output");
    }

    #[test]
    fn test_output_chunk_combined() {
        let chunk = OutputChunk::combined(b"mixed output".to_vec());
        assert_eq!(chunk.source, OutputSource::Combined);
    }
}
