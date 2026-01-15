//! Command execution engine.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::command::Command;
use super::result::{ExecutionResult, OutputChunk};
use crate::error::ShellTunnelError;
use crate::output::OutputSanitizer;
use crate::pty::NativePty;
use crate::session::{SessionState, SessionStore};
use crate::Result;

/// Default execution timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default buffer size for reading PTY output.
const READ_BUFFER_SIZE: usize = 4096;

/// Command executor for running commands in shell sessions.
pub struct CommandExecutor {
    store: Arc<SessionStore>,
}

impl CommandExecutor {
    /// Create a new command executor.
    pub fn new(store: Arc<SessionStore>) -> Self {
        Self { store }
    }

    /// Execute a command synchronously (blocking).
    ///
    /// This runs the command and waits for completion or timeout.
    pub fn execute_sync(&self, command: &Command) -> Result<ExecutionResult> {
        let start = Instant::now();
        let timeout_duration = command.timeout.unwrap_or(DEFAULT_TIMEOUT);

        // Create PTY and spawn shell
        let mut pty = NativePty::new();
        let mut shell = pty.spawn_shell(command.working_dir.as_deref())?;
        let mut writer = shell.take_writer()?;
        let mut reader = shell.take_reader()?;

        // Write command to PTY
        let cmd_with_newline = format!("{}\n", command.command_line);
        writer
            .write_all(cmd_with_newline.as_bytes())
            .map_err(ShellTunnelError::Io)?;
        writer.flush().map_err(ShellTunnelError::Io)?;

        // Collect output with timeout
        let mut raw_output = Vec::new();
        let mut buf = [0u8; READ_BUFFER_SIZE];

        loop {
            if start.elapsed() > timeout_duration {
                let text = OutputSanitizer::strip_ansi(&raw_output);
                return Ok(ExecutionResult::timeout(raw_output, text, start.elapsed()));
            }

            match reader.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    raw_output.extend_from_slice(&buf[..n]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => return Err(ShellTunnelError::Io(e)),
            }

            // Check if child has exited
            if let Ok(Some(_)) = shell.try_wait() {
                // Read any remaining output
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    raw_output.extend_from_slice(&buf[..n]);
                }
                break;
            }
        }

        let duration = start.elapsed();
        let exit_status = shell.wait().ok();
        let exit_code = exit_status.map(|s| {
            if s.success() {
                0i32
            } else {
                s.exit_code() as i32
            }
        });

        let text = OutputSanitizer::strip_ansi(&raw_output);
        let mut result = ExecutionResult::new(raw_output, text, duration);
        if let Some(code) = exit_code {
            result = result.with_exit_code(code);
        }

        Ok(result)
    }

    /// Execute a command asynchronously.
    ///
    /// Returns a receiver for streaming output chunks.
    pub async fn execute_async(
        &self,
        command: &Command,
    ) -> Result<(
        mpsc::Receiver<OutputChunk>,
        tokio::task::JoinHandle<Result<ExecutionResult>>,
    )> {
        let (tx, rx) = mpsc::channel::<OutputChunk>(64);
        let timeout_duration = command.timeout.unwrap_or(DEFAULT_TIMEOUT);
        let cmd_line = command.command_line.clone();
        let working_dir = command.working_dir.clone();

        let handle = tokio::task::spawn_blocking(move || {
            let start = Instant::now();

            // Create PTY and spawn shell
            let mut pty = NativePty::new();
            let mut shell = pty.spawn_shell(working_dir.as_deref())?;
            let mut writer = shell.take_writer()?;
            let mut reader = shell.take_reader()?;

            // Write command
            let cmd_with_newline = format!("{}\n", cmd_line);
            writer
                .write_all(cmd_with_newline.as_bytes())
                .map_err(ShellTunnelError::Io)?;
            writer.flush().map_err(ShellTunnelError::Io)?;

            // Collect output
            let mut raw_output = Vec::new();
            let mut buf = [0u8; READ_BUFFER_SIZE];

            loop {
                if start.elapsed() > timeout_duration {
                    let text = OutputSanitizer::strip_ansi(&raw_output);
                    return Ok(ExecutionResult::timeout(raw_output, text, start.elapsed()));
                }

                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk_data = buf[..n].to_vec();
                        raw_output.extend_from_slice(&chunk_data);

                        // Send chunk (ignore if receiver dropped)
                        let _ = tx.blocking_send(OutputChunk::combined(chunk_data));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => return Err(ShellTunnelError::Io(e)),
                }

                if let Ok(Some(_)) = shell.try_wait() {
                    while let Ok(n) = reader.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let chunk_data = buf[..n].to_vec();
                        raw_output.extend_from_slice(&chunk_data);
                        let _ = tx.blocking_send(OutputChunk::combined(chunk_data));
                    }
                    break;
                }
            }

            let duration = start.elapsed();
            let exit_status = shell.wait().ok();
            let exit_code = exit_status.map(|s| {
                if s.success() {
                    0i32
                } else {
                    s.exit_code() as i32
                }
            });

            let text = OutputSanitizer::strip_ansi(&raw_output);
            let mut result = ExecutionResult::new(raw_output, text, duration);
            if let Some(code) = exit_code {
                result = result.with_exit_code(code);
            }

            Ok(result)
        });

        Ok((rx, handle))
    }

    /// Execute a command in an existing session.
    pub async fn execute_in_session(
        &self,
        session_id: &crate::session::SessionId,
        command: &Command,
    ) -> Result<ExecutionResult> {
        // Verify session exists and is executable
        let session = self
            .store
            .get(session_id)?
            .ok_or_else(|| ShellTunnelError::SessionNotFound(session_id.to_string()))?;

        if !session.state.can_execute() {
            return Err(ShellTunnelError::NotExecutable(session.state));
        }

        // Mark session as active
        self.store.update(session_id, |s| {
            let _ = s.state.transition_to(SessionState::Active);
            s.touch();
        })?;

        // Execute command
        let result = self.execute_sync(command);

        // Mark session as idle
        self.store.update(session_id, |s| {
            let _ = s.state.transition_to(SessionState::Idle);
            s.touch();
        })?;

        result
    }
}

/// Simple one-shot command execution.
pub fn execute_simple(command_line: &str) -> Result<ExecutionResult> {
    let cmd = Command::new(command_line);
    let store = Arc::new(SessionStore::new());
    let executor = CommandExecutor::new(store);
    executor.execute_sync(&cmd)
}

/// Execute a command with timeout.
pub fn execute_with_timeout(command_line: &str, timeout: Duration) -> Result<ExecutionResult> {
    let cmd = Command::new(command_line).timeout(timeout);
    let store = Arc::new(SessionStore::new());
    let executor = CommandExecutor::new(store);
    executor.execute_sync(&cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_new() {
        let store = Arc::new(SessionStore::new());
        let _executor = CommandExecutor::new(store);
    }

    #[test]
    fn test_command_builder() {
        let cmd = Command::new("echo hello")
            .timeout(Duration::from_secs(5))
            .capture_output(true);

        assert_eq!(cmd.command_line, "echo hello");
        assert_eq!(cmd.timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    #[ignore] // PTY tests need special handling
    fn test_execute_simple_echo() {
        let result = execute_simple("echo test").unwrap();
        assert!(result.text_output.contains("test"));
    }

    #[test]
    #[ignore] // PTY tests need special handling
    fn test_execute_with_timeout() {
        let result = execute_with_timeout("echo fast", Duration::from_secs(5)).unwrap();
        assert!(!result.timed_out);
    }

    #[test]
    fn test_default_timeout() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    }
}
