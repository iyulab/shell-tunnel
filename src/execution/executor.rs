//! Command execution engine.

use std::io::Read;
use std::process::Stdio;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::command::Command;
use super::result::{ExecutionResult, OutputChunk};
use crate::error::ShellTunnelError;
use crate::output::OutputSanitizer;
use crate::process::{detach_process_group, kill_tree, shell_command};
use crate::session::{SessionState, SessionStore};
use crate::Result;

/// Default execution timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default buffer size for reading process output.
const READ_BUFFER_SIZE: usize = 4096;

/// Poll interval for the non-blocking control loop.
const CONTROL_POLL: Duration = Duration::from_millis(5);

/// Hard backstop for collecting trailing output after the process has ended.
/// Bounds the tail so a lingering grandchild that inherited a pipe cannot block
/// the return past this grace period.
const COLLECT_GRACE: Duration = Duration::from_millis(500);

/// Spawn a reader thread that pumps a pipe into `tx` until EOF.
fn spawn_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    tx: std_mpsc::Sender<Vec<u8>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF: the process closed this pipe
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break; // control side went away
                    }
                }
                Err(_) => break, // broken pipe / closed handle
            }
        }
    })
}

/// Run a non-interactive command with an *enforceable* timeout.
///
/// This is the blocking core shared by both the sync and async entry points.
///
/// Non-interactive commands are executed via a piped [`std::process::Command`]
/// rather than a PTY. This is deliberate: a PTY (Windows ConPTY in particular)
/// does not signal EOF or report child exit for a one-shot command until the
/// pseudoconsole itself is torn down, so there is no reliable way to tell when
/// the command finished — every command would run to the full timeout, and each
/// hung read leaked a `conhost.exe`. A piped child gives real EOF on pipe close
/// and a working `try_wait()`/`kill()`, which is exactly what a deterministic
/// "run command, capture output, get exit code, honor timeout" contract needs.
/// (Interactive/streaming sessions that genuinely need a TTY keep using the PTY
/// path in [`super::executor::CommandExecutor::execute_async`].)
///
/// The design keeps a blocking `read()` from ever stalling progress:
/// - stdout and stderr are each pumped by a dedicated reader thread (reading
///   only one while the other's pipe buffer fills would deadlock the child).
/// - the control loop here is fully non-blocking: it drains the channel, polls
///   `try_wait()`, and checks the deadline, so the timeout is actually honored.
/// - on timeout the child is killed; both pipes then close and the reader
///   threads reach EOF, so nothing leaks.
///
/// `on_chunk` is invoked for every output chunk as it arrives, which is what
/// lets the streaming (WebSocket) path forward output live; the non-streaming
/// callers pass a no-op.
fn run_command_streaming(
    command: &Command,
    mut on_chunk: impl FnMut(&[u8]),
) -> Result<ExecutionResult> {
    let start = Instant::now();
    let timeout_duration = command.timeout.unwrap_or(DEFAULT_TIMEOUT);

    let mut os_cmd = shell_command(&command.command_line);
    os_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = &command.working_dir {
        os_cmd.current_dir(dir);
    }
    for (key, value) in &command.env {
        os_cmd.env(key, value);
    }

    // Put the child in its own process group so that on timeout we can signal
    // the whole tree (a shell that spawned grandchildren) at once.
    detach_process_group(&mut os_cmd);

    let mut child = os_cmd.spawn().map_err(ShellTunnelError::Io)?;
    let child_pid = child.id();

    // stdout and stderr are merged into one output stream. True interleaving is
    // not guaranteed (nor is it with a TTY), but clients consume a single stream.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (tx, rx) = std_mpsc::channel::<Vec<u8>>();
    let out_handle = stdout.map(|s| spawn_pipe_reader(s, tx.clone()));
    let err_handle = stderr.map(|s| spawn_pipe_reader(s, tx));

    // Non-blocking control loop.
    let mut raw_output = Vec::new();
    let mut exit_status = None;
    let mut timed_out = false;
    loop {
        while let Ok(chunk) = rx.try_recv() {
            on_chunk(&chunk);
            raw_output.extend_from_slice(&chunk);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {}
            Err(e) => return Err(ShellTunnelError::Io(e)),
        }

        if start.elapsed() >= timeout_duration {
            timed_out = true;
            // Kill the whole tree: `cmd /c ...` / `sh -c ...` may have spawned
            // grandchildren that would otherwise keep the output pipes open and
            // stall our collection below (and keep running as orphans).
            kill_tree(child_pid);
            let _ = child.wait();
            break;
        }

        std::thread::sleep(CONTROL_POLL);
    }

    // Collect any remaining output. Once the process (and, on timeout, its whole
    // tree) is gone, both pipe handles close, the reader threads reach EOF and
    // drop their senders, and `recv_timeout` returns `Disconnected`. The grace
    // deadline is a hard backstop so a stray grandchild that inherited a pipe
    // can never block us — we return the timed-out result regardless.
    drop(out_handle);
    drop(err_handle);
    let collect_deadline = Instant::now() + COLLECT_GRACE;
    loop {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(chunk) => {
                on_chunk(&chunk);
                raw_output.extend_from_slice(&chunk);
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= collect_deadline {
                    break;
                }
            }
        }
    }

    let duration = start.elapsed();
    let text = OutputSanitizer::strip_ansi(&raw_output);

    if timed_out {
        return Ok(ExecutionResult::timeout(raw_output, text, duration));
    }

    let exit_code = exit_status.and_then(|s| s.code());
    let mut result = ExecutionResult::new(raw_output, text, duration);
    if let Some(code) = exit_code {
        result = result.with_exit_code(code);
    }
    Ok(result)
}

/// Run a non-interactive command, collecting all output (no streaming).
fn run_command(command: &Command) -> Result<ExecutionResult> {
    run_command_streaming(command, |_| {})
}

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
    /// This runs the command and waits for completion or timeout. Prefer
    /// [`CommandExecutor::execute`] from async contexts — this blocking variant
    /// must never be called directly on a tokio worker thread.
    pub fn execute_sync(&self, command: &Command) -> Result<ExecutionResult> {
        run_command(command)
    }

    /// Execute a command, keeping the async runtime responsive.
    ///
    /// The blocking work runs on a dedicated blocking thread via
    /// `spawn_blocking`, so the tokio worker pool (and therefore `/health` and
    /// the accept loop) is never starved by a slow or hung command. The
    /// underlying [`run_command`] enforces its own timeout, so this always
    /// completes without leaking runtime capacity.
    pub async fn execute(&self, command: &Command) -> Result<ExecutionResult> {
        let command = command.clone();
        tokio::task::spawn_blocking(move || run_command(&command))
            .await
            .map_err(|e| ShellTunnelError::Pty(format!("execution task failed: {e}")))?
    }

    /// Execute a command asynchronously, streaming output chunks as they arrive.
    ///
    /// Returns a receiver that yields [`OutputChunk`]s live, plus a join handle
    /// resolving to the final [`ExecutionResult`]. Backed by the same piped
    /// [`run_command_streaming`] core as the non-streaming paths, so it inherits
    /// real completion detection, enforceable timeout, and process-tree kill —
    /// none of which the previous PTY implementation could provide for
    /// non-interactive commands (see [`run_command_streaming`]).
    pub async fn execute_async(
        &self,
        command: &Command,
    ) -> Result<(
        mpsc::Receiver<OutputChunk>,
        tokio::task::JoinHandle<Result<ExecutionResult>>,
    )> {
        let (tx, rx) = mpsc::channel::<OutputChunk>(64);
        let command = command.clone();

        let handle = tokio::task::spawn_blocking(move || {
            run_command_streaming(&command, |chunk| {
                // Forward the chunk live; ignore if the receiver was dropped.
                let _ = tx.blocking_send(OutputChunk::combined(chunk.to_vec()));
            })
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

        // Execute command (off the async runtime workers)
        let result = self.execute(command).await;

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
