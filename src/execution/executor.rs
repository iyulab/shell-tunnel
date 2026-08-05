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
use crate::session::{BusySession, SessionStore};
use crate::Result;

/// Default execution timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How much output a command's result keeps, unless the caller asks for less.
///
/// Until 0.14.0 nothing bounded this: the only effective limit was the timeout,
/// which bounds time rather than size, so a single `cat` of a large file was
/// held whole in memory and then serialised into one JSON response. Behind a
/// relay that response could not even be delivered.
///
/// 1 MiB sits well under every ceiling downstream of it, so a capped result
/// behaves the same locally and across a relay — a limit that only bites on one
/// path is worse than none, because it is discovered in production.
///
/// The cap governs what a *result* carries; a streaming consumer is not subject
/// to it. That is not the same as receiving everything unconditionally — a
/// consumer that stops draining its receiver can miss chunks produced after the
/// command's deadline, because [`forward_chunk`] stops waiting on it there
/// rather than letting a stalled reader hold the command past its timeout.
/// `total_bytes` counts what the command produced either way.
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

/// The largest cap a caller may ask for.
///
/// A request may lower [`DEFAULT_MAX_OUTPUT_BYTES`] or raise it to here, but
/// not past it: the point of the cap is that a response stays deliverable, and
/// a caller opting out entirely would restore exactly the failure it exists to
/// prevent.
pub const MAX_OUTPUT_BYTES_CEILING: u64 = 8 * 1024 * 1024;

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
/// (This is every path, streaming included: nothing here allocates a terminal.
/// The crate's PTY module was removed in 0.20.0 having gone uncalled since this
/// decision was made. A feature that genuinely needs a TTY brings one back —
/// the reasons above are what it would have to answer for.)
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
    let cap = command
        .max_output_bytes
        .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES)
        .min(MAX_OUTPUT_BYTES_CEILING);
    let mut raw_output = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut exit_status = None;
    let mut timed_out = false;

    // Every chunk goes to `on_chunk` and counts toward `total_bytes`; only what
    // fits under the cap is kept. Streaming consumers therefore still see the
    // whole stream — the cap governs the collected result, not the pipe — and
    // `total_bytes` stays the true figure rather than the kept one.
    //
    // Draining continues after the cap is reached rather than stopping: the
    // reader threads must keep emptying the pipes, or a child writing more than
    // the cap would block on a full pipe buffer and never exit.
    let mut absorb = |chunk: &[u8], raw_output: &mut Vec<u8>, total: &mut u64| {
        on_chunk(chunk);
        *total += chunk.len() as u64;
        let kept = raw_output.len() as u64;
        if kept < cap {
            let room = (cap - kept) as usize;
            let take = room.min(chunk.len());
            raw_output.extend_from_slice(&chunk[..take]);
        }
    };

    loop {
        while let Ok(chunk) = rx.try_recv() {
            absorb(&chunk, &mut raw_output, &mut total_bytes);
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
            Ok(chunk) => absorb(&chunk, &mut raw_output, &mut total_bytes),
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
    let truncated = total_bytes > raw_output.len() as u64;

    if timed_out {
        return Ok(ExecutionResult::timeout(raw_output, text, duration)
            .with_output_extent(total_bytes, truncated));
    }

    let exit_code = exit_status.and_then(|s| s.code());
    let mut result =
        ExecutionResult::new(raw_output, text, duration).with_output_extent(total_bytes, truncated);
    if let Some(code) = exit_code {
        result = result.with_exit_code(code);
    }
    Ok(result)
}

/// Run a non-interactive command, collecting all output (no streaming).
fn run_command(command: &Command) -> Result<ExecutionResult> {
    run_command_streaming(command, |_| {})
}

/// How long to nap between attempts at a full channel.
const FORWARD_RETRY: Duration = Duration::from_millis(2);

/// Hand one chunk to a streaming consumer, waiting while the channel is full —
/// but never past `stop_waiting_at`.
///
/// This is called from inside [`run_command_streaming`]'s control loop, the same
/// loop that checks the deadline and reaps the child. Anything that parks here
/// parks those checks too, which is why an unbounded `blocking_send` was wrong:
/// a consumer that stopped receiving without dropping its receiver left the
/// child running past its timeout and a blocking thread parked for good.
///
/// Backpressure is preserved for a consumer that is merely slow — it only stops
/// applying once the command has outlived the window in which it could still
/// have been delivered, and at that point the control loop is about to kill the
/// tree anyway. Chunks dropped here are still counted in `total_bytes` and still
/// collected into the result under its cap; only the live stream loses them, and
/// only for a consumer that is no longer reading it.
fn forward_chunk(tx: &mpsc::Sender<OutputChunk>, chunk: &[u8], stop_waiting_at: Instant) {
    let mut pending = OutputChunk::combined(chunk.to_vec());
    loop {
        match tx.try_send(pending) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Closed(_)) => return,
            Err(mpsc::error::TrySendError::Full(returned)) => {
                if Instant::now() >= stop_waiting_at {
                    return;
                }
                pending = returned;
                std::thread::sleep(FORWARD_RETRY);
            }
        }
    }
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
    ///
    /// **A consumer that stops receiving should drop the receiver.** Holding it
    /// while awaiting the join handle is a deadlock in waiting: the channel is
    /// bounded, and the producer runs inside the control loop that enforces the
    /// timeout, so a full channel stops that loop from checking anything. Both
    /// WebSocket handlers used to do exactly this when their client hung up, and
    /// the command then outlived its own timeout — verified by watching a child
    /// with a five-second timeout run to completion.
    ///
    /// Dropping the receiver frees the producer immediately. As a backstop for
    /// the consumer that forgets, forwarding gives up once the command's own
    /// deadline has passed — timeout enforcement is a guarantee of this crate,
    /// not something each consumer re-earns.
    pub async fn execute_async(
        &self,
        command: &Command,
    ) -> Result<(
        mpsc::Receiver<OutputChunk>,
        tokio::task::JoinHandle<Result<ExecutionResult>>,
    )> {
        let (tx, rx) = mpsc::channel::<OutputChunk>(64);
        let command = command.clone();
        let budget = command.timeout.unwrap_or(DEFAULT_TIMEOUT);

        let handle = tokio::task::spawn_blocking(move || {
            // Past this instant the command is due to be killed anyway, so no
            // chunk is worth waiting on: see `forward_chunk`.
            let stop_waiting_at = Instant::now() + budget;
            run_command_streaming(&command, |chunk| {
                forward_chunk(&tx, chunk, stop_waiting_at);
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

        // Busy for as long as the guard lives. Held rather than written as a
        // pair of transitions because the await below may never resume: a
        // caller that hangs up mid-command has axum drop this future, and a
        // hand-written "back to idle" line after the await would never run.
        let _busy = BusySession::begin(&self.store, session_id)?;

        // Execute command (off the async runtime workers)
        self.execute(command).await
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

    /// Ignored until 0.20.0 as "PTY tests need special handling" — a label left
    /// over from before execution moved to pipes. Nothing on this path has
    /// allocated a terminal since, and the PTY module it named is gone; both of
    /// these run in a fresh `cmd /c` / `sh -c` like every other execute. Ran
    /// green under `--ignored` before the gate came off.
    #[test]
    fn test_execute_simple_echo() {
        let result = execute_simple("echo test").unwrap();
        assert!(result.text_output.contains("test"));
    }

    #[test]
    fn test_execute_with_timeout() {
        let result = execute_with_timeout("echo fast", Duration::from_secs(5)).unwrap();
        assert!(!result.timed_out);
    }

    #[test]
    fn test_default_timeout() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    }
}
