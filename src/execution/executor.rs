//! Command execution engine.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::command::Command;
use super::pipe::PipeDrain;
use super::result::{ExecutionResult, OutputChunk};
use crate::error::ShellTunnelError;
use crate::output::OutputSanitizer;
use crate::process::{detach_process_group, kill_tree, shell_command};
use crate::session::{BusySession, SessionStore};
use crate::Result;

/// Default execution timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest timeout a caller may ask for.
///
/// `docs/openapi.json` has declared `"maximum": 300` on `timeout_secs` since the
/// route existed, and `security::validation::ValidationConfig` names the same
/// figure — but nothing enforced either, so `timeout_secs: 999999999` was
/// accepted and honoured. That is the published reference being false, which is
/// the failure this repository has been bitten by repeatedly; the value here is
/// the one the reference already promises rather than a new one invented to
/// match the code.
///
/// It also bounds a resource that is not local to the request. One command holds
/// one blocking thread for its whole deadline, the runtime is built with tokio's
/// default blocking pool, and `AuditSink::record_async` and every filesystem
/// route *await* `spawn_blocking` — so a saturated pool stalls routes that have
/// nothing to do with the command holding it.
///
/// Clamped rather than refused, as [`MAX_OUTPUT_BYTES_CEILING`] is: the caller
/// asked for "as long as possible", and `timed_out` plus `duration_ms` report
/// what actually happened either way.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// The shortest timeout a caller may ask for.
///
/// The same declaration carries `"minimum": 1`, and it was equally unenforced:
/// `timeout_secs: 0` produced a deadline that had already passed, so *every*
/// command died on its first pass through the control loop having run nothing.
/// A caller who sends zero has asked for the smallest timeout there is, so that
/// is what they get — the alternative, treating zero as "no timeout", would read
/// an opt-out into a field whose whole purpose is the opposite.
pub const MIN_TIMEOUT: Duration = Duration::from_secs(1);

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

/// Poll interval for the non-blocking control loop.
const CONTROL_POLL: Duration = Duration::from_millis(5);

/// Hard backstop for collecting trailing output after the process has ended.
/// Bounds the tail so a lingering grandchild that inherited a pipe cannot hold
/// the return past this grace period.
const COLLECT_GRACE: Duration = Duration::from_millis(500);

/// Most bytes taken from one pipe in one pass of the control loop.
///
/// The loop must reach its `try_wait` and deadline checks on every pass, so a
/// command producing output faster than it is consumed — `cat` of a large file,
/// a build log — must not be able to keep the loop inside a drain. Large enough
/// that streaming megabytes costs a handful of passes rather than thousands.
const DRAIN_BUDGET: usize = 256 * 1024;

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
/// Nothing here ever blocks on a `read()`, which is what lets one loop own
/// everything:
/// - both pipes are drained by [`PipeDrain`], which reads only what is already
///   there. Draining both every pass is what keeps one pipe's buffer from
///   filling — and deadlocking the child — while the other is attended to.
/// - the same loop polls `try_wait()` and checks the deadline, so the timeout is
///   actually honored. Each drain pass is bounded by [`DRAIN_BUDGET`] so a
///   command producing output faster than it is read cannot postpone either.
/// - the loop can therefore *give up* on a pipe. That is the property the
///   previous design lacked: a dedicated reader thread per pipe had EOF as its
///   only exit, EOF needs every write end closed, and a grandchild that
///   inherited the pipes holds one open for as long as it runs. Those threads
///   were never joined, so each such command leaked one — measured, unbounded,
///   for the life of the process. Here the deadline below closes the read ends
///   and returns; a pipe nobody is blocked on cannot be leaked.
///
/// Note what this does *not* claim: a surviving grandchild is still surviving.
/// It keeps its inherited handles and keeps running, and on the success path
/// nothing kills it — the server has no grounds to decide that a background
/// process a command deliberately started should die. What is guaranteed is
/// narrower and is the part that belongs to this crate: **the server's own
/// resources are released either way.**
///
/// `on_chunk` is invoked for every output chunk as it arrives, which is what
/// lets the streaming (WebSocket) path forward output live; the non-streaming
/// callers pass a no-op.
fn run_command_streaming(
    command: &Command,
    mut on_chunk: impl FnMut(&[u8]),
) -> Result<ExecutionResult> {
    let start = Instant::now();
    let timeout_duration = command.effective_timeout();

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
    let mut out_pipe = child.stdout.take().map(PipeDrain::new);
    let mut err_pipe = child.stderr.take().map(PipeDrain::new);

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
    // pipes must keep being emptied, or a child writing more than the cap would
    // block on a full pipe buffer and never exit.
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

    // Both pipes, one bounded pass each. Returns how many bytes moved, which is
    // what tells the caller whether there is any point sleeping before the next
    // pass.
    macro_rules! drain_pass {
        () => {{
            let mut moved = 0;
            if let Some(pipe) = out_pipe.as_mut() {
                moved += pipe.drain(DRAIN_BUDGET, &mut |chunk: &[u8]| {
                    absorb(chunk, &mut raw_output, &mut total_bytes)
                });
            }
            if let Some(pipe) = err_pipe.as_mut() {
                moved += pipe.drain(DRAIN_BUDGET, &mut |chunk: &[u8]| {
                    absorb(chunk, &mut raw_output, &mut total_bytes)
                });
            }
            moved
        }};
    }

    /// Whether every pipe has reached its end and nothing more can arrive.
    macro_rules! pipes_ended {
        () => {
            out_pipe.as_ref().map_or(true, |p| p.finished())
                && err_pipe.as_ref().map_or(true, |p| p.finished())
        };
    }

    loop {
        let moved = drain_pass!();

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

        // Only idle when there was nothing to move. A command mid-flood is
        // served every pass instead of being metered at one pass per interval.
        if moved == 0 {
            std::thread::sleep(CONTROL_POLL);
        }
    }

    // Collect the tail. Both pipes end on their own once every write end has
    // closed — normally as the child exits, and on timeout once `kill_tree` has
    // taken the tree with it. The grace deadline is the backstop for the case
    // that has no other end: a grandchild inherited these pipes and is still
    // holding them open. Reaching it closes our read ends and returns.
    //
    // That last step is the fix. The reader threads this replaced could not be
    // told to stop — they were blocked in `read()` on a pipe held by a process
    // this crate does not own, and dropping their `JoinHandle`s (which is all
    // the old code could do) detached them rather than ending them. One thread
    // and one handle leaked per such command, for the life of the server.
    let collect_deadline = Instant::now() + COLLECT_GRACE;
    loop {
        let moved = drain_pass!();

        if pipes_ended!() {
            break;
        }
        if Instant::now() >= collect_deadline {
            if let Some(pipe) = out_pipe.as_mut() {
                pipe.release();
            }
            if let Some(pipe) = err_pipe.as_mut() {
                pipe.release();
            }
            break;
        }
        if moved == 0 {
            std::thread::sleep(CONTROL_POLL);
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
        // The same deadline the blocking core will enforce, from the same place
        // it gets it — see `Command::effective_timeout` for why that matters
        // here in particular.
        let budget = command.effective_timeout();

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
