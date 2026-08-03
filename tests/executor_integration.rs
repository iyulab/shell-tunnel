//! Integration tests for non-interactive command execution.
//!
//! These exercise the real piped `std::process` execution path end-to-end.
//! Unlike the PTY-based tests (which are `#[ignore]` due to platform timing),
//! piped execution is deterministic, so these run on every platform in CI.

use std::sync::Arc;
use std::time::{Duration, Instant};

use shell_tunnel::{Command, CommandExecutor, SessionStore};

fn executor() -> CommandExecutor {
    CommandExecutor::new(Arc::new(SessionStore::new()))
}

#[tokio::test]
async fn echo_returns_output_and_zero_exit() {
    let exec = executor();
    let result = exec
        .execute(&Command::new("echo hello_world"))
        .await
        .expect("execute failed");

    assert!(
        result.text_output.contains("hello_world"),
        "output was: {:?}",
        result.text_output
    );
    assert_eq!(result.exit_code, Some(0));
    assert!(!result.timed_out);
}

#[tokio::test]
async fn nonzero_exit_code_is_propagated() {
    let exec = executor();
    let result = exec
        .execute(&Command::new("exit 7"))
        .await
        .expect("execute failed");

    assert_eq!(result.exit_code, Some(7));
    assert!(!result.timed_out);
}

#[tokio::test]
async fn stderr_is_captured_in_output() {
    let exec = executor();
    // `1>&2` redirects echo's output to stderr on both cmd.exe and sh.
    let result = exec
        .execute(&Command::new("echo err_msg 1>&2"))
        .await
        .expect("execute failed");

    assert!(
        result.text_output.contains("err_msg"),
        "output was: {:?}",
        result.text_output
    );
}

#[tokio::test]
async fn timeout_is_enforced_and_returns_promptly() {
    let exec = executor();

    // A command that would otherwise run ~20s.
    #[cfg(windows)]
    let cmd_line = "ping -n 20 127.0.0.1";
    #[cfg(unix)]
    let cmd_line = "sleep 20";

    let cmd = Command::new(cmd_line).timeout(Duration::from_secs(2));
    let start = Instant::now();
    let result = exec.execute(&cmd).await.expect("execute failed");
    let elapsed = start.elapsed();

    assert!(result.timed_out, "expected timed_out=true");
    // Must return near the deadline (timeout + collection grace), never the
    // full 20s — proves the timeout is actually enforced and the process tree
    // is killed rather than left to run.
    assert!(
        elapsed < Duration::from_secs(6),
        "timeout took too long: {:?}",
        elapsed
    );
}

#[tokio::test]
async fn streaming_execute_async_yields_chunks_and_final_result() {
    let exec = executor();
    let (mut rx, handle) = exec
        .execute_async(&Command::new("echo streamed_chunk"))
        .await
        .expect("execute_async failed");

    let mut collected = Vec::new();
    while let Some(chunk) = rx.recv().await {
        collected.extend_from_slice(&chunk.raw);
    }
    let result = handle.await.expect("join failed").expect("execute failed");

    let streamed = String::from_utf8_lossy(&collected);
    assert!(
        streamed.contains("streamed_chunk"),
        "streamed output was: {:?}",
        streamed
    );
    assert_eq!(result.exit_code, Some(0));
    assert!(!result.timed_out);
}

/// Emit `n` bytes to stdout, on either platform.
///
/// Written without a redirect or a pipe so the shell cannot change the exit
/// code out from under the assertion — the whole reason a caller should not
/// have to reach for `| head -c` to bound output.
///
/// The Windows form carries no double quotes on purpose: the command goes
/// through `cmd /c`, which strips them before PowerShell sees the argument, and
/// the quoted form then reaches `-Command` as a literal string that PowerShell
/// dutifully echoes — 32 bytes of source text instead of `n` bytes of output.
/// Verified by running both forms through `cmd /c`.
fn emit_bytes_command(n: usize) -> String {
    #[cfg(windows)]
    {
        format!("powershell -NoProfile -Command [Console]::Out.Write(('x'*{n}))")
    }
    #[cfg(unix)]
    {
        format!("printf 'x%.0s' $(seq 1 {n})")
    }
}

#[tokio::test]
async fn output_over_the_cap_is_truncated_and_says_so() {
    // Nothing bounded `output` before 0.14.0: the only effective limit was the
    // timeout, which bounds time rather than size. A caller had no way to tell
    // a complete answer from one the transport could not carry, because there
    // was no field to tell them with.
    let exec = executor();
    let produced = 64 * 1024;
    let cap = 4 * 1024;

    let cmd = Command::new(emit_bytes_command(produced)).max_output_bytes(cap as u64);
    let result = exec.execute(&cmd).await.expect("execute failed");

    assert_eq!(result.exit_code, Some(0));
    assert!(
        result.truncated,
        "producing {produced} bytes under a {cap}-byte cap must set truncated"
    );
    assert_eq!(
        result.raw_output.len(),
        cap,
        "the kept output must stop exactly at the cap"
    );
    // The figure a caller acts on: what the command produced, not what survived.
    assert_eq!(
        result.total_bytes, produced as u64,
        "total_bytes must report what was produced, not what was kept"
    );
}

#[tokio::test]
async fn output_under_the_cap_is_whole_and_not_flagged() {
    // The other half of the contract, and the one a mutation that always sets
    // `truncated` would break: a short answer must not claim to be cut.
    let exec = executor();
    let result = exec
        .execute(&Command::new("echo small_output"))
        .await
        .expect("execute failed");

    assert!(!result.truncated, "a short answer must not be flagged");
    assert_eq!(
        result.total_bytes,
        result.raw_output.len() as u64,
        "with nothing discarded the two figures must agree"
    );
    assert!(result.total_bytes > 0, "echo produced nothing");
}

#[tokio::test]
async fn a_streaming_consumer_receives_what_the_cap_would_discard() {
    // The cap governs the collected result, not the pipe. A WebSocket consumer
    // sees every chunk as it arrives, so capping the result must not silently
    // shorten the stream — and `total_bytes` is what lets that consumer confirm
    // it received everything.
    let exec = executor();
    let produced = 64 * 1024;
    let cap = 4 * 1024;

    let cmd = Command::new(emit_bytes_command(produced)).max_output_bytes(cap as u64);
    let (mut rx, handle) = exec
        .execute_async(&cmd)
        .await
        .expect("execute_async failed");

    let mut streamed = 0usize;
    while let Some(chunk) = rx.recv().await {
        streamed += chunk.raw.len();
    }
    let result = handle.await.expect("join failed").expect("execute failed");

    assert_eq!(
        streamed, produced,
        "the stream must carry everything even though the result is capped"
    );
    assert_eq!(result.total_bytes, produced as u64);
    assert!(result.truncated, "the collected result is still capped");
}

/// A session's execute uses the same shell as `/execute`, and keeps nothing
/// between calls.
///
/// USAGE §3.2 now says so outright, after an upstream report and this
/// repository's own handover notes both stated the opposite — that a session
/// runs `powershell.exe` on Windows and `$SHELL` on Unix. It does not: sessions
/// carry an id, a working directory and an environment, and every command runs
/// in a fresh shell exactly as a one-shot does. The `shell` field on create is
/// accepted and ignored.
///
/// Pinned as a test rather than left to the prose because a doc sentence about
/// behaviour is the thing this repository has repeatedly shipped stale, and
/// because the day sessions *do* get a persistent shell, this failing is how
/// the sentence gets rewritten instead of quietly becoming false again.
#[tokio::test]
async fn a_session_runs_each_command_in_a_fresh_shell() {
    use shell_tunnel::session::SessionConfig;

    let store = Arc::new(SessionStore::new());
    let exec = CommandExecutor::new(store.clone());
    let id = store
        .create(SessionConfig {
            // Named explicitly, so this fails the day it starts being honoured.
            shell: Some(
                if cfg!(windows) {
                    "powershell.exe"
                } else {
                    "/bin/bash"
                }
                .to_string(),
            ),
            ..Default::default()
        })
        .expect("create session");
    store
        .update(&id, |s| {
            let _ = s
                .state
                .transition_to(shell_tunnel::session::SessionState::Idle);
        })
        .expect("session becomes idle");

    // A command only the *other* shell understands. If the `shell` field were
    // honoured this would succeed, which is the point.
    #[cfg(windows)]
    let (foreign, set, read) = ("Get-Location", "set FOO=bar", "echo %FOO%");
    #[cfg(unix)]
    let (foreign, set, read) = ("shopt -s nullglob", "FOO=bar", "echo $FOO");

    let result = exec
        .execute_in_session(&id, &Command::new(foreign))
        .await
        .expect("execute failed");
    assert_ne!(
        result.exit_code,
        Some(0),
        "the `shell` field is documented as ignored; a shell-specific builtin \
         must not work: {:?}",
        result.text_output
    );

    exec.execute_in_session(&id, &Command::new(set))
        .await
        .expect("execute failed");
    let after = exec
        .execute_in_session(&id, &Command::new(read))
        .await
        .expect("execute failed");
    assert!(
        !after.text_output.contains("bar"),
        "a session is documented as keeping no state between calls: {:?}",
        after.text_output
    );
}
