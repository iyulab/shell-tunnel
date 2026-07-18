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
