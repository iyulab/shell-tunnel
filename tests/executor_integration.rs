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
/// USAGE says so outright, after an upstream report and this repository's own
/// handover notes both stated the opposite — that a session runs
/// `powershell.exe` on Windows and `$SHELL` on Unix. It does not: every command
/// runs in a fresh shell exactly as a one-shot does. `pty::default_shell()` does
/// return those two, which is where the wrong sentence came from; nothing on
/// this path calls it.
///
/// A session no longer has a `shell` field to ask with — create carries no
/// fields at all since 0.20.0 — so this now pins the shell a session's execute
/// actually uses. Pinned as a test rather than left to the prose because a doc
/// sentence about behaviour is the thing this repository has repeatedly shipped
/// stale, and because the day sessions *do* get a persistent shell, this
/// failing is how the sentence gets rewritten instead of quietly becoming false
/// again.
#[tokio::test]
async fn a_session_runs_each_command_in_a_fresh_shell() {
    let store = Arc::new(SessionStore::new());
    let exec = CommandExecutor::new(store.clone());
    let id = store.create().expect("create session");
    store
        .update(&id, |s| {
            let _ = s
                .state
                .transition_to(shell_tunnel::session::SessionState::Idle);
        })
        .expect("session becomes idle");

    // The two platforms need different probes, for the reason that makes this
    // test worth having: `/bin/sh` is not one program. On Linux it is dash,
    // which rejects a bash builtin; on macOS it is bash in POSIX mode, which
    // accepts one. "A foreign builtin must fail" is therefore not portable —
    // asserted anyway, it passed on Linux and Windows and failed only on macOS,
    // where it claimed the `shell` field was being honoured when it was not.
    #[cfg(windows)]
    {
        // `Get-Location` is a PowerShell cmdlet and `cmd.exe` has no command by
        // that name, so the exit code separates the two outright here.
        let result = exec
            .execute_in_session(&id, &Command::new("Get-Location"))
            .await
            .expect("execute failed");
        assert_ne!(
            result.exit_code,
            Some(0),
            "the `shell` field is documented as ignored, but a PowerShell \
             cmdlet ran: {:?}",
            result.text_output
        );
    }
    #[cfg(unix)]
    {
        // `$0` is what a shell calls itself, so it names whichever one actually
        // ran regardless of which program `/bin/sh` happens to be — `/bin/sh`
        // under either, and `/bin/bash` on the day the field starts being
        // honoured.
        let result = exec
            .execute_in_session(&id, &Command::new("echo $0"))
            .await
            .expect("execute failed");
        let named = result.text_output.trim().to_string();
        assert!(
            !named.contains("bash"),
            "the `shell` field is documented as ignored, but the session ran \
             {named:?}"
        );
        // Without this the probe passes on empty output, which would say
        // nothing about which shell ran.
        assert!(
            named.ends_with("sh"),
            "expected the shell to name itself, so the check above means \
             something; got {named:?}"
        );
    }

    #[cfg(windows)]
    let (set, read) = ("set FOO=bar", "echo %FOO%");
    #[cfg(unix)]
    let (set, read) = ("FOO=bar", "echo $FOO");

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
