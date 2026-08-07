//! Integration tests for non-interactive command execution.
//!
//! These exercise the real piped `std::process` execution path end-to-end.
//! Piped execution is deterministic, so these run on every platform in CI —
//! which is the whole path now that the PTY module and its timing-sensitive
//! tests are gone (0.20.0).

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

    // A command that would otherwise run for five minutes. The gap between that
    // and the bound below is the point: it has to be wide enough that machine
    // load cannot close it, because most of the wall clock measured here is not
    // the executor's at all (see below).
    #[cfg(windows)]
    let cmd_line = "ping -n 300 127.0.0.1";
    #[cfg(unix)]
    let cmd_line = "sleep 300";

    let cmd = Command::new(cmd_line).timeout(Duration::from_secs(2));
    let start = Instant::now();
    let result = exec.execute(&cmd).await.expect("execute failed");
    let elapsed = start.elapsed();

    // This is the enforcement claim. `timed_out` is set only where the deadline
    // branch runs, and that branch is reached only when `try_wait` had not yet
    // reported an exit — so a command that had simply finished cannot produce
    // it.
    assert!(result.timed_out, "expected timed_out=true");

    // And this is a different claim: having killed the tree, the call returned
    // rather than waiting the command out.
    //
    // Almost none of this elapsed time is the executor's. Instrumented once, on
    // the 0.20.x tree: killing a tree **6.12 s**, `child.wait()` 24 µs — the
    // Windows kill shelled out to `taskkill.exe`, and spawning a process is
    // exactly what a loaded machine is slow at. Under the full parallel suite
    // the same call exceeded 28 s. So a tight bound here did not measure the
    // code; it measured the host, and it measured it wrong — six seconds against
    // a twenty-second command failed at 9.6 s, 13.6 s and 25.9 s on a busy
    // workstation, *identically on the unmodified tree*.
    //
    // 0.21.0 took that term out: the kill is a job object now, measured at
    // 0.097 ms. The bound below stays wide anyway, because the host still varies
    // in the one place this test cannot avoid — spawning the command itself —
    // and a bound that has stopped tripping is not evidence that tightening it
    // would be safe.
    //
    // The margin is therefore bought in the command rather than in the
    // tolerance, which is what keeps the discriminating power: a version that
    // waited for the command out would take five minutes, not one.
    assert!(
        elapsed < Duration::from_secs(60),
        "returning waited for the command instead of killing it: {elapsed:?}"
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
        // Streamed rather than built as arguments. `printf 'x%.0s' $(seq 1 N)`
        // expands to N words on the command line, so at the 4 MiB the streaming
        // tests use it exceeds `ARG_MAX` and the shell produces *nothing* — the
        // command then "succeeds" with no output, and a test asserting on the
        // size of that output fails for a reason that has nothing to do with
        // what it is testing. Seen on macOS in CI, where the whole branch ran
        // on a Unix for the first time.
        format!("head -c {n} /dev/zero | tr '\\0' x")
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

/// A consumer that stops reading cannot park the executor.
///
/// The streaming channel is bounded, and the producer runs inside the control
/// loop that enforces the timeout and reaps the child. So a consumer holding its
/// receiver without draining it used to stop that loop from checking anything:
/// the join handle never resolved, the child outlived its own timeout, and a
/// blocking thread was parked for good. Both WebSocket handlers did exactly this
/// the moment their client hung up mid-command.
///
/// Dropping the receiver is the right thing for a consumer to do and both
/// handlers now do it. This pins the backstop underneath that — the guarantee
/// belongs to the executor, not to each consumer's discipline.
#[tokio::test]
async fn a_consumer_that_stops_receiving_cannot_park_the_executor() {
    let exec = executor();
    // Far more than the channel holds, so it is full long before the command ends.
    let cmd = Command::new(emit_bytes_command(4 * 1024 * 1024)).timeout(Duration::from_secs(2));

    let (_rx, handle) = exec
        .execute_async(&cmd)
        .await
        .expect("execute_async failed");

    // `_rx` is deliberately alive and never read for the whole wait.
    //
    // The bound is generous on purpose, and widening it costs nothing: the
    // failure this guards against is *unbounded* — a parked control loop never
    // resolves the handle at all — so any finite bound discriminates equally
    // well, while a tight one only adds false reds. At thirty seconds it was
    // producing them: measured at 13–32 s across five runs on a busy
    // workstation, and 13–32 s on the unmodified 0.20.0 tree as well, which is
    // how it was established as load rather than regression.
    let joined = tokio::time::timeout(Duration::from_secs(120), handle).await;

    assert!(
        joined.is_ok(),
        "the executor never finished: an unread receiver parked the control loop that enforces the timeout"
    );
    joined
        .unwrap()
        .expect("join failed")
        .expect("execute failed");
}

/// What the backstop costs, stated where it can be checked.
///
/// Freeing the executor from a consumer that has stopped reading is not free:
/// chunks produced after the command's deadline are dropped rather than waited
/// on. The trade is deliberate — the alternative is the stall above — but it
/// makes one of this crate's older sentences conditional, so the surviving
/// promise is pinned here instead of left to prose: `total_bytes` counts what
/// the command produced whatever the stream carried, which is how a consumer
/// tells a short stream from a quiet command.
///
/// Deliberately not asserting that bytes *were* lost: that depends on how fast
/// the command outruns the channel, and a test that has to win a race to pass
/// is a test that fails for the wrong reason. Measured once at 2 KB of 1 MB.
#[tokio::test]
async fn a_short_stream_still_reports_the_true_output_size() {
    let exec = executor();
    // Primed with an `echo` that the shell itself runs, so the command has
    // produced *something* the instant it starts. Without it this test depends
    // on the emitter's interpreter booting inside the two-second deadline —
    // PowerShell on a loaded machine does not, the command is killed having
    // written nothing, and the final assertion then fails over interpreter
    // startup rather than over what it is testing. Observed failing four times
    // out of four that way. The flood after it is what the rest of the test
    // needs; the priming byte is what makes the precondition hold.
    #[cfg(windows)]
    let line = format!("echo primed & {}", emit_bytes_command(4 * 1024 * 1024));
    #[cfg(unix)]
    let line = format!("echo primed; {}", emit_bytes_command(4 * 1024 * 1024));

    let cmd = Command::new(line).timeout(Duration::from_secs(2));

    let (mut rx, handle) = exec
        .execute_async(&cmd)
        .await
        .expect("execute_async failed");

    // Alive, holding the receiver, reading nothing until past the deadline.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut streamed = 0u64;
    while let Some(chunk) = rx.recv().await {
        streamed += chunk.raw.len() as u64;
    }
    let result = tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("the executor never finished")
        .expect("join failed")
        .expect("execute failed");

    assert!(
        result.total_bytes >= streamed,
        "total_bytes ({}) must count at least what the stream carried ({streamed})",
        result.total_bytes
    );
    assert!(
        result.total_bytes > 0,
        "the command produced output; total_bytes must say so even when the stream did not carry it"
    );
}

/// Execution must take its deadline from `Command::effective_timeout` and
/// nowhere else.
///
/// That method is where `timeout_secs` gets clamped into the range
/// `docs/openapi.json` publishes, so a path that reads `command.timeout`
/// directly is a path with no bounds — which is the state this replaced, where
/// `timeout_secs: 999999999` was honoured and `0` was taken as a deadline that
/// had already passed. It also has to be *one* place: the deadline was worked
/// out twice, once to kill the command and once to decide when a stalled
/// streaming consumer stops being waited on, and clamping only the first would
/// have killed a command at the ceiling while still feeding its stream for the
/// hours originally asked for.
///
/// Read off the source, and the limit is worth stating: this proves where the
/// deadline comes from, not what it is — `Command::effective_timeout`'s own unit
/// tests pin the arithmetic.
///
/// A behavioural test was written first and withdrawn, which is why this is here
/// instead. The cheap observable is the floor: with a zero deadline the command
/// is killed having run nothing, and with the floor applied it gets a second and
/// finishes. But "a shell starts and echoes inside one second" is a race, and on
/// a loaded machine it loses — that test passed alone and failed under the full
/// suite. The expensive observable is the ceiling, which takes five minutes to
/// reach. Neither is a test worth having, and a green that depends on winning a
/// race is worse than none.
#[test]
fn execution_takes_its_deadline_from_one_bounded_place() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/execution/executor.rs");
    let source = std::fs::read_to_string(&path).expect("source file is readable");

    assert!(
        !source.contains("command.timeout"),
        "src/execution/executor.rs reads the requested timeout directly; a deadline \
         taken from `Command::timeout` skips the bounds `docs/openapi.json` publishes. \
         Use `Command::effective_timeout()` — and keep it to one call site per \
         deadline, so the streaming backstop cannot outlive the command it backs"
    );
    assert_eq!(
        source.matches("effective_timeout()").count(),
        2,
        "exactly two deadlines are taken: the command's own, and the streaming \
         backstop's. A third means a new path; fewer means one of them went back \
         to computing its own"
    );

    // What the two assertions above do *not* cover, stated rather than implied.
    //
    // The first is name-dependent: it catches `command.timeout`, which is what
    // both deadline sites were called, and would miss the same bypass written
    // through a differently-named binding. This file already contains
    // `cmd.timeout` in its own tests, which is why the check cannot simply be
    // widened to `.timeout` — it would match those and fail for no reason.
    //
    // The second counts a method name in text, so a doc comment that mentions
    // `effective_timeout()` breaks it. That direction is loud rather than
    // silent, which is the acceptable one, and it is the same trade
    // `no_threads_are_spawned_to_read_a_pipe` makes.
    //
    // Both are structural guards over a rule the compiler cannot see. Neither
    // is a proof that no unbounded deadline can ever be constructed; what they
    // do is make the bypass that actually happened, and the split that would
    // undo the fix, fail loudly instead of compiling quietly.
}

/// A command that leaves a background process behind must still return on its
/// own schedule, not on that process's.
///
/// The grandchild inherits both output pipes and does not close them, because it
/// is still running. Nothing in the crate can make it close them, and nothing
/// should try — a background process a command deliberately started is not the
/// server's to kill on the success path. So the executor's own release is what
/// bounds this: the tail is collected for the grace period and then the read
/// ends are closed, whatever is still holding the write ends.
///
/// The shape this guards against is a "wait for EOF" collection loop, which is
/// what the reader threads underneath the previous implementation did — with no
/// way to be told to stop, they blocked on those pipes for as long as the
/// grandchild ran, one leaked thread and one leaked handle per command, never
/// reclaimed. Measured on Windows before the change: 30 such commands took the
/// server from 21 threads to 52, and from 81 handles to 122, with no path back.
/// The pipes are drained without blocking now (`src/execution/pipe.rs`), so the
/// loop can simply give up on them; `no_threads_are_spawned_to_read_a_pipe`
/// below pins the absence of the threads themselves.
///
/// Deliberately quiet on both pipes — a grandchild that *writes* would end its
/// reader by other means, and the quiet one is both the harder case and the
/// common one, since a daemon usually redirects its own output.
#[tokio::test]
async fn a_command_that_leaves_a_background_process_still_returns_promptly() {
    let exec = executor();

    #[cfg(windows)]
    let cmd_line = "start /b ping -n 10 127.0.0.1 >nul 2>nul";
    #[cfg(unix)]
    let cmd_line = "sleep 10 >/dev/null 2>&1 &";

    let start = Instant::now();
    let result = exec
        .execute(&Command::new(cmd_line).timeout(Duration::from_secs(30)))
        .await
        .expect("execute failed");
    let elapsed = start.elapsed();

    assert!(
        !result.timed_out,
        "the command itself finished at once; only the process it left behind is still running"
    );
    assert_eq!(
        result.exit_code,
        Some(0),
        "the shell reported the background start as successful: {:?}",
        result.text_output
    );
    // Well under the grandchild's ten seconds. The bound is the collection
    // grace, not the lifetime of whatever the command left running.
    assert!(
        elapsed < Duration::from_secs(5),
        "returning waited on the surviving process rather than on the grace period: {elapsed:?}"
    );
}

/// Reading a child's pipes must not put a thread on them.
///
/// Read off the source rather than observed at runtime, and the limitation is
/// worth stating plainly: this proves no thread is spawned, not that no resource
/// leaks. It is here because the failure it guards is invisible to every
/// behavioural test in this file — a blocking reader thread produces identical
/// output, identical exit codes and identical timing, and differs only in that
/// it never ends when the pipe outlives the child. That is precisely how the
/// leak above shipped and stayed. Same shape as
/// `audit_e2e::the_async_handlers_record_without_blocking_the_runtime` and
/// `tests/ci_feature_gates.rs`: a rule the compiler cannot see, held in the one
/// place that can see it.
///
/// If a future change genuinely needs a thread here, it needs an answer for how
/// that thread ends when a process this crate does not own is holding the pipe
/// open — and this assertion is where that answer gets written down.
#[test]
fn no_threads_are_spawned_to_read_a_pipe() {
    for file in ["src/execution/executor.rs", "src/execution/pipe.rs"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        let source = std::fs::read_to_string(&path).expect("source file is readable");
        assert!(
            !source.contains("thread::spawn"),
            "{file} spawns a thread to attend a child's pipes; a thread blocked in \
             `read()` ends only at EOF, and EOF needs every inherited write end \
             closed — which a surviving grandchild will not do. Drain the pipe \
             instead (`PipeDrain`, `src/execution/pipe.rs`), so giving up stays possible"
        );
    }
}

/// A session's execute uses the same shell as `/execute`, and keeps nothing
/// between calls.
///
/// USAGE says so outright, after an upstream report and this repository's own
/// handover notes both stated the opposite — that a session runs
/// `powershell.exe` on Windows and `$SHELL` on Unix. It does not: every command
/// runs in a fresh shell exactly as a one-shot does. Those two names came from
/// a `default_shell()` helper in the PTY module, which nothing on this path
/// ever called; the module was removed in 0.20.0 and the names with it.
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

/// Whether `--kill-orphans` actually reaches the thing that kills.
///
/// The flag is parsed in `cli.rs`, stored on `AppState`, rebuilt into a
/// `CommandExecutor`, and read three call frames further down in
/// `run_command_streaming`. Every one of those links can be written and none of
/// them observed — "the primitive exists but nothing calls it" is this
/// repository's most repeated defect, and a flag that parses but does nothing
/// looks exactly like a working one. So this asserts the *effect*, on a real
/// process, from the public API.
///
/// Both directions are asserted, because the default is a promise: a command
/// that deliberately starts a daemon must still get to keep it.
mod kill_orphans {
    use super::*;

    /// Prints the pid of a process it leaves running, then exits.
    ///
    /// 25 s rather than something longer so the surviving half cleans up after
    /// itself even if its explicit teardown fails.
    fn spawn_background_and_print_pid() -> &'static str {
        #[cfg(windows)]
        {
            concat!(
                r#"powershell -NoProfile -Command "#,
                r#""(Start-Process powershell -ArgumentList '-NoProfile','-Command',"#,
                r#"'Start-Sleep -Seconds 25' -PassThru).Id""#
            )
        }
        #[cfg(unix)]
        {
            "sleep 25 & echo $!"
        }
    }

    fn alive(pid: u32) -> bool {
        #[cfg(windows)]
        {
            let out = std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}"), "/NH"])
                .output()
                .expect("tasklist");
            String::from_utf8_lossy(&out.stdout).contains(&pid.to_string())
        }
        #[cfg(unix)]
        {
            std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    }

    fn terminate(pid: u32) {
        #[cfg(windows)]
        let mut c = std::process::Command::new("taskkill");
        #[cfg(windows)]
        c.args(["/F", "/PID", &pid.to_string()]);
        #[cfg(unix)]
        let mut c = std::process::Command::new("kill");
        #[cfg(unix)]
        c.args(["-9", &pid.to_string()]);
        let _ = c
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    fn background_pid(kill_orphans: bool) -> u32 {
        let exec = CommandExecutor::new(Arc::new(SessionStore::new())).kill_orphans(kill_orphans);
        let result = exec
            .execute_sync(&Command::new(spawn_background_and_print_pid()))
            .expect("command should run");
        result
            .text_output
            .split_whitespace()
            .find_map(|w| w.trim().parse::<u32>().ok())
            .unwrap_or_else(|| panic!("no pid in output: {:?}", result.text_output))
    }

    #[test]
    fn on_the_background_process_is_gone_when_the_command_returns() {
        let pid = background_pid(true);

        // Polled rather than slept on: the kill is a system call, so this
        // normally succeeds on the first pass. The bound is only here so a
        // failure reports rather than hangs, and it is far under the 25 s the
        // process would otherwise run for — a pass cannot be the sleeper simply
        // having finished.
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }

        let still_there = alive(pid);
        if still_there {
            terminate(pid);
        }
        assert!(
            !still_there,
            "--kill-orphans is on, so pid {pid} should not have outlived the command"
        );
    }

    #[test]
    fn off_the_background_process_keeps_running() {
        let pid = background_pid(false);
        let survived = alive(pid);
        terminate(pid);
        assert!(
            survived,
            "with --kill-orphans off, pid {pid} must survive: a daemon started on purpose is meant to outlive the request"
        );
    }
}
