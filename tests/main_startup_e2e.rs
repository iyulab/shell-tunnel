//! End-to-end tests for startup-time refusals that only the real binary can
//! prove are actually wired up.
//!
//! `src/main.rs`'s `audit_log_is_inside_fs_root` is unit-tested directly as a
//! pure comparison, but nothing in that unit test proves `async_main` calls
//! it before serving — deleting the whole `if let` block around it would
//! leave every one of those unit tests green. Spawning the real process with
//! both flags for real is the only thing that closes that gap.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_shell-tunnel");

/// Run `BIN` with `args` and wait up to `timeout` for it to exit on its own.
///
/// A plain `.output()` (as `tests/tunnel_e2e.rs` uses for its own startup
/// refusals) blocks forever if the process being tested does not exit —
/// exactly the failure mode a regression here would cause: if the wiring
/// this test exists to prove were ever deleted, the server would start and
/// keep running instead of refusing, and a bare `.output()` would hang the
/// whole suite rather than failing. Confirmed directly while writing this
/// test: temporarily disabling the check under test made a bare `.output()`
/// call hang past a two-minute background-command timeout with the server
/// still bound to its port, which is the reason this wrapper exists rather
/// than the simpler call.
/// Returns the exit code (`None` if the process was killed by a signal)
/// alongside the captured output, rather than a bare success bool: the
/// refusals here are specified to exit 2, and "some non-zero code" would not
/// distinguish them from a panic or a different refusal entirely.
fn run_with_timeout(args: &[&str], timeout: Duration) -> (Option<i32>, String, String) {
    let mut command = Command::new(BIN);
    command.args(args);
    run_command_with_timeout(command, timeout)
}

/// As `run_with_timeout`, for a command that needs more than arguments set on
/// it — a working directory, in the one case that has one.
fn run_command_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> (Option<i32>, String, String) {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");

    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut stdout = String::new();
        let mut stderr = String::new();
        let _ = stdout_pipe.read_to_string(&mut stdout);
        let _ = stderr_pipe.read_to_string(&mut stderr);
        let _ = tx.send((stdout, stderr));
    });

    match rx.recv_timeout(timeout) {
        Ok((stdout, stderr)) => {
            let code = child.wait().expect("child is waitable").code();
            (code, stdout, stderr)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "process did not exit within {timeout:?} — a startup refusal that should \
                 have happened did not, and the server kept running instead"
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => unreachable!("reader thread always sends"),
    }
}

/// `--audit-log` resolving inside `--fs-root` must refuse to start, naming
/// both paths and why, and must not leave the log file it refused to use
/// sitting on disk inside the jail it was refused for.
#[test]
fn audit_log_inside_the_fs_root_refuses_to_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir(&root).expect("mkdir root");
    let audit_log = root.join("audit.jsonl");

    let (code, _stdout, stderr) = run_with_timeout(
        &[
            "--port",
            "39880",
            "--fs-root",
            root.to_str().expect("utf-8 path"),
            "--audit-log",
            audit_log.to_str().expect("utf-8 path"),
        ],
        Duration::from_secs(10),
    );

    assert_eq!(code, Some(2), "expected exit 2; stderr: {stderr}");
    assert!(stderr.contains("--audit-log"), "{stderr}");
    assert!(stderr.contains("--fs-root"), "{stderr}");

    // Matched on text unique to the containment branch, not merely on both
    // flag names: `audit_log_is_inside_fs_root`'s `Err` arm also refuses,
    // also exits 2, and also names both flags ("cannot be checked against").
    // Asserting only "refused, and both flags appear" would therefore pass
    // just as happily if this check started failing to *evaluate*
    // containment on some platform instead of finding it — which is the most
    // likely way this could diverge on a system other than the one it was
    // written on, and precisely the case worth being told about. This
    // pins the refusal to the stated reason.
    assert!(
        stderr.contains("resolves inside"),
        "the refusal must be the containment branch, not the cannot-be-checked fallback: {stderr}"
    );

    // The check runs before the audit sink is created (see `async_main`), so
    // a misconfigured server must never create the file it is about to
    // refuse — that would be litter left inside the very jail this refusal
    // exists to protect.
    assert!(
        !audit_log.exists(),
        "a refused startup must not have created the audit log file"
    );
}

/// A bare non-loopback bind is exposed on its own, and an exposed run derives
/// an audit log it was never asked for — so the derived path faces the same
/// containment check as a chosen one, and refuses startup when it lands inside
/// the jail.
///
/// This is the only test that proves the derivation is *wired*. `src/main.rs`'s
/// `effective_audit_log` and `posture_banner` are unit-tested as pure
/// functions, but re-pointing `async_main` back at the raw `--audit-log` value
/// would leave every one of those unit tests green — the same gap this file
/// exists to close for `audit_log_is_inside_fs_root`. It pins three facts at
/// once: the posture is computed from the bind address alone (no tunnel, no
/// relay, no `--audit-log` here), the derived path is what the containment
/// check sees, and its refusal is reachable.
#[test]
fn an_exposed_bind_deriving_an_audit_log_inside_the_fs_root_refuses_to_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir(&root).expect("mkdir root");

    // The working directory is the root itself, which is what puts the derived
    // default path (a bare file name) inside the jail.
    let mut child = Command::new(BIN);
    child.current_dir(&root).args([
        "--host",
        "0.0.0.0",
        "--port",
        "39881",
        "--fs-root",
        root.to_str().expect("utf-8 path"),
    ]);
    let (code, _stdout, stderr) = run_command_with_timeout(child, Duration::from_secs(10));

    assert_eq!(code, Some(2), "expected exit 2; stderr: {stderr}");
    // Matched on text unique to the derived branch: the chosen-path refusal
    // above also exits 2 and also names `--fs-root`, so asserting less would
    // pass just as happily if the derived path were reported as one the user
    // had picked — the mistake that branch exists to avoid.
    assert!(
        stderr.contains("A publicly reachable server writes an audit trail"),
        "the refusal must be the derived-path branch, not the chosen-path one: {stderr}"
    );

    // Nothing was created inside the jail on the way to refusing.
    assert!(
        !root.join("shell-tunnel-audit.jsonl").exists(),
        "a refused startup must not have created the audit log it refused"
    );
}
