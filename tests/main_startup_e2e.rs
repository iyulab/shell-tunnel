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
fn run_with_timeout(args: &[&str], timeout: Duration) -> (bool, String, String) {
    let mut child = Command::new(BIN)
        .args(args)
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
            let success = child.wait().map(|s| s.success()).unwrap_or(false);
            (success, stdout, stderr)
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

    let (success, _stdout, stderr) = run_with_timeout(
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

    assert!(!success, "expected a non-zero exit; stderr: {stderr}");
    assert!(stderr.contains("--audit-log"), "{stderr}");
    assert!(stderr.contains("--fs-root"), "{stderr}");

    // The check runs before the audit sink is created (see `async_main`), so
    // a misconfigured server must never create the file it is about to
    // refuse — that would be litter left inside the very jail this refusal
    // exists to protect.
    assert!(
        !audit_log.exists(),
        "a refused startup must not have created the audit log file"
    );
}
