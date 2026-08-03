//! End-to-end tests for startup-time behaviour that only the real binary can
//! prove is actually wired up — the refusals below, and the posture banner,
//! whose text depends on *when* in `async_main` its inputs are read.
//!
//! `src/main.rs`'s `audit_log_is_inside_fs_root` is unit-tested directly as a
//! pure comparison, but nothing in that unit test proves `async_main` calls
//! it before serving — deleting the whole `if let` block around it would
//! leave every one of those unit tests green. Spawning the real process with
//! both flags for real is the only thing that closes that gap.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
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

/// Kill a server that is expected to keep running, on the way out of a test.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Read the server's stdout until a line matches `predicate`, or time runs out.
///
/// The refusals above exit on their own and are read with `run_with_timeout`;
/// a banner assertion is the opposite shape — the process is *supposed* to
/// stay up, so its output has to be streamed while it runs.
fn wait_for_line(
    server: &mut Killed,
    timeout: Duration,
    predicate: impl Fn(&str) -> bool,
) -> String {
    let stdout = server.0.stdout.take().expect("stdout is piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = std::time::Instant::now() + timeout;
    let mut seen = Vec::new();
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if predicate(&line) {
                    return line;
                }
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    panic!(
        "expected line not seen within {timeout:?}; got:\n{}",
        seen.join("\n")
    );
}

/// The banner must name the scope `harden_for_public_exposure` actually chose,
/// which means reading it *after* that call rather than before.
///
/// Nothing else pins the ordering. Move the read above the hardening and all
/// fifteen unit tests in `src/main.rs` stay green — `token_scope` and
/// `posture_banner` are pure and would be handed the pre-promotion state,
/// which they would describe perfectly accurately as the wildcard. Only the
/// real binary can tell the two apart, and the difference is the whole defect
/// this banner was already fixed for once: a wildcard claim for a token that
/// is in fact scoped to `operator`.
#[test]
fn the_exposed_banner_names_the_scope_the_hardening_chose() {
    // cwd is a tempdir because an exposed run derives an audit trail relative
    // to it; the crate root would collect one per test run.
    let dir = tempfile::tempdir().expect("tempdir");
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args(["--host", "0.0.0.0", "--port", "39882"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);

    let line = wait_for_line(&mut server, Duration::from_secs(30), |l| {
        l.starts_with("Reachable:")
    });

    assert!(
        line.contains("operator"),
        "the promoted preset must be what the banner names: {line}"
    );
    assert!(
        !line.contains("wildcard `*`"),
        "reading the scope before hardening would report the wildcard here: {line}"
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

/// The TLS flags belong to the relay, and `--help` must say so — because for a
/// while it said the opposite.
///
/// The header read `TLS OPTIONS (serve HTTPS directly, no reverse proxy
/// needed)`, in a help text where the relay's own section *is* scoped
/// (`RELAY OPTIONS (with `relay`)`). A scope marker on one section and not the
/// other reads as "the unmarked one is common to both modes", which is exactly
/// backwards: a gateway refuses these flags at startup, and its refusal tells
/// the operator to put a reverse proxy in front — the thing the header said was
/// not needed. Both halves of that parenthetical were false.
///
/// The two assertions cover different regressions. Behaviour: each way of
/// asking for TLS is refused, and refused *for being a relay flag* rather than
/// for some incidental parse error. Text: the help scopes the section and does
/// not carry the old claim back. Neither alone would have caught the defect —
/// the behaviour was always correct, and it was the text that lied.
#[test]
fn the_tls_flags_are_refused_by_a_gateway_and_scoped_to_the_relay_in_help() {
    for (label, args) in [
        ("--tls-self-signed", vec!["--tls-self-signed"]),
        (
            "--tls-cert/--tls-key",
            vec!["--tls-cert", "cert.pem", "--tls-key", "key.pem"],
        ),
    ] {
        let mut with_bind = vec!["--host", "127.0.0.1", "--port", "39885"];
        with_bind.extend(args);
        let (code, _stdout, stderr) = run_with_timeout(&with_bind, Duration::from_secs(10));

        assert_eq!(
            code,
            Some(1),
            "{label} must refuse startup; stderr: {stderr}"
        );
        assert!(
            stderr.contains("shell-tunnel relay"),
            "{label} must be refused as a relay flag, not for an unrelated \
             reason: {stderr}"
        );
        // The refusal names what was passed. `--tls-self-signed` fills in
        // `--tls-cert`/`--tls-key` during parsing, so reporting the fields
        // instead sent an operator looking for two flags they never wrote.
        assert!(
            stderr.contains(label),
            "the refusal must name the flag that was given: {stderr}"
        );
    }

    let (code, help, _stderr) = run_with_timeout(&["--help"], Duration::from_secs(10));
    assert_eq!(code, Some(0));
    let tls_header = help
        .lines()
        .find(|l| l.starts_with("TLS OPTIONS"))
        .expect("the help has a TLS section");
    assert!(
        tls_header.contains("relay"),
        "the TLS section must name the mode that accepts it: {tls_header}"
    );
    assert!(
        !help.contains("no reverse proxy needed"),
        "the help claimed a gateway needs no reverse proxy while its own \
         refusal tells the operator to add one"
    );
}

/// A flag accepted in either mode must not be filed under a section header that
/// names one.
///
/// `--check-update`, `--update`, `--no-update-check`, `-h` and `-V` were listed
/// under `RELAY OPTIONS (with `relay`)`, having simply been left at the bottom
/// of the last section. None of them has anything to do with the relay: one
/// flat parser reads every flag, and the update trio exits before a server of
/// either kind starts. The help contradicted itself two screens later, where
/// EXAMPLES shows `shell-tunnel --check-update` with no subcommand.
///
/// This is the TLS header's defect one section further down, and scoping that
/// header is what sharpened it: once every *named* section carries a mode, the
/// flags trailing the last one inherit a scope nobody wrote. So the guard is
/// written as a rule over sections rather than an assertion about these five
/// flags — a sixth added to the end of the file must not quietly acquire the
/// relay's scope either.
#[test]
fn a_flag_accepted_in_either_mode_is_not_filed_under_a_mode_scoped_section() {
    let (code, help, _stderr) = run_with_timeout(&["--help"], Duration::from_secs(10));
    assert_eq!(code, Some(0));

    // The update trio is compiled in only with the `self-update` feature, so it
    // is checked where present rather than required to be present: a build
    // without it must still not misfile `-h`/`-V`.
    const MODE_INDEPENDENT: &[&str] = &[
        "-h, --help",
        "-V, --version",
        "--check-update",
        "--update ",
        "--no-update-check",
    ];

    // Section headers are the only unindented lines ending in a colon.
    let mut header = "";
    let mut checked = 0;
    for line in help.lines() {
        if !line.starts_with(' ') && line.ends_with(':') {
            header = line;
            continue;
        }
        let flags = line.trim_start();
        for flag in MODE_INDEPENDENT {
            if flags.starts_with(flag) {
                checked += 1;
                assert!(
                    !header.contains("with `relay`"),
                    "`{}` is accepted in either mode, but the help files it \
                     under `{header}`",
                    flag.trim()
                );
            }
        }
    }

    // Without this the test passes on a help text that stopped listing the
    // flags at all, which is not the property being pinned.
    assert!(
        checked >= 2,
        "expected at least `-h` and `-V` to be found in the help, saw {checked}"
    );
}

/// A relay whose port is taken must not have announced itself first.
///
/// The announcement used to come before the bind, so a taken port produced a
/// banner saying `listening on`, a join command for a relay that does not
/// exist, an `INFO relay listening on` line, and only then the failure. An
/// operator pasted that join command into a device and got a dial timeout with
/// nothing pointing back at the relay as the cause.
///
/// This asserts on what was **not** printed, which is the only thing that
/// catches an ordering bug: the return value was always `Err`, and every
/// assertion about it stayed green while three lines lied. It also pins the
/// failure text, which was the `Debug` form of an `io::Error` — the one place
/// in the binary a Rust internal reached an operator.
#[test]
fn a_relay_on_a_taken_port_says_nothing_about_listening() {
    let dir = tempfile::tempdir().expect("tempdir");
    let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = holder.local_addr().expect("addr").port().to_string();

    let mut command = Command::new(BIN);
    command.current_dir(dir.path()).args([
        "relay",
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--enroll-token",
        "st_test",
    ]);
    let (code, stdout, stderr) = run_command_with_timeout(command, Duration::from_secs(15));

    assert_eq!(code, Some(1), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        !stdout.contains("listening on"),
        "a relay that never bound must not claim to be listening: {stdout}"
    );
    assert!(
        !stdout.contains("Devices join with"),
        "a join command for a relay that does not exist is worse than no \
         output at all: {stdout}"
    );
    assert!(
        !stderr.contains("relay listening on"),
        "the log line moved below the bind for the same reason: {stderr}"
    );

    assert!(
        stderr.contains("already in use"),
        "the failure must be readable, not a Debug dump: {stderr}"
    );
    assert!(
        !stderr.contains("Io(Os {"),
        "the raw io::Error Debug form must not reach an operator: {stderr}"
    );
    drop(holder);
}

/// The gateway shares the translation, because it had the identical screen.
///
/// Fixing only the relay would have left `Error: Io(Os { code: 10048, ... })`
/// on the other path — measured on both before the change, which is why the
/// helper is shared rather than local to the relay.
///
/// The tunnelled case is the relay's own defect wearing different clothes, and
/// it turned up while checking this one. A tunnel spawned the server as a task
/// and then published its banner without ever learning whether the port had
/// been taken: against a held port the old binary printed a public URL, a
/// generated API key, and a ready-to-paste `curl` — then exited 1. Every line
/// of that was false, and the URL and key were for a server that does not
/// exist. Binding before the spawn is what makes the banner conditional on the
/// port, so the two are asserted together.
#[test]
fn a_gateway_on_a_taken_port_reports_it_in_words() {
    for tunnelled in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a port");
        let port = holder.local_addr().expect("addr").port().to_string();

        let mut command = Command::new(BIN);
        command
            .current_dir(dir.path())
            .args(["--host", "127.0.0.1", "--port", &port]);
        if tunnelled {
            // A stand-in tunnel client: prints a URL and exits, which is all
            // the supervisor reads. Nothing here should be reached, and that
            // is the point.
            command.args(["--tunnel-command", "cmd /c echo https://taken.example"]);
        }
        let (code, stdout, stderr) = run_command_with_timeout(command, Duration::from_secs(20));

        assert_eq!(
            code,
            Some(1),
            "tunnelled={tunnelled} stdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("already in use"),
            "tunnelled={tunnelled}: the failure must be readable, not a Debug \
             dump: {stderr}"
        );
        assert!(
            !stderr.contains("Io(Os {"),
            "tunnelled={tunnelled}: the raw io::Error Debug form must not reach \
             an operator: {stderr}"
        );
        assert!(
            !stdout.contains("Public URL"),
            "a server that never bound must not publish a URL: {stdout}"
        );
        assert!(
            !stdout.contains("API key:"),
            "nor a credential for a server that does not exist: {stdout}"
        );
        drop(holder);
    }
}

/// `GET /api/v1` over a bare socket, with an optional bearer token, returning
/// the status code.
///
/// Written out rather than pulled from an HTTP client crate for the reason
/// `tests/fs_relay_e2e.rs` writes its own requests: a status code is all that
/// is being asked for here, and this file is otherwise synchronous and
/// dependency-free. The connect retries because the banner under test is
/// printed *before* the listener binds — seeing the line is not evidence the
/// port accepts yet.
fn get_status(port: u16, token: Option<&str>) -> u16 {
    use std::io::Write;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(e) if std::time::Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("server on port {port} never accepted a connection: {e}"),
        }
    };

    let auth = match token {
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };
    let request =
        format!("GET /api/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n{auth}\r\n");
    stream.write_all(request.as_bytes()).expect("write request");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw);
    let status_line = text.lines().next().expect("a response status line");
    status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("no status code in {status_line:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("status code in {status_line:?} is not a number: {e}"))
}

/// A server that generates its own API key must print it on stdout whatever
/// the log level is — and the key it prints must be the one that authenticates.
///
/// Both halves are load-bearing, and each covers a way the fix could be undone
/// without the other noticing:
///
/// * **`warn` as well as `info`.** The key used to be issued inside `serve_on`
///   and reported only as a `tracing::info!` line. At `-l warn` that line
///   disappears while the server starts anyway and refuses every request — an
///   unusable server that looks healthy, with no copy of the key anywhere. A
///   test at the default level alone cannot see a level-dependent bug.
/// * **stdout, with stderr discarded.** The banner and the log go to different
///   streams, so a fix that moved the key to a `warn!` line would satisfy "it
///   is printed at both levels" and still be lost to anyone redirecting only
///   stdout. Dropping stderr here is what pins the stream.
/// * **The key is exercised, not just matched.** Asserting on the shape of a
///   printed string would pass just as happily if the banner reported a key
///   that was generated, discarded, and replaced by a different one at serve
///   time — which is close to the shape of the defect being fixed.
#[test]
fn a_generated_key_reaches_stdout_at_every_log_level() {
    for (level, port) in [("info", 39883u16), ("warn", 39884u16)] {
        // Loopback derives no audit trail, but a tempdir costs nothing and
        // keeps the crate root clean should that ever change.
        let dir = tempfile::tempdir().expect("tempdir");
        let child = Command::new(BIN)
            .current_dir(dir.path())
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--require-auth",
                "-l",
                level,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("binary should start");
        let mut server = Killed(child);

        let line = wait_for_line(&mut server, Duration::from_secs(30), |l| {
            l.starts_with("API key:")
        });
        let key = line
            .split_whitespace()
            .nth(2)
            .unwrap_or_else(|| panic!("no key in {line:?} at -l {level}"));
        assert!(
            key.starts_with("st_"),
            "at -l {level} the banner must carry the issued key, got {line:?}"
        );

        assert_eq!(
            get_status(port, None),
            401,
            "at -l {level} the server must be enforcing authentication, \
             or the key above proves nothing"
        );
        assert_eq!(
            get_status(port, Some(key)),
            200,
            "at -l {level} the printed key must be the one the server accepts"
        );
    }
}
