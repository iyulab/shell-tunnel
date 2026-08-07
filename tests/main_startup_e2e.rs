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
            "0",
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
    let mut seen = wait_for_stdout_lines(server, timeout, predicate);
    seen.pop().expect("the matching line is the last one read")
}

/// As `wait_for_line`, returning every line read rather than only the match.
///
/// Callers that assert on what the stream does *not* carry, or on a line's
/// neighbour, need the lines that arrived before the match as much as the
/// match itself.
fn wait_for_stdout_lines(
    server: &mut Killed,
    timeout: Duration,
    predicate: impl Fn(&str) -> bool,
) -> Vec<String> {
    let stdout = server.0.stdout.take().expect("stdout is piped");
    match read_lines_until(stdout, timeout, predicate) {
        Ok(lines) => lines,
        Err(seen) => {
            explain_missing_line(
                &seen,
                server.0.stderr.take(),
                "stderr",
                "a server that fails at startup says why on stderr and nowhere else, which \
                 is why a bind failure reads from stdout alone as a banner that lost a line",
                timeout,
            );
        }
    }
}

/// As `wait_for_stdout_lines`, for the diagnostics stream.
fn wait_for_stderr_lines(
    server: &mut Killed,
    timeout: Duration,
    predicate: impl Fn(&str) -> bool,
) -> Vec<String> {
    let stderr = server.0.stderr.take().expect("stderr is piped");
    match read_lines_until(stderr, timeout, predicate) {
        Ok(lines) => lines,
        Err(seen) => {
            explain_missing_line(
                &seen,
                server.0.stdout.take(),
                "stdout",
                "the banner is written to stdout, so how far it got is what says whether \
                 the process reached the point this log line comes from",
                timeout,
            );
        }
    }
}

/// Read `stream` until a line matches `predicate`, returning everything read
/// with the match last. Panics if the deadline passes first, quoting what did
/// arrive — a silent empty result would let an absence assertion pass on a
/// stream that never produced anything.
///
/// The reader thread goes on draining after its receiver is gone, and that is
/// load-bearing rather than tidy-up. Stopping at the first failed send drops
/// the `BufReader`, which closes this end of the child's pipe — and the child
/// is still writing its banner. Its next `println!` then fails on a broken
/// pipe and panics the process, so a test that had already found the line it
/// wanted would go on to find nothing listening on the port. That is a race,
/// not a certainty: it depends on how much of the banner the child had flushed
/// before the match arrived, which is why it stayed hidden until a line was
/// added to the banner and shifted the timing. Draining until EOF keeps the
/// pipe open for as long as the child holds the other end; `Killed` ends both.
/// Returns `Err` with everything read rather than panicking, so the caller —
/// which still has the child — can say what the *other* stream held before it
/// gives up. See `explain_missing_line`.
fn read_lines_until(
    stream: impl Read + Send + 'static,
    timeout: Duration,
    predicate: impl Fn(&str) -> bool,
) -> Result<Vec<String>, Vec<String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });

    let deadline = std::time::Instant::now() + timeout;
    let mut seen = Vec::new();
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                let matched = predicate(&line);
                seen.push(line);
                if matched {
                    return Ok(seen);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Err(seen)
}

/// Panic for a line that never arrived, saying where the reason would be.
///
/// A server that fails at startup writes why on stderr and stops, so on stdout
/// the failure looks like a banner that simply stopped early — indistinguishable
/// from a banner line being renamed. cycle-92 read exactly that and diagnosed the
/// wrong cause; the message it had quoted the truncated stdout and said nothing
/// about the stream that held the answer.
///
/// So: drain whatever is left of the sibling stream and quote it, and when the
/// test discarded that stream, *say that* rather than printing the same
/// truncated stdout and leaving the reader to infer a cause. Naming the blind
/// spot is the part that stops the misdiagnosis; the drained text is a bonus
/// when it is there.
/// `why_it_matters` completes the sentence for the stream that is missing —
/// stdout and stderr carry different evidence, and a note written for one reads
/// as false about the other.
fn explain_missing_line(
    seen: &[String],
    sibling: Option<impl Read + Send + 'static>,
    sibling_name: &str,
    why_it_matters: &str,
    timeout: Duration,
) -> ! {
    let sibling_report = match sibling {
        // Nothing waits on a predicate here: the child is already failing, so
        // read what has been written and move on rather than adding another
        // multi-second stall to a test that is going to fail anyway.
        Some(stream) => match read_lines_until(stream, Duration::from_millis(500), |_| false) {
            Ok(lines) | Err(lines) if lines.is_empty() => {
                format!("{sibling_name} was open and carried nothing")
            }
            Ok(lines) | Err(lines) => format!("{sibling_name} held:\n{}", lines.join("\n")),
        },
        None => format!(
            "{sibling_name} is not readable here — this test discards it, or had already \
             read it. {why_it_matters}, so this message is missing that evidence rather \
             than reporting its absence"
        ),
    };
    panic!(
        "expected line not seen within {timeout:?}; got:\n{}\n\n---\n{sibling_report}",
        seen.join("\n")
    );
}

/// A TCP port nothing is listening on, for a server a test has to connect to.
///
/// Binding `:0` and closing hands back a port the OS had free a moment ago,
/// which is not the same as reserving it — something else can take it in the
/// window before the child binds. That race is against the machine's whole
/// ephemeral range, though, where the fixed numbers this file used to carry
/// raced against *each other*: two tests in this binary both wanted `39884`
/// and both bound it, and `#[test]`s in one binary run in parallel by default.
/// A leftover process from an interrupted run held those numbers too.
///
/// The ten spawn sites that only need a port the OS will accept do not need
/// this — they pass `--port 0` and let it choose, with no window at all. Only
/// three send a request, and one of those (`a_generated_key_reaches_stdout_at_every_log_level`)
/// is why the port cannot simply be read back from the running server: the
/// chosen port is announced by a `tracing` line at `info`, and that test exists
/// to cover `warn`, where the line is not emitted.
///
/// The same bind-`:0` call already appears in the two taken-port tests below,
/// which keep the listener open instead of dropping it. This is that pattern
/// with the opposite intent, not a new one.
fn reserved_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("a loopback port is available")
        .local_addr()
        .expect("a bound listener has an address")
        .port()
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
        .args(["--host", "0.0.0.0", "--port", "0"])
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
        "0",
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
        let mut with_bind = vec!["--host", "127.0.0.1", "--port", "0"];
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
            Err(e) => panic!(
                "server on port {port} never accepted a connection: {e}. The port came \
                 from `reserved_port()`, which cannot hold it — if something else took \
                 it before the child bound, the child exited at startup and never \
                 listened. That is not a server that started and then died, which is \
                 what these tests are about. Read the child's stderr before concluding \
                 this is the behaviour under test."
            ),
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
    // A port this test has to connect to, so `--port 0` is not available: the
    // number the OS picks is announced only by a `tracing` line at `info`, and
    // half of this test's point is that `warn` must work too. See
    // `reserved_port`.
    for level in ["info", "warn"] {
        let port = reserved_port();
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

/// The diagnostics stream must carry no ANSI escapes.
///
/// `tracing-subscriber`'s `fmt` layer colours its output whenever the crate's
/// `ansi` feature is compiled in — it never asks whether anything downstream
/// can render an escape, and on Windows it never enables the console's
/// virtual-terminal mode either. So the escapes went wherever the logs went:
/// into the file a service definition redirects to, into an agent's pipe, and
/// onto consoles that print them literally as `←[2m` in front of every line.
///
/// Nothing inside the crate could have caught it. `logging.rs`'s unit tests
/// emit records and assert they do not panic, and a record's *text* is
/// identical either way — only the bytes on the pipe differ, and only a real
/// process writing to a real pipe has those. This test is that process.
///
/// It reads until the version line rather than asserting on an empty stream:
/// an absence assertion over nothing passes vacuously. The predicate matches
/// with escapes present too (they wrap the fields, not the message), so a
/// regression fails on the assertion below rather than timing out — confirmed
/// by running it against the unfixed binary.
#[test]
fn the_log_stream_carries_no_ansi_escapes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args(["--host", "127.0.0.1", "--port", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);

    let seen = wait_for_stderr_lines(&mut server, Duration::from_secs(30), |l| {
        l.contains("shell-tunnel v")
    });

    for line in &seen {
        assert!(
            !line.contains('\u{1b}'),
            "a log line reaching a pipe must be plain text, got {line:?}"
        );
    }
}

/// A key this server generated must say, on the next line, that it is gone on
/// restart — the same thing the relay's generated enrolment token already says.
///
/// `Config::ensure_api_key` pushes the key into the in-memory key list and
/// writes it nowhere, so the two credentials fail identically: restart, and
/// the old value stops working. Only the enrolment token said so. The gap is
/// worst behind a relay, where a device names itself after the machine and its
/// public URL is *deliberately* stable across restarts — the address an
/// operator handed out keeps answering while the key behind it rotates, so the
/// symptom is "the URL is fine and everything 401s" rather than anything that
/// points at a key.
///
/// The assertion is on adjacency, not mere presence. A note printed somewhere
/// else in the banner would satisfy "the text appears" and still not read as a
/// qualifier of the line it belongs to, which is the whole of its job.
#[test]
fn a_generated_key_is_printed_with_the_warning_that_it_is_not_saved() {
    let dir = tempfile::tempdir().expect("tempdir");
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args(["--host", "127.0.0.1", "--port", "0", "--require-auth"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);

    let seen = wait_for_stdout_lines(&mut server, Duration::from_secs(30), |l| {
        l.trim_start().starts_with("not saved:")
    });

    let note = seen.last().expect("the match is the last line");
    let above = seen
        .get(seen.len().wrapping_sub(2))
        .unwrap_or_else(|| panic!("the note has no line above it: {seen:?}"));
    assert!(
        above.starts_with("API key:") && above.contains("(generated)"),
        "the note must qualify the generated-key line directly above it, got {above:?}"
    );

    // Naming the flag is what makes the note actionable rather than a lament;
    // the enrolment token's note names `--enroll-token` for the same reason.
    assert!(
        note.contains("--api-key"),
        "the note must name the flag that pins the key, got {note:?}"
    );
    // Alignment is what makes it read as a continuation of the line above
    // rather than a new fact, so it is pinned to the column that line's value
    // actually starts at — not to a hardcoded width that would drift silently
    // if the labels were ever re-padded.
    let column = above.find("st_").expect("the key line carries the key");
    assert!(
        note.starts_with(&" ".repeat(column)) && !note[column..].starts_with(' '),
        "the note must start at the value column ({column}) of the line above, got {note:?}"
    );
}

/// The join line a relay prints must be the command, not a template.
///
/// Every other value on it is interpolated — the URL, and the fingerprint when
/// there is one — so a placeholder in the token position leaves an operator
/// splicing one field by hand into an otherwise complete line. Nothing is
/// protected by it either: a token this process generated is printed in full
/// three lines above, on the same screen.
#[test]
fn a_generated_enrolment_token_reaches_the_join_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args(["relay", "--host", "127.0.0.1", "--port", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary should start");
    let mut relay = Killed(child);

    let seen = wait_for_stdout_lines(&mut relay, Duration::from_secs(30), |l| {
        l.trim_start().starts_with("shell-tunnel --relay")
    });
    let join = seen.last().expect("the match is the last line").clone();

    let token = seen
        .iter()
        .find_map(|l| l.strip_prefix("Enroll token:"))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no generated token was announced: {seen:?}"));
    assert!(
        token.starts_with("st_"),
        "expected a generated token above the join line, got {token:?}"
    );

    assert!(
        join.contains(&format!("--enroll-token {token}")),
        "the join line must carry the token that was generated, got {join:?}"
    );
    assert!(
        !join.contains("<token>"),
        "a line presented as the command to run must not be a template: {join:?}"
    );
}

/// The audit trail's path is announced once, by whichever of the two outputs
/// is speaking for the posture in force.
///
/// An exposed server's posture banner names it on stdout, so logging it as
/// well printed the same path twice, two lines apart. A local server has no
/// banner at all — `posture_banner` reports nothing when nothing was narrowed
/// — and can still be handed `--audit-log`, so there the log line is the only
/// thing that says where the trail went. Deleting it outright would have
/// traded a duplicate for a silence, which is why both halves are asserted
/// here rather than just the one that changed.
#[test]
fn the_audit_trail_path_is_announced_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args(["--host", "0.0.0.0", "--port", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    let mut exposed = Killed(child);

    let out = wait_for_stdout_lines(&mut exposed, Duration::from_secs(30), |l| {
        l.starts_with("File API:")
    });
    assert_eq!(
        out.iter().filter(|l| l.starts_with("Audit trail:")).count(),
        1,
        "the exposed banner names the trail exactly once: {out:?}"
    );

    // Read past the line that proves startup logging happened, so "no audit
    // line on stderr" is an assertion about a stream that spoke, not silence.
    let err = wait_for_stderr_lines(&mut exposed, Duration::from_secs(30), |l| {
        l.contains("Starting shell-tunnel API server")
    });
    assert!(
        !err.iter().any(|l| l.contains("audit trail:")),
        "the banner already said it; the log must not repeat it: {err:?}"
    );
    drop(exposed);

    // The other half: with no banner to carry it, the log line must.
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_log = dir.path().join("local-audit.jsonl");
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--audit-log",
            audit_log.to_str().expect("utf-8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    let mut local = Killed(child);

    let err = wait_for_stderr_lines(&mut local, Duration::from_secs(30), |l| {
        l.contains("audit trail:")
    });
    let line = err.last().expect("the match is the last line");
    assert!(
        line.contains("local-audit.jsonl"),
        "a local server's only announcement must name the path it was given: {line:?}"
    );
}

/// A relay-joined device advertises a smaller upload chunk than a directly
/// reached one, and it does so *silently* unless the banner says otherwise —
/// an operator comparing two deployments would find no line explaining why
/// one hands out 262144 and the other 4194304.
///
/// Only the real binary can prove this. `resolve_chunk_size` is a pure
/// function and could be unit-tested green while `async_main` printed the
/// banner from a second, stale copy of the same decision — which is exactly
/// the shape the resolution was factored out to prevent. The line has to be
/// read off the process that also serves the value.
///
/// Gated because it drives the binary with `--relay`, which a build without
/// this feature refuses outright ("this build has no relay client"). Ungated,
/// it failed every plain `cargo test --all` — a command this repository tells
/// you to run when you touch dependencies. It went unnoticed because CI checks
/// the default build by *building* it (`cargo build --locked`), never by
/// running its tests, so nothing on any machine but a developer's ran this.
#[cfg(feature = "relay-client")]
#[test]
fn a_relay_joined_banner_names_the_chunk_size_it_will_advertise() {
    let dir = tempfile::tempdir().expect("tempdir");
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args([
            "--relay",
            // Deliberately unreachable: the relay client retries in the
            // background, and the local server (and its banner) come up
            // regardless. Nothing here needs a relay to actually answer.
            "wss://127.0.0.1:59999",
            "--enroll-token",
            "t",
            "--port",
            "0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);

    let line = wait_for_line(&mut server, Duration::from_secs(30), |l| {
        l.contains("upload chunk size")
    });

    assert!(
        line.contains("262144"),
        "the banner must name the relay-path size the server will actually advertise: {line}"
    );
}

/// A loopback server that is actually behind a proxy says so, on the first
/// request that proves it.
///
/// The posture is decided by the bind address, so a reverse proxy — the
/// arrangement this product's own TLS error tells an operator to set up —
/// leaves the server reading itself as private while it is reachable from
/// wherever the proxy is. Documentation says this at every place the
/// arrangement is suggested, and documentation protects whoever reads it. The
/// warning is the part that needs no reading.
///
/// Only the real binary can prove it. The middleware is added conditionally,
/// and a unit test of the message could be green while nothing ever mounted
/// the layer — which is the whole failure mode: a check nobody runs.
#[test]
fn a_proxied_request_to_an_unauthenticated_server_is_warned_about() {
    let dir = tempfile::tempdir().expect("tempdir");
    // This test sends a request, so it needs the port up front. See `reserved_port`.
    let port = reserved_port();
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);

    assert_eq!(
        get_status_with_headers(port, &["X-Forwarded-For: 203.0.113.9"]),
        200,
        "the warning must not change what the request gets"
    );

    let lines = wait_for_stderr_lines(&mut server, Duration::from_secs(30), |l| {
        l.contains("--require-auth")
    });
    let text = lines.join("\n");

    assert!(
        text.contains("X-Forwarded-For") || text.contains("x-forwarded-for"),
        "the warning must name the evidence it saw: {text}"
    );
    assert!(
        text.contains("run commands"),
        "an operator has to be told what is at stake, not only that a header arrived: {text}"
    );
}

/// `GET /api/v1` with extra request headers, returning the status code.
///
/// `get_status` takes only a bearer token; this takes whole header lines,
/// which is what a test about a proxy-added header needs.
fn get_status_with_headers(port: u16, headers: &[&str]) -> u16 {
    use std::io::Write;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(e) if std::time::Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!(
                "server on port {port} never accepted a connection: {e}. The port came \
                 from `reserved_port()`, which cannot hold it — if something else took \
                 it before the child bound, the child exited at startup and never \
                 listened. That is not a server that started and then died, which is \
                 what these tests are about. Read the child's stderr before concluding \
                 this is the behaviour under test."
            ),
        }
    };

    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    let request =
        format!("GET /api/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n{extra}\r\n");
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

/// A server whose stdout reader goes away must keep serving.
///
/// `println!` panics on a failed write, and a banner written into a pipe with
/// no reader left is a failed write — so the process used to die mid-banner
/// with `failed printing to stdout: The pipe is being closed. (os error 232)`.
/// That was first seen as a *test* harness closing the read end early
/// (cycle-60), but nothing about it is peculiar to a test: the operating
/// guide's service recipes put a long-lived consumer on this pipe, and a log
/// shipper restarting or a wrapper's `| head` exiting closes it the same way.
/// An operator cannot defend against it from outside the process.
///
/// The read end is closed *before* the banner is written rather than after one
/// line, which is what makes this deterministic. Reading a line first
/// reproduces the panic only when the child happens to still be writing —
/// cycle-60 saw it two runs in three that way, and `shell-tunnel | head -1`
/// never reproduced it at all, because `head` holds the pipe open until it
/// exits. Closing outright puts every banner write on the far side of a closed
/// pipe, so this fails every time if the tolerance is removed.
#[test]
fn a_server_outlives_the_reader_of_its_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The stdout this test closes is the only stream that could have carried an
    // OS-chosen port, so the port has to be known before the child starts. See
    // `reserved_port`.
    let port = reserved_port();
    let mut child = Command::new(BIN)
        .current_dir(dir.path())
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--require-auth",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary should start");

    drop(child.stdout.take().expect("stdout is piped"));
    let mut server = Killed(child);

    // `401`, not `200`: the key was announced on the stdout just closed, and
    // what is being asked here is whether anything is answering at all. A dead
    // process fails this by never accepting the connection.
    assert_eq!(
        get_status(port, None),
        401,
        "the server must outlive the reader of its stdout"
    );

    // Touch `server` after the request so the child is not killed before it.
    let _ = &mut server;
}

/// Both periodic sweeps are wired into the running server, not merely written.
///
/// `SessionStore::sweep_idle` and `UploadStore::sweep` are the only things that
/// reclaim an abandoned session, and a sweep with no caller is indistinguishable
/// from no sweep at all — which is exactly the state shell sessions were in:
/// the reclaim method existed and nothing outside tests called it, so sessions
/// accumulated for the life of the process.
///
/// Read off the source, and the reason is worth stating rather than implying:
/// the sweeps run on a five-minute ticker against a one-hour TTL, so observing
/// one from outside means either waiting an hour or making the interval and the
/// TTL configurable purely so a test can shorten them. Adding configuration to
/// a product surface to make a test possible is the tail wagging the dog, and
/// an hour-long test would be skipped and then rot (this repository has already
/// had three skipped tests whose stated reasons had quietly become false).
///
/// So what is pinned is the wiring: that the periodic task exists and calls
/// both audit-aware sweeps. `SessionStore::sweep_idle`'s own unit tests pin what
/// a sweep does; this pins that something asks for one.
#[test]
fn the_periodic_sweeps_are_wired_into_the_server() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = std::fs::read_to_string(&path).expect("source file is readable");

    for call in [
        "sweep_expired_sessions(",
        "sweep_expired_uploads(",
        "tokio::time::interval(",
    ] {
        assert!(
            source.contains(call),
            "src/main.rs no longer contains `{call}` — an abandoned session or upload is \
             reclaimed by nothing else on a server that has gone quiet, and a reclaim \
             method with no caller is the state this guard exists to prevent"
        );
    }
}

/// `--help` must name the audit rotation default the binary actually applies.
///
/// Read from the running binary rather than from the source string, because
/// what an operator sees is the output — this repository has shipped
/// user-facing text no test asserted on four separate occasions, and `--help`
/// is the only place most operators ever read a default.
///
/// The pairing matters more than either half. A default that changes without
/// the help changing, and help that names a default the code does not have,
/// are the same defect seen from two sides, and both read as reassurance.
#[test]
fn help_names_the_audit_rotation_default_the_binary_uses() {
    let (_code, stdout, _stderr) = run_with_timeout(&["--help"], Duration::from_secs(20));
    let figure = shell_tunnel::audit::DEFAULT_MAX_BYTES.to_string();

    assert!(
        stdout.contains(&figure),
        "--help should name {figure}, the limit it actually applies. Got:\n{stdout}"
    );
    assert!(
        stdout.contains("0 never rotates"),
        "--help must say what 0 does, or an operator reads it as a zero-byte limit. Got:\n{stdout}"
    );
}

/// A device started with `--kill-orphans` says so, and one without it does not.
///
/// The flag reverses a promise `--help` makes in as many words — "a daemon
/// started on purpose is meant to outlive the request" — and a device running
/// with it used to print a banner not one byte different from a device running
/// without it. An operator inheriting such a server, whose deployment daemon
/// then died with the request that started it, had nothing to read anywhere:
/// not the banner, not the response, not the audit trail.
///
/// Both directions are asserted from one run each, because the absence half is
/// the one that catches a line printed unconditionally — which would be a
/// worse defect than the silence, since a banner that always claims the flag
/// is on tells every operator the wrong thing rather than one of them nothing.
/// `tests/kill_orphans_e2e.rs` proves the *behaviour* from the router down; it
/// never sees a banner, because it serves an `AppState` rather than spawning
/// the binary.
#[test]
fn the_banner_says_when_kill_orphans_is_on_and_stays_quiet_when_it_is_not() {
    let with = spawn_and_read_banner(&["--host", "0.0.0.0", "--port", "0", "--kill-orphans"]);
    let without = spawn_and_read_banner(&["--host", "0.0.0.0", "--port", "0"]);

    let orphan_line = with
        .iter()
        .find(|l| l.starts_with("Orphans:"))
        .unwrap_or_else(|| {
            panic!(
                "--kill-orphans left no trace in the banner. Got:\n{}",
                with.join("\n")
            )
        });
    assert!(
        orphan_line.contains("--kill-orphans"),
        "the line must name the flag, or an operator cannot tell what to remove: {orphan_line}"
    );
    assert!(
        with.iter()
            .any(|l| l.contains("does NOT outlive its request")),
        "the line must say what stops happening, not only that a flag is set. Got:\n{}",
        with.join("\n")
    );
    assert!(
        !without.iter().any(|l| l.starts_with("Orphans:")),
        "the default behaviour is the documented one and needs no line. Got:\n{}",
        without.join("\n")
    );
}

/// Spawn an exposed server, read its banner up to the file-API block, and
/// return every line seen.
///
/// `File API:` is the last block of the banner, so waiting for the line after
/// which nothing more is printed is what makes an *absence* assertion sound: a
/// test that stopped reading earlier could not tell "the line is not printed"
/// from "the line had not been printed yet".
fn spawn_and_read_banner(args: &[&str]) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let child = Command::new(BIN)
        .current_dir(dir.path())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);
    // The audit-scope note is the last line an exposed bare bind prints, and
    // the orphan line sits above it — so reaching this predicate means the
    // whole banner has been read, including the place the orphan line would
    // have been. `Public URL`/`Try:` never appear on a bare bind.
    wait_for_stdout_lines(&mut server, Duration::from_secs(30), |l| {
        l.contains("nothing is outside a machine-wide file API")
    })
}

/// A relay started with its limiter off says what that turned off.
///
/// The relay's limiter is not throughput management: enrolment attempts land on
/// a relay route, so it is the only thing standing between a weak enrol token
/// and line-speed guessing — which `docs/USAGE.md` says outright. The *device*
/// warned on the same flag; the relay, the more exposed of the two, said
/// nothing. Measured on 0.21.0: 200 wrong tokens, 200 `401`s, no `429`.
///
/// This test is why the warning sits below `logging::init`. Written beside the
/// flag it reads — the obvious place — it compiled, ran, and printed nothing,
/// because no subscriber existed that early. Reading the code could not have
/// shown that; spawning the binary did.
#[test]
fn a_relay_started_without_its_limiter_says_what_that_turned_off() {
    let port = reserved_port().to_string();
    let child = Command::new(BIN)
        .args([
            "relay",
            "--port",
            &port,
            "--enroll-token",
            "t",
            "--no-rate-limit",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);

    let lines = wait_for_stderr_lines(&mut server, Duration::from_secs(30), |l| {
        l.contains("relay listening on")
    });
    let warning = lines
        .iter()
        .find(|l| l.contains("rate limiting is disabled"))
        .unwrap_or_else(|| {
            panic!(
                "a relay that dropped its brute-force defence said nothing. Got:\n{}",
                lines.join("\n")
            )
        });
    assert!(
        warning.contains("enrol token"),
        "naming the flag is not enough — the line must say what is now guessable: {warning}"
    );

    // The control. A relay keeping its limiter must not carry the warning, or
    // the line means nothing wherever it appears.
    let port = reserved_port().to_string();
    let child = Command::new(BIN)
        .args(["relay", "--port", &port, "--enroll-token", "t"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);
    let lines = wait_for_stderr_lines(&mut server, Duration::from_secs(30), |l| {
        l.contains("relay listening on")
    });
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("rate limiting is disabled")),
        "a relay with its limiter on must not claim otherwise. Got:\n{}",
        lines.join("\n")
    );
}
