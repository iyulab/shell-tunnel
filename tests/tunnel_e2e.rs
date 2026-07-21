//! End-to-end tests for public exposure (`--tunnel` / `--tunnel-command`).
//!
//! These drive the real binary. The tunnel provider is a fake command that
//! prints a URL, which keeps the tests runnable anywhere — installing
//! `cloudflared` is deliberately not a prerequisite for the test suite.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_shell-tunnel");

/// A tunnel command that publishes a URL and then stays alive.
fn fake_tunnel(url: &str) -> String {
    #[cfg(windows)]
    {
        format!("echo {url} && ping -n 120 127.0.0.1 > nul")
    }
    #[cfg(unix)]
    {
        format!("echo {url} && sleep 120")
    }
}

/// Kill the server and its tunnel child on the way out of a test.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Read the server's stdout lines until `predicate` matches or time runs out.
///
/// Takes the guard rather than the raw child so that a failure still tears the
/// process down — a leaked server would hold its port and break the next test.
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

#[test]
fn tunnel_publishes_a_banner_with_a_generated_key() {
    let child = Command::new(BIN)
        .args([
            "--port",
            "39871",
            "--tunnel-command",
            &fake_tunnel("https://banner-test.example"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);

    let line = wait_for_line(&mut server, Duration::from_secs(30), |l| {
        l.contains("Public URL")
    });

    assert!(line.contains("https://banner-test.example"), "{line}");
    assert!(line.contains("tunnel-command"), "{line}");
}

#[test]
fn tunnel_generates_and_reports_an_api_key() {
    let child = Command::new(BIN)
        .args([
            "--port",
            "39872",
            "--tunnel-command",
            &fake_tunnel("https://key-test.example"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary should start");
    let mut server = Killed(child);

    // A tunnel implies authentication, and the generated key must be shown —
    // it is the only copy the user gets.
    // Anchored at the start of the line: "API key" also appears in the log line
    // "Authentication enabled with 1 API key(s)", which is not the banner.
    let line = wait_for_line(&mut server, Duration::from_secs(30), |l| {
        l.starts_with("API key:")
    });

    assert!(line.contains("st_"), "{line}");
    assert!(line.contains("generated"), "{line}");
}

#[test]
fn tunnel_with_no_auth_is_refused() {
    let output = Command::new(BIN)
        .args([
            "--port",
            "39873",
            "--no-auth",
            "--tunnel-command",
            &fake_tunnel("https://never-started.example"),
        ])
        .output()
        .expect("binary should run");

    assert!(!output.status.success(), "expected a non-zero exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--no-auth"), "{stderr}");
    assert!(stderr.contains("unauthenticated shell"), "{stderr}");
}

#[test]
fn a_tunnel_command_that_never_publishes_fails_the_startup() {
    #[cfg(windows)]
    let silent = "ping -n 5 127.0.0.1 > nul";
    #[cfg(unix)]
    let silent = "sleep 5";

    let output = Command::new(BIN)
        .args([
            "--port",
            "39874",
            "--log-level",
            "error",
            "--tunnel-command",
            silent,
        ])
        .output()
        .expect("binary should run");

    // Serving local-only after being asked for a public URL would be a silent
    // failure; the process must exit instead.
    assert!(!output.status.success(), "expected a non-zero exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tunnel error"), "{stderr}");
    assert!(
        !stderr.to_lowercase().contains("tunnel error: tunnel error"),
        "the error prefix must not stutter: {stderr}"
    );
}

#[test]
fn no_tunnel_flag_means_no_banner() {
    let child = Command::new(BIN)
        .args(["--port", "39875"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary should start");

    let mut server = Killed(child);
    std::thread::sleep(Duration::from_millis(750));
    let _ = server.0.kill();

    // Logs share stdout with the banner, so the assertion is about the banner
    // itself: without a tunnel there is no public URL to announce.
    let stdout = server.0.stdout.take().expect("stdout is piped");
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        assert!(
            !line.contains("Public URL"),
            "plain listen mode must not announce a public URL: {line}"
        );
    }
}
