//! `--kill-orphans`, through the real router rather than the executor's API.
//!
//! `tests/executor_integration.rs::kill_orphans` proves the *effect* — a
//! background process is or is not ended — starting from `CommandExecutor`.
//! What it cannot see is everything above that: the flag has to travel from
//! `cli.rs` into `AppState` and out again into a rebuilt executor, and each of
//! those links can be written without ever being run. "The primitive exists but
//! nothing calls it" is this repository's most repeated defect, and a flag that
//! parses but does nothing looks exactly like one that works.
//!
//! So this drives `POST /execute` against a served `AppState` and asserts on a
//! real process. What it still does not cover is named at the bottom.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use shell_tunnel::{api, api::SecurityConfig, AppState};

const KEY: &str = "kill-orphans-e2e-key";

async fn start(kill_orphans: bool) -> SocketAddr {
    let mut security = SecurityConfig::secure().with_api_key(KEY);
    security.auth.enabled = true;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config =
        api::ServerConfig::new("127.0.0.1".to_string(), addr.port()).with_security(security);
    let state = AppState::new().with_kill_orphans(kill_orphans);

    tokio::spawn(async move {
        api::serve_on(listener, config, state).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    addr
}

/// Minimal HTTP POST returning the body — the crate has no HTTP client.
async fn post(addr: SocketAddr, path: &str, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAuthorization: Bearer {KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
        .await
        .expect("server should answer")
        .unwrap();
    String::from_utf8_lossy(&raw).into_owned()
}

/// Prints the pid of a process it leaves running, then exits.
///
/// Sleeps 25 s rather than longer so the surviving half tidies up after itself
/// even if its explicit teardown fails.
fn leave_a_process_running() -> &'static str {
    #[cfg(windows)]
    {
        // Plain text. `run` does the JSON escaping — pre-escaping here as well
        // put a literal backslash in front of the quote PowerShell needed, and
        // the command then produced no pid at all.
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

/// The pid the command printed, out of the JSON response body.
fn pid_from(response: &str) -> u32 {
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_else(|| panic!("no body in response: {response:?}"));
    // The pid is what the command *printed*, so take it from `output` rather
    // than from the whole body — `duration_ms` and the byte counts are digits
    // too, and picking one of those silently turns both tests into checks on a
    // pid that never existed. That happened: a mis-escaped command produced no
    // pid, `max()` returned a byte count, and the killing half passed on a
    // process that had never been started.
    let field = "\"output\":\"";
    let start = body
        .find(field)
        .unwrap_or_else(|| panic!("no output field in body: {body:?}"))
        + field.len();
    let printed = &body[start..];
    let printed = &printed[..printed.find('"').unwrap_or(printed.len())];
    printed
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u32>().ok())
        .next()
        .unwrap_or_else(|| panic!("the command printed no pid: {printed:?} (body {body:?})"))
}

async fn run(kill_orphans: bool) -> u32 {
    let addr = start(kill_orphans).await;
    // The route's request type carries `deny_unknown_fields`, so the key is
    // `command` and nothing else will do — this test learned that by being
    // answered `422`, which is the reason to drive the real router at all.
    let escaped = leave_a_process_running()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let body = format!(r#"{{"command":"{escaped}"}}"#);
    let response = post(addr, "/api/v1/execute", &body).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "execute should succeed: {response}"
    );
    pid_from(&response)
}

#[tokio::test]
async fn with_the_flag_on_a_background_process_does_not_outlive_the_request() {
    let pid = run(true).await;

    // Polled rather than slept on: the kill is a system call and normally lands
    // before the first check. The bound only turns a failure into a report
    // instead of a hang, and it is far under the 25 s the process would run for
    // on its own — a pass cannot be the sleeper merely having finished.
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
        "--kill-orphans is on, so pid {pid} should not have outlived the request"
    );
}

#[tokio::test]
async fn with_the_flag_off_a_background_process_keeps_running() {
    // The default is a promise, not the absence of a feature: a command that
    // starts a daemon on purpose has always been allowed to keep it, and an
    // upgrade must not change that. This is the half that fails if reaping ever
    // becomes unconditional.
    let pid = run(false).await;
    let survived = alive(pid);
    terminate(pid);
    assert!(
        survived,
        "with --kill-orphans off, pid {pid} must survive the request"
    );
}

/// The one link neither test above can reach: `main.rs` passing the parsed flag.
///
/// Everything from `AppState` down is covered by running it. Above that sits a
/// single expression in the binary's startup path, and covering *it* by
/// behaviour would mean spawning the binary and speaking HTTP to it — a whole
/// harness for one argument. So this checks the source text instead, which is
/// the same trade this repository already makes for the reader-thread guard.
///
/// What it proves: the call exists and is fed by the parsed flag. What it does
/// not prove: that it runs. If this ever fails, the fix is the call, not the
/// test.
#[test]
fn the_binary_hands_the_parsed_flag_to_the_state() {
    let main_rs = include_str!("../src/main.rs");
    assert!(
        main_rs.contains(".with_kill_orphans(args.kill_orphans)"),
        "src/main.rs must pass the parsed --kill-orphans through to AppState, or the flag is inert"
    );
}
