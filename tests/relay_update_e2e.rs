//! A device following its relay's version, driven through the real binary on
//! both sides: a relay, a device started from a copy in a scratch directory,
//! and a local HTTP server standing in for the release download.
//!
//! A second release cannot be built inside a test, so the "release" is this
//! very binary, and the device is told (debug builds only) to count itself as
//! version 0.0.1. Its trial run still reports the real version, which is the
//! one the relay announces — so every check on the way is the real one except
//! the Windows publisher check, which a debug build skips when asked to.
//!
//! Windows has no in-place restart: the device ends with status 4 and the test
//! plays the supervisor by starting it again. On Unix the process replaces
//! itself and keeps its pid.

#![cfg(all(feature = "self-update", feature = "relay-client"))]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_shell-tunnel");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const EXE_NAME: &str = if cfg!(windows) {
    "shell-tunnel.exe"
} else {
    "shell-tunnel"
};

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port from a window no other test binary hands out from.
fn reserved_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(23_000);
    loop {
        let port = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(port < 23_500, "no free port in the window");
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn asset() -> String {
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "windows-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "x86_64") => "macos-x64",
        ("macos", "aarch64") => "macos-arm64",
        other => panic!("no release target for {other:?}"),
    };
    format!(
        "shell-tunnel-{target}.{}",
        if cfg!(windows) { "zip" } else { "tar.gz" }
    )
}

/// This binary packed the way a release packs it.
fn pack() -> Vec<u8> {
    let work = tempfile::tempdir().unwrap();
    std::fs::copy(BIN, work.path().join(EXE_NAME)).unwrap();
    let out = work.path().join(asset());
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new(
            PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32\\tar.exe"),
        );
        c.arg("-a").arg("-cf");
        c
    } else {
        let mut c = Command::new("tar");
        c.arg("-czf");
        c
    };
    let status = cmd
        .arg(&out)
        .arg("-C")
        .arg(work.path())
        .arg(EXE_NAME)
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::read(out).unwrap()
}

/// Serve the release for `VERSION` from a thread of its own. Returns the base URL.
fn serve_release() -> String {
    use axum::extract::State;
    use axum::http::{StatusCode, Uri};
    use axum::response::IntoResponse;

    let archive = pack();
    let sums = format!(
        "{}  {}\n",
        Sha256::digest(&archive)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        asset()
    );
    let files: Arc<HashMap<String, Vec<u8>>> = Arc::new(HashMap::from([
        (format!("/download/v{VERSION}/{}", asset()), archive),
        (
            format!("/download/v{VERSION}/SHA256SUMS"),
            sums.into_bytes(),
        ),
    ]));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let app = axum::Router::new()
                .fallback(
                    |State(files): State<Arc<HashMap<String, Vec<u8>>>>, uri: Uri| async move {
                        match files.get(uri.path()) {
                            Some(body) => body.clone().into_response(),
                            None => StatusCode::NOT_FOUND.into_response(),
                        }
                    },
                )
                .with_state(files);
            axum::serve(listener, app).await.unwrap();
        });
    });
    format!("http://127.0.0.1:{port}/download")
}

fn start_relay(dir: &Path, port: u16) -> Killed {
    Killed(
        Command::new(BIN)
            .current_dir(dir)
            .args([
                "relay",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--enroll-token",
                "st_update",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("relay should start"),
    )
}

/// One scratch directory holding the device's executable, state and trail.
struct Device {
    dir: tempfile::TempDir,
    relay_port: u16,
    base_url: String,
    timings: &'static str,
}

impl Device {
    fn new(relay_port: u16, base_url: String, timings: &'static str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(BIN, dir.path().join(EXE_NAME)).unwrap();
        Self {
            dir,
            relay_port,
            base_url,
            timings,
        }
    }

    fn exe(&self) -> PathBuf {
        self.dir.path().join(EXE_NAME)
    }

    /// Start the device; `pretend` makes it count itself as 0.0.1.
    fn start(&self, pretend: bool) -> Killed {
        self.start_on(pretend, 0)
    }

    /// As [`Self::start`], with the local API on `port` (0: any).
    fn start_on(&self, pretend: bool, port: u16) -> Killed {
        let port = port.to_string();
        let mut cmd = Command::new(self.exe());
        cmd.current_dir(self.dir.path())
            .args([
                "--relay",
                &format!("ws://127.0.0.1:{}", self.relay_port),
                "--enroll-token",
                "st_update",
                "--device-name",
                "upd",
                "--port",
                &port,
                "-k",
                "st_update_key",
                "--audit-log",
                "audit.jsonl",
                "--follow-relay-updates",
            ])
            .env("SHELL_TUNNEL_UPDATE_BASE_URL", &self.base_url)
            .env("SHELL_TUNNEL_UPDATE_SKIP_AUTHENTICODE", "1")
            .env("SHELL_TUNNEL_UPDATE_TIMINGS", self.timings)
            .env_remove("SHELL_TUNNEL_UPDATE_PRETEND_VERSION")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if pretend {
            cmd.env("SHELL_TUNNEL_UPDATE_PRETEND_VERSION", "0.0.1");
        }
        Killed(cmd.spawn().expect("device should start"))
    }

    /// The `kind` of every audit event so far, in order.
    fn kinds(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["kind"].as_str().map(str::to_string))
            .filter(|k| k.starts_with("update."))
            .collect()
    }

    /// Every `update.*` line of the trail, whole — for failure messages.
    fn update_lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("\"update."))
            .map(str::to_string)
            .collect()
    }

    fn wait_for_kind(&self, kind: &str, within: Duration) {
        let deadline = Instant::now() + within;
        while !self.kinds().iter().any(|k| k == kind) {
            assert!(
                Instant::now() < deadline,
                "no {kind} within {within:?}; update events so far: {:#?}",
                self.update_lines()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn state(&self) -> serde_json::Value {
        let text = std::fs::read_to_string(self.dir.path().join("shell-tunnel.update.json"))
            .unwrap_or_else(|_| "{}".to_string());
        serde_json::from_str(&text).unwrap()
    }
}

/// Wait for `child` to exit, and return its status code.
fn exit_code(child: &mut Killed, within: Duration) -> Option<i32> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            return status.code();
        }
        assert!(
            Instant::now() < deadline,
            "the device did not exit within {within:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn an_opted_in_device_updates_when_idle_and_reattaches() {
    let relay_dir = tempfile::tempdir().unwrap();
    let relay_port = reserved_port();
    let _relay = start_relay(relay_dir.path(), relay_port);
    let device = Device::new(relay_port, serve_release(), "300,0,20000");

    let mut first = device.start(true);
    device.wait_for_kind("update.applying", Duration::from_secs(120));

    if cfg!(windows) {
        // No in-place restart: the device ends so its supervisor starts the
        // new binary, with the status that tells a log it was on purpose.
        assert_eq!(exit_code(&mut first, Duration::from_secs(30)), Some(4));
        let state = device.state();
        assert_eq!(state["pending"]["to"], VERSION, "state: {state}");
        assert_eq!(state["pending"]["from"], "0.0.1", "state: {state}");
        first = device.start(false);
    }

    device.wait_for_kind("update.applied", Duration::from_secs(60));
    assert!(
        first.0.try_wait().unwrap().is_none(),
        "the updated device should keep running"
    );
    // The process now runs the binary at the executable's path, not the one
    // the swap moved aside — the two are the same bytes here, so only the path
    // can tell them apart. Linux shows it through a rename.
    #[cfg(target_os = "linux")]
    {
        let running = std::fs::read_link(format!("/proc/{}/exe", first.0.id())).unwrap();
        assert_eq!(running, device.exe(), "restarted into the replaced binary");
    }
    let state = device.state();
    assert!(state["pending"].is_null(), "state: {state}");
    assert!(
        device.dir.path().join(format!("{EXE_NAME}.prev")).exists(),
        "the replaced binary is kept as .prev"
    );
    assert!(!device
        .dir
        .path()
        .join(if cfg!(windows) {
            "shell-tunnel.staged.exe"
        } else {
            "shell-tunnel.staged"
        })
        .exists());

    // Running the relay's version now, it does not update again.
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        device.kinds(),
        ["update.available", "update.applying", "update.applied"]
    );
}

#[test]
fn a_new_binary_that_cannot_reach_the_relay_is_rolled_back() {
    let relay_dir = tempfile::tempdir().unwrap();
    let relay_port = reserved_port();
    let relay = start_relay(relay_dir.path(), relay_port);
    // Idle for 3 s before the swap: long enough to take the relay away after
    // the device has seen its version and before the new binary starts.
    let device = Device::new(relay_port, serve_release(), "3000,0,2000");

    let mut first = device.start(true);
    device.wait_for_kind("update.available", Duration::from_secs(60));
    drop(relay);
    device.wait_for_kind("update.applying", Duration::from_secs(120));

    if cfg!(windows) {
        assert_eq!(exit_code(&mut first, Duration::from_secs(30)), Some(4));
        // The new binary, on probation, cannot reach the relay.
        first = device.start(false);
        assert_eq!(exit_code(&mut first, Duration::from_secs(30)), Some(4));
    }
    device.wait_for_kind("update.rolled-back", Duration::from_secs(60));

    let state = device.state();
    assert!(state["pending"].is_null(), "state: {state}");
    assert!(
        state["retry_not_before_ms"].as_u64().is_some(),
        "an unreachable relay is retried later, not abandoned: {state}"
    );
    assert_eq!(state["abandoned"], serde_json::json!([]), "state: {state}");
    assert!(device
        .dir
        .path()
        .join(format!("{EXE_NAME}.failed"))
        .exists());
    assert!(!device.dir.path().join(format!("{EXE_NAME}.prev")).exists());
    drop(first);
}

/// Run `command` through the device's own API, blocking until it answers.
fn execute(port: u16, command: &str) -> String {
    use std::io::{Read, Write};
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => break s,
            Err(e) => {
                assert!(Instant::now() < deadline, "device API never came up: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    let body = serde_json::json!({ "command": command, "timeout_secs": 60 }).to_string();
    let request = format!(
        "POST /api/v1/execute HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: Bearer st_update_key\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    raw
}

/// The `at_ms` of the first audit event of `kind`.
fn at_ms(device: &Device, kind: &str) -> u64 {
    std::fs::read_to_string(device.dir.path().join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["kind"] == kind)
        .and_then(|v| v["at_ms"].as_u64())
        .unwrap()
}

#[test]
fn a_device_busy_with_a_command_waits_for_it_to_finish() {
    let relay_dir = tempfile::tempdir().unwrap();
    let relay_port = reserved_port();
    let _relay = start_relay(relay_dir.path(), relay_port);
    let device = Device::new(relay_port, serve_release(), "300,0,20000");
    let api_port = reserved_port();

    let _first = device.start_on(true, api_port);
    // Started at once, before the device has even attached, so it is running
    // well before the release is staged; it holds the device busy for ~6 s.
    let long = if cfg!(windows) {
        "ping -n 7 127.0.0.1 >NUL"
    } else {
        "sleep 6"
    };
    let answer = execute(api_port, long);
    let finished_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    device.wait_for_kind("update.applying", Duration::from_secs(120));
    let available = at_ms(&device, "update.available");
    let applying = at_ms(&device, "update.applying");
    assert!(
        available < finished_ms,
        "the relay's version was not seen while the command ran — nothing was proven"
    );
    assert!(
        applying + 50 >= finished_ms,
        "the swap began {} ms before the command it would have cut off finished",
        finished_ms - applying
    );
}
