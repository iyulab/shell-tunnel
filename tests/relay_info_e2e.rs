//! A relay device reports the relay it is attached to, driven through the real
//! binary on both sides.
//!
//! The relay's version reaches a device in its enrolment answer and nowhere
//! else — the relay publishes it to no caller. A fix split between a relay and
//! a device works only when both halves are at its version, so a caller that
//! cannot see the relay's cannot tell whether a fix is in place. The device
//! hands it on in `GET /api/v1`.
//!
//! The link that needs the binary is the one in `main.rs`, where the relay
//! client's attach event is written into the state the handler reads. A handler
//! test can be green while nothing writes that state.

#![cfg(feature = "relay-client")]

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_shell-tunnel");
const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port from a window no other test binary hands out from.
fn reserved_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(23_600);
    loop {
        let port = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(port < 23_700, "no free port in the window");
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// `GET /api/v1` on the device's own API, or `None` while it is not up.
fn api_info(port: u16) -> Option<serde_json::Value> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    let request = "GET /api/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
                   Authorization: Bearer st_info_key\r\n\r\n";
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    let body = raw.split_once("\r\n\r\n")?.1;
    serde_json::from_str(body).ok()
}

#[test]
fn a_device_reports_the_version_of_the_relay_it_enrolled_with() {
    let dir = tempfile::tempdir().unwrap();
    let relay_port = reserved_port();
    let _relay = Killed(
        Command::new(BIN)
            .current_dir(dir.path())
            .args([
                "relay",
                "--host",
                "127.0.0.1",
                "--port",
                &relay_port.to_string(),
                "--enroll-token",
                "st_info",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("relay should start"),
    );

    let device_port = reserved_port();
    let _device = Killed(
        Command::new(BIN)
            .current_dir(dir.path())
            .args([
                "--relay",
                &format!("ws://127.0.0.1:{relay_port}"),
                "--enroll-token",
                "st_info",
                "--device-name",
                "info",
                "--port",
                &device_port.to_string(),
                "-k",
                "st_info_key",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("device should start"),
    );

    // The local API comes up before the device has enrolled, and answers
    // without `relay` until it has; wait for the enrolment rather than for
    // the port.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = None;
    let info = loop {
        if let Some(info) = api_info(device_port) {
            if info.get("relay").is_some() {
                break info;
            }
            last = Some(info);
        }
        assert!(
            Instant::now() < deadline,
            "the device never reported a relay; its last answer: {last:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    assert_eq!(info["version"], VERSION, "{info}");
    assert_eq!(info["relay"]["version"], VERSION, "{info}");
    assert!(
        info["relay"]["enrolled_at_ms"].as_u64().unwrap() > 0,
        "{info}"
    );
}
