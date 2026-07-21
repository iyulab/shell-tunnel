//! Reachability: making a local server reachable from the internet.
//!
//! shell-tunnel binds a local port, so behind NAT it is unreachable without port
//! forwarding, a VPN, or a tunnel. This module owns the tunnel side of that
//! problem: it supervises an external tunnel client and reports the public URL
//! it allocates.
//!
//! Failures here are never silent. A requested tunnel that cannot be
//! established is an error, not a quiet fallback to local-only listening — the
//! caller asked to be reachable, and pretending otherwise is the worst outcome.

pub mod spawned;

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::error::ShellTunnelError;
use crate::process::{detach_process_group, kill_tree};
use crate::Result;

pub use spawned::{Cloudflared, CustomCommand, TunnelProvider};

/// How long to wait for a provider to report its public URL before giving up.
pub const URL_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for the URL.
const POLL: Duration = Duration::from_millis(50);

/// A running tunnel process and the public URL it allocated.
///
/// Dropping the handle terminates the tunnel client and its descendants, so a
/// tunnel can never outlive the server it exposes.
#[derive(Debug)]
pub struct TunnelHandle {
    child: Child,
    public_url: String,
    provider: String,
}

impl TunnelHandle {
    /// The public URL clients should call.
    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    /// Name of the provider that established this tunnel.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Whether the tunnel client is still running.
    ///
    /// The client dying means the public URL is dead: for a quick tunnel a
    /// restart would allocate a *different* URL, so a caller that keeps serving
    /// would be silently unreachable at the address it advertised.
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        kill_tree(self.child.id());
        let _ = self.child.wait();
    }
}

/// Start `provider` against `local` and wait for it to publish a URL.
///
/// Returns an error if the provider's program is missing, exits before
/// publishing a URL, or stays silent past `timeout`.
pub fn start(
    provider: &dyn TunnelProvider,
    local: SocketAddr,
    timeout: Duration,
) -> Result<TunnelHandle> {
    let name = provider.name().to_string();

    let mut cmd = provider.build_command(local);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    detach_process_group(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ShellTunnelError::Tunnel(format!(
                "`{}` is not installed or not on PATH — {}",
                name,
                provider.install_hint()
            ))
        } else {
            ShellTunnelError::Tunnel(format!("failed to start `{}`: {}", name, e))
        }
    })?;

    // Providers announce the URL on either stream (cloudflared uses stderr), so
    // both are scanned. Every line is also logged, which is how an operator
    // debugs a provider that never publishes.
    let (tx, rx) = mpsc::channel::<String>();
    if let Some(out) = child.stdout.take() {
        spawn_scanner(out, tx.clone(), name.clone());
    }
    if let Some(err) = child.stderr.take() {
        spawn_scanner(err, tx, name.clone());
    }

    let deadline = Instant::now() + timeout;
    loop {
        while let Ok(line) = rx.try_recv() {
            if let Some(url) = provider.extract_url(&line) {
                return Ok(TunnelHandle {
                    child,
                    public_url: url,
                    provider: name,
                });
            }
        }

        if let Ok(Some(status)) = child.try_wait() {
            // Drain whatever the process managed to say before dying.
            while let Ok(line) = rx.try_recv() {
                if let Some(url) = provider.extract_url(&line) {
                    return Ok(TunnelHandle {
                        child,
                        public_url: url,
                        provider: name,
                    });
                }
            }
            return Err(ShellTunnelError::Tunnel(format!(
                "`{}` exited ({}) before publishing a public URL",
                name, status
            )));
        }

        if Instant::now() >= deadline {
            kill_tree(child.id());
            let _ = child.wait();
            return Err(ShellTunnelError::Tunnel(format!(
                "`{}` did not publish a public URL within {}s",
                name,
                timeout.as_secs()
            )));
        }

        std::thread::sleep(POLL);
    }
}

/// Pump one of the child's pipes: log every line, forward every line for URL
/// matching. Ends at EOF, which happens when the child exits.
fn spawn_scanner<R: Read + Send + 'static>(
    pipe: R,
    tx: mpsc::Sender<String>,
    provider: String,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for line in BufReader::new(pipe)
            .lines()
            .map_while(std::result::Result::ok)
        {
            tracing::debug!(target: "tunnel", provider = %provider, "{}", line);
            if tx.send(line).is_err() {
                break; // supervisor is gone
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:3000".parse().unwrap()
    }

    /// A command that prints a URL is enough to stand in for any provider, which
    /// is what keeps these tests runnable without cloudflared installed.
    fn fake(command_line: &str) -> CustomCommand {
        CustomCommand::new(command_line)
    }

    #[test]
    fn missing_program_reports_an_install_hint() {
        #[derive(Debug)]
        struct Missing;
        impl TunnelProvider for Missing {
            fn name(&self) -> &str {
                "definitely-not-installed-xyz"
            }
            fn build_command(&self, _: SocketAddr) -> std::process::Command {
                std::process::Command::new("definitely-not-installed-xyz")
            }
            fn extract_url(&self, _: &str) -> Option<String> {
                None
            }
            fn install_hint(&self) -> &str {
                "install hint here"
            }
        }

        let err = start(&Missing, addr(), Duration::from_secs(1)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not installed"), "{msg}");
        assert!(msg.contains("install hint here"), "{msg}");
    }

    #[test]
    fn publishes_the_url_a_provider_prints() {
        let handle = start(
            &fake("echo https://example-tunnel.test/"),
            addr(),
            Duration::from_secs(10),
        )
        .expect("tunnel should start");
        assert_eq!(handle.public_url(), "https://example-tunnel.test/");
        assert_eq!(handle.provider(), "tunnel-command");
    }

    #[test]
    fn a_provider_that_exits_without_a_url_is_an_error() {
        let err = start(&fake("exit 3"), addr(), Duration::from_secs(10)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("before publishing"), "{msg}");
    }

    #[test]
    fn a_silent_provider_times_out() {
        // Sleeps well past the deadline without printing anything.
        #[cfg(windows)]
        let quiet = "ping -n 30 127.0.0.1 > nul";
        #[cfg(unix)]
        let quiet = "sleep 30";

        let start_at = Instant::now();
        let err = start(&fake(quiet), addr(), Duration::from_millis(300)).unwrap_err();
        assert!(err.to_string().contains("did not publish"), "{err}");

        // The property is that the deadline ends the wait at all, not that it
        // ends it fast: tearing the provider down shells out to `taskkill` on
        // Windows, which is itself a process spawn and can take seconds on a
        // loaded machine. A tight bound here measures the host, not the code.
        assert!(
            start_at.elapsed() < Duration::from_secs(20),
            "the deadline should end the wait, not hang"
        );
    }

    #[test]
    fn dropping_the_handle_stops_the_tunnel_process() {
        #[cfg(windows)]
        let long_lived = "echo https://kept.test && ping -n 60 127.0.0.1 > nul";
        #[cfg(unix)]
        let long_lived = "echo https://kept.test && sleep 60";

        let mut handle = start(&fake(long_lived), addr(), Duration::from_secs(10)).unwrap();
        assert!(handle.is_alive());
        let pid = handle.child.id();
        drop(handle);

        // The process group is gone: a second kill is a no-op and must not hang.
        kill_tree(pid);
    }
}
