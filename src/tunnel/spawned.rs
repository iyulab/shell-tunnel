//! Tunnel providers that run as an external process.
//!
//! A provider is described purely as a *process spec*: how to invoke it, and how
//! to recognise the public URL in its output. shell-tunnel never links a tunnel
//! client — the core build stays dependency-free and the 40MB-class Go binaries
//! (cloudflared) are neither vendored nor downloaded.

use std::net::SocketAddr;
use std::process::Command as OsCommand;

use crate::process::shell_command;

/// How to run one external tunnel client and read its public URL.
///
/// `Debug` is required so a provider can be reported in errors and logs
/// (and so `Result`s carrying one can be asserted on in tests).
pub trait TunnelProvider: std::fmt::Debug + Send + Sync {
    /// Human-readable provider name, used in logs and error messages.
    fn name(&self) -> &str;

    /// Build the command that exposes `local` to the internet.
    fn build_command(&self, local: SocketAddr) -> OsCommand;

    /// Recognise the public URL in one line of the provider's output.
    fn extract_url(&self, line: &str) -> Option<String>;

    /// What to tell the user when the program is not installed.
    fn install_hint(&self) -> &str;
}

/// Cloudflare quick tunnel (`cloudflared tunnel --url …`).
///
/// Quick tunnels need no Cloudflare account, which is what makes "just run it"
/// possible. Cloudflare documents them as **testing/development only**: no SLA,
/// a random URL that changes on every restart, and a 200 concurrent in-flight
/// request cap. Those limits are stated in the user-facing docs rather than
/// papered over here.
#[derive(Debug, Default, Clone, Copy)]
pub struct Cloudflared;

/// Host suffix a Cloudflare quick tunnel always allocates under.
const TRYCLOUDFLARE_SUFFIX: &str = ".trycloudflare.com";

impl TunnelProvider for Cloudflared {
    fn name(&self) -> &str {
        "cloudflared"
    }

    fn build_command(&self, local: SocketAddr) -> OsCommand {
        let mut cmd = OsCommand::new("cloudflared");
        cmd.arg("tunnel")
            .arg("--url")
            .arg(format!("http://{}", local))
            // The tunnel's lifetime is ours; let it never self-update mid-run.
            .arg("--no-autoupdate");
        cmd
    }

    fn extract_url(&self, line: &str) -> Option<String> {
        find_url(line, |url| {
            url.strip_prefix("https://")
                .and_then(|host| host.split('/').next())
                .is_some_and(|host| host.ends_with(TRYCLOUDFLARE_SUFFIX))
        })
    }

    fn install_hint(&self) -> &str {
        "install it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ \
         (or use --tunnel-command to drive a different tunnel client)"
    }
}

/// An arbitrary user-supplied tunnel command (`--tunnel-command "<cmd>"`).
///
/// The escape hatch for ngrok, bore, frp, or anything else: shell-tunnel does
/// not need to know the tool, only that it prints a URL. The command runs
/// through the platform shell so a full command line works as typed.
#[derive(Debug, Clone)]
pub struct CustomCommand {
    command_line: String,
}

impl CustomCommand {
    /// Wrap a user-supplied command line.
    pub fn new(command_line: impl Into<String>) -> Self {
        Self {
            command_line: command_line.into(),
        }
    }
}

impl TunnelProvider for CustomCommand {
    fn name(&self) -> &str {
        "tunnel-command"
    }

    fn build_command(&self, local: SocketAddr) -> OsCommand {
        // The local address is exported rather than substituted: a command line
        // stays copy-pasteable from the provider's own docs, and callers that
        // need the port can reference the variable.
        let mut cmd = shell_command(&self.command_line);
        cmd.env("SHELL_TUNNEL_LOCAL_ADDR", local.to_string());
        cmd.env("SHELL_TUNNEL_LOCAL_PORT", local.port().to_string());
        cmd
    }

    fn extract_url(&self, line: &str) -> Option<String> {
        find_url(line, |_| true)
    }

    fn install_hint(&self) -> &str {
        "check that the command exists and is on PATH"
    }
}

/// Find the first `http(s)://…` token in `line` that satisfies `accept`.
///
/// Providers frame their URLs in decorative boxes (`|  https://x  |`), so the
/// token is cut at whitespace and common framing characters, then stripped of
/// trailing punctuation.
fn find_url(line: &str, accept: impl Fn(&str) -> bool) -> Option<String> {
    let mut rest = line;
    loop {
        let start = rest
            .find("http://")
            .into_iter()
            .chain(rest.find("https://"))
            .min()?;
        let candidate = &rest[start..];
        let end = candidate
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '|' | '"' | '\'' | '<' | '>' | ')' | ',')
            })
            .unwrap_or(candidate.len());
        let url = candidate[..end].trim_end_matches(['.', ';', ':']);
        if !url.is_empty() && accept(url) {
            return Some(url.to_string());
        }
        rest = &rest[start + 4..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:3000".parse().unwrap()
    }

    #[test]
    fn cloudflared_command_points_at_the_local_server() {
        let cmd = Cloudflared.build_command(addr());
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(cmd.get_program().to_string_lossy(), "cloudflared");
        assert!(args.contains(&"--url".to_string()));
        assert!(args.contains(&"http://127.0.0.1:3000".to_string()));
        assert!(args.contains(&"--no-autoupdate".to_string()));
    }

    #[test]
    fn cloudflared_extracts_the_boxed_quick_tunnel_url() {
        // Shape of the real banner cloudflared prints on stderr.
        let line = "|  https://caring-brave-fox-mint.trycloudflare.com                       |";
        assert_eq!(
            Cloudflared.extract_url(line).as_deref(),
            Some("https://caring-brave-fox-mint.trycloudflare.com")
        );
    }

    #[test]
    fn cloudflared_extracts_url_from_a_log_line() {
        let line = "2026-07-21T03:20:56Z INF +--------------------+ url=https://foo-bar-baz.trycloudflare.com";
        assert_eq!(
            Cloudflared.extract_url(line).as_deref(),
            Some("https://foo-bar-baz.trycloudflare.com")
        );
    }

    #[test]
    fn cloudflared_ignores_unrelated_urls() {
        // Its own docs/telemetry links must not be mistaken for the tunnel URL.
        let line = "INF Thank you for trying Cloudflare Tunnel. See https://developers.cloudflare.com/cloudflare-one/";
        assert!(Cloudflared.extract_url(line).is_none());
        assert!(Cloudflared
            .extract_url("INF Requesting new quick Tunnel on trycloudflare.com...")
            .is_none());
    }

    #[test]
    fn custom_command_accepts_any_url() {
        let p = CustomCommand::new("ngrok http 3000");
        assert_eq!(
            p.extract_url("Forwarding  https://1a2b.ngrok-free.app -> http://localhost:3000")
                .as_deref(),
            Some("https://1a2b.ngrok-free.app")
        );
        assert_eq!(
            p.extract_url("listening at bore.pub:41234").as_deref(),
            None
        );
    }

    #[test]
    fn custom_command_exports_the_local_address() {
        let cmd = CustomCommand::new("echo hi").build_command(addr());
        let envs: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert!(envs.contains(&("SHELL_TUNNEL_LOCAL_PORT".to_string(), "3000".to_string())));
        assert!(envs.contains(&(
            "SHELL_TUNNEL_LOCAL_ADDR".to_string(),
            "127.0.0.1:3000".to_string()
        )));
    }

    #[test]
    fn urls_are_trimmed_of_framing_and_punctuation() {
        let p = CustomCommand::new("x");
        assert_eq!(
            p.extract_url("see https://example.com/a.").as_deref(),
            Some("https://example.com/a")
        );
        assert_eq!(
            p.extract_url("<https://example.com/b>").as_deref(),
            Some("https://example.com/b")
        );
    }

    #[test]
    fn lines_without_a_url_yield_none() {
        let p = CustomCommand::new("x");
        assert!(p.extract_url("").is_none());
        assert!(p.extract_url("starting up, no address yet").is_none());
        assert!(p.extract_url("http").is_none());
    }
}
