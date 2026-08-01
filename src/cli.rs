//! Command-line interface for shell-tunnel.
//!
//! Uses lexopt for minimal binary size overhead (~34KB).

use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;

/// Command-line arguments.
#[derive(Debug, Clone)]
pub struct Args {
    /// Host address to bind to.
    pub host: IpAddr,
    /// Port to listen on.
    pub port: u16,
    /// Whether the port was stated rather than defaulted.
    ///
    /// A relay-attached device serves only itself on loopback, so the port is an
    /// implementation detail there — but only if the user did not ask for one.
    pub port_explicit: bool,
    /// Path to configuration file.
    pub config: Option<PathBuf>,
    /// API key for authentication (overrides config file).
    pub api_key: Option<String>,
    /// Disable authentication.
    pub no_auth: bool,
    /// Require authentication, auto-generating an API key if none is provided.
    pub require_auth: bool,
    /// Capability strings scoping the issued token(s) (empty = full-control).
    pub capabilities: Vec<String>,
    /// Role preset scoping the issued token(s) (operator/file-write/file-read/full-control).
    pub preset: Option<String>,
    /// Disable rate limiting.
    pub no_rate_limit: bool,
    /// Expose the server through a Cloudflare quick tunnel.
    pub tunnel: bool,
    /// Expose the server through an arbitrary tunnel command.
    pub tunnel_command: Option<String>,
    /// Run as a relay server (`shell-tunnel relay`) instead of a shell gateway.
    pub relay: bool,
    /// Attach to this relay instead of publishing through a tunnel.
    pub relay_url: Option<String>,
    /// Shared secret devices present to attach to this relay.
    pub enroll_token: Option<String>,
    /// Public base URL this relay is reachable at.
    pub public_base: Option<String>,
    /// Stable name to claim on the relay (keeps one URL across reconnects).
    pub device_name: Option<String>,
    /// PEM certificate chain for serving HTTPS directly.
    pub tls_cert: Option<PathBuf>,
    /// PEM private key matching `tls_cert`.
    pub tls_key: Option<PathBuf>,
    /// Generate a self-signed certificate when none is present.
    pub tls_self_signed: bool,
    /// Expect exactly this certificate fingerprint from the relay.
    pub relay_fingerprint: Option<String>,
    /// Extra PEM certificate authority to trust when dialling a relay.
    pub relay_ca: Option<PathBuf>,
    /// Additional host names this server answers to.
    pub allow_hosts: Vec<String>,
    /// Append an audit trail of executions and refusals to this file.
    pub audit_log: Option<PathBuf>,
    /// Directory the filesystem API is confined to. `None` disables the API.
    pub fs_root: Option<PathBuf>,
    /// Chunk size advertised to upload clients, in bytes.
    pub fs_chunk_size: Option<usize>,
    /// Rotate the audit trail once it passes this many bytes.
    pub audit_max_bytes: Option<u64>,
    /// Allow any CORS origin (permissive; opt-in for browser UIs).
    pub cors_allow_any: bool,
    /// Log level (error, warn, info, debug, trace).
    pub log_level: Option<String>,
    /// Show version and exit.
    pub version: bool,
    /// Show help and exit.
    pub help: bool,
    /// Check for updates and exit.
    pub check_update: bool,
    /// Perform self-update and exit.
    pub update: bool,
    /// Disable automatic update check on startup.
    pub no_update_check: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".parse().unwrap(),
            port: 3000,
            port_explicit: false,
            config: None,
            api_key: None,
            no_auth: false,
            require_auth: false,
            capabilities: Vec::new(),
            preset: None,
            no_rate_limit: false,
            tunnel: false,
            tunnel_command: None,
            relay: false,
            relay_url: None,
            enroll_token: None,
            public_base: None,
            device_name: None,
            tls_cert: None,
            tls_key: None,
            tls_self_signed: false,
            relay_fingerprint: None,
            relay_ca: None,
            allow_hosts: Vec::new(),
            audit_log: None,
            audit_max_bytes: None,
            fs_root: None,
            fs_chunk_size: None,
            cors_allow_any: false,
            log_level: None,
            version: false,
            help: false,
            check_update: false,
            update: false,
            no_update_check: false,
        }
    }
}

/// Parse command-line arguments.
pub fn parse_args() -> Result<Args, ArgsError> {
    parse_args_from(std::env::args_os())
}

/// Parse arguments from an iterator (for testing).
pub fn parse_args_from<I>(args: I) -> Result<Args, ArgsError>
where
    I: IntoIterator<Item = OsString>,
{
    use lexopt::prelude::*;

    let mut result = Args::default();
    let mut parser = lexopt::Parser::from_iter(args);

    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                result.help = true;
            }
            Short('V') | Long("version") => {
                result.version = true;
            }
            Short('H') | Long("host") => {
                let value: String = parser.value()?.parse()?;
                result.host = value
                    .parse()
                    .map_err(|_| ArgsError::InvalidValue("host", value))?;
            }
            Short('p') | Long("port") => {
                let value: String = parser.value()?.parse()?;
                result.port = value
                    .parse()
                    .map_err(|_| ArgsError::InvalidValue("port", value))?;
                result.port_explicit = true;
            }
            Short('c') | Long("config") => {
                result.config = Some(parser.value()?.parse()?);
            }
            Short('k') | Long("api-key") => {
                result.api_key = Some(parser.value()?.parse()?);
            }
            Long("no-auth") => {
                result.no_auth = true;
            }
            Long("require-auth") => {
                result.require_auth = true;
            }
            Long("capabilities") => {
                // Comma-separated; may be repeated. Accumulate non-empty entries.
                let value: String = parser.value()?.parse()?;
                result.capabilities.extend(
                    value
                        .split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                );
            }
            Long("preset") => {
                result.preset = Some(parser.value()?.parse()?);
            }
            Long("no-rate-limit") => {
                result.no_rate_limit = true;
            }
            Long("tunnel") => {
                result.tunnel = true;
            }
            Long("tunnel-command") => {
                result.tunnel_command = Some(parser.value()?.parse()?);
            }
            Long("relay") => {
                result.relay_url = Some(parser.value()?.parse()?);
            }
            Long("enroll-token") => {
                result.enroll_token = Some(parser.value()?.parse()?);
            }
            Long("public-base") => {
                result.public_base = Some(parser.value()?.parse()?);
            }
            Long("device-name") => {
                result.device_name = Some(parser.value()?.parse()?);
            }
            Long("tls-cert") => {
                result.tls_cert = Some(parser.value()?.parse()?);
            }
            Long("tls-key") => {
                result.tls_key = Some(parser.value()?.parse()?);
            }
            Long("tls-self-signed") => {
                result.tls_self_signed = true;
            }
            Long("relay-fingerprint") => {
                result.relay_fingerprint = Some(parser.value()?.parse()?);
            }
            Long("relay-ca") => {
                result.relay_ca = Some(parser.value()?.parse()?);
            }
            Long("allow-host") => {
                let value: String = parser.value()?.parse()?;
                result.allow_hosts.push(value);
            }
            Long("audit-log") => {
                result.audit_log = Some(parser.value()?.parse()?);
            }
            Long("audit-max-bytes") => {
                let value: String = parser.value()?.parse()?;
                result.audit_max_bytes = Some(
                    value
                        .parse()
                        .map_err(|_| ArgsError::InvalidValue("audit-max-bytes", value))?,
                );
            }
            Long("cors-allow-any") => {
                result.cors_allow_any = true;
            }
            Long("fs-root") => {
                result.fs_root = Some(parser.value()?.parse()?);
            }
            Long("fs-chunk-size") => {
                let value: String = parser.value()?.parse()?;
                result.fs_chunk_size = Some(
                    value
                        .parse()
                        .map_err(|_| ArgsError::InvalidValue("fs-chunk-size", value))?,
                );
            }
            Short('l') | Long("log-level") => {
                result.log_level = Some(parser.value()?.parse()?);
            }
            #[cfg(feature = "self-update")]
            Long("check-update") => {
                result.check_update = true;
            }
            #[cfg(feature = "self-update")]
            Long("update") => {
                result.update = true;
            }
            #[cfg(feature = "self-update")]
            Long("no-update-check") => {
                result.no_update_check = true;
            }
            // The only positional is the `relay` subcommand, which switches the
            // binary into relay-server mode. Bind address and port keep using
            // -H/-p so one CLI vocabulary covers both modes.
            Value(val) if val == "relay" && !result.relay => {
                result.relay = true;
            }
            Value(val) => {
                return Err(ArgsError::UnexpectedArgument(val.to_string_lossy().into()));
            }
            _ => return Err(arg.unexpected().into()),
        }
    }

    // A certificate without its key (or the reverse) cannot serve anything, and
    // silently falling back to plaintext would be the opposite of what was asked.
    if result.tls_cert.is_some() != result.tls_key.is_some() {
        return Err(ArgsError::Conflicting("--tls-cert", "--tls-key"));
    }

    // `--tls-self-signed` needs no paths; naming them just says where to put it.
    if result.tls_self_signed && result.tls_cert.is_none() {
        let defaults = (
            std::path::PathBuf::from("shell-tunnel-cert.pem"),
            std::path::PathBuf::from("shell-tunnel-key.pem"),
        );
        result.tls_cert = Some(defaults.0);
        result.tls_key = Some(defaults.1);
    }

    // Relay mode serves devices, not shells: a tunnel would publish the wrong
    // thing entirely.
    if result.relay && (result.tunnel || result.tunnel_command.is_some()) {
        return Err(ArgsError::Conflicting("relay", "--tunnel"));
    }
    if result.relay_url.is_some() && result.tunnel {
        return Err(ArgsError::Conflicting("--relay", "--tunnel"));
    }
    if result.relay_url.is_some() && result.tunnel_command.is_some() {
        return Err(ArgsError::Conflicting("--relay", "--tunnel-command"));
    }

    // Reachability paths are mutually exclusive: two tunnels would each publish
    // a different public URL for the same server, and only one can be reported.
    if result.tunnel && result.tunnel_command.is_some() {
        return Err(ArgsError::Conflicting("--tunnel", "--tunnel-command"));
    }

    Ok(result)
}

/// Print help message.
pub fn print_help() {
    let version = env!("CARGO_PKG_VERSION");

    // Update flags exist only when compiled with the `self-update` feature.
    #[cfg(feature = "self-update")]
    let update_opts = "        --check-update      Check for updates and exit\n        --update            Download and install latest version\n        --no-update-check   Disable automatic update check on startup\n";
    #[cfg(not(feature = "self-update"))]
    let update_opts = "";

    #[cfg(feature = "self-update")]
    let update_examples = "\n    # Check for updates\n    shell-tunnel --check-update\n\n    # Self-update to latest version\n    shell-tunnel --update\n";
    #[cfg(not(feature = "self-update"))]
    let update_examples = "";

    println!(
        r#"shell-tunnel {version}
Ultra-lightweight remote shell gateway with a REST/WebSocket API

USAGE:
    shell-tunnel [OPTIONS]              Serve a shell gateway
    shell-tunnel relay [OPTIONS]        Serve a relay that devices dial out to

OPTIONS:
    -H, --host <ADDR>       Host address to bind [default: 127.0.0.1]
    -p, --port <PORT>       Port to listen on [default: 3000]
    -c, --config <FILE>     Path to configuration file (JSON)
    -k, --api-key <KEY>     API key callers present to run commands here
    -l, --log-level <LVL>   Log level (error, warn, info, debug, trace)
        --no-auth           Disable authentication (refused when reachable)
        --require-auth      Require auth, auto-generating an API key if none given
        --capabilities <C>  Scope issued token(s): comma-separated capabilities
                            (e.g. exec,session.read). Default: full-control, or
                            operator when the server is reachable
        --preset <NAME>     Scope issued token(s) by role preset
                            (operator | file-write | file-read | full-control)
        --no-rate-limit     Disable rate limiting
        --tunnel            Expose publicly via a Cloudflare quick tunnel
                            (requires `cloudflared`; implies authentication)
        --tunnel-command <C>
                            Expose publicly by running an arbitrary tunnel
                            command (ngrok, bore, frp, ...); its printed URL
                            is used. Implies authentication
        --relay <URL>       Attach to a self-hosted relay (dial out, no inbound
                            port). Needs the relay's --enroll-token; implies
                            authentication. The local port is chosen for you
                            unless -p says otherwise
        --device-name <N>   Claim a stable name on the relay, so the device URL
                            survives reconnects [default: this machine's name]
        --allow-host <HOST> Also answer to this host name. A loopback-bound
                            server otherwise answers only to localhost, which is
                            what stops DNS rebinding. Repeatable
        --audit-log <FILE>  Append every execution and refusal to this file
                            (JSON per line; the token itself is never written)
                            [default: off; shell-tunnel-audit.jsonl when reachable]
        --audit-max-bytes <N>
                            Rotate the audit trail to <FILE>.1 past this size
                            [default: unbounded]
        --cors-allow-any    Allow any CORS origin (opt-in; for browser UIs)
        --fs-root <PATH>    Confine the file API to this directory. Without it
                            the API reaches everything this account can
        --fs-chunk-size <N> Upload chunk size in bytes (default 4194304)

TLS OPTIONS (serve HTTPS directly, no reverse proxy needed):
        --tls-self-signed   Serve HTTPS with a self-signed certificate,
                            generating one on first run and reusing it after.
                            Needs no paths; devices trust it with --relay-ca
        --tls-cert <FILE>   PEM certificate chain [default with --tls-self-signed:
                            shell-tunnel-cert.pem]
        --tls-key <FILE>    PEM private key matching the certificate
        --relay-fingerprint <FP>
                            Expect exactly this certificate from the relay, as
                            printed by `shell-tunnel relay --tls-self-signed`.
                            Nothing to copy but the string, and the certificate
                            need not name the address being dialled
        --relay-ca <FILE>   Also trust this PEM authority when dialling a relay
                            (the alternative to a fingerprint, for a private CA)

RELAY OPTIONS (with `relay`):
        --enroll-token <T>  Secret devices present to attach to this relay
                            (generated if unset). Distinct from --api-key, which
                            is what callers present to a device
        --public-base <URL> Public base URL of this relay. A URL with no port
                            uses this relay's listen port; name a port only when
                            a proxy remaps it [default: http://<bind address>]
{update_opts}    -h, --help              Print help
    -V, --version           Print version

ENVIRONMENT VARIABLES:
    SHELL_TUNNEL_HOST       No effect: -H sets the bind address on every start
    SHELL_TUNNEL_PORT       No effect: -p sets the port on every start
    SHELL_TUNNEL_API_KEY    Adds an API key and turns auth on. Keys from the
                            config file stay valid alongside it
    SHELL_TUNNEL_LOG_LEVEL  Log level (overrides config)
    RUST_LOG                Alternative log level setting

EXAMPLES:
    # Start with defaults (localhost:3000, no auth)
    shell-tunnel

    # Start on all interfaces with API key
    shell-tunnel -H 0.0.0.0 -p 8080 -k my-secret-key

    # Start with config file
    shell-tunnel -c /etc/shell-tunnel/config.json

    # Development mode (no security)
    shell-tunnel --no-auth --no-rate-limit

    # Publish on the internet with a generated key (no account needed)
    shell-tunnel --tunnel

    # Publish using a different tunnel client
    shell-tunnel --tunnel-command "ngrok http 3000"

    # Attach to a relay under a stable name
    shell-tunnel --relay https://relay.example.com --enroll-token <t> --device-name box

    # Run a relay with HTTPS, generating a certificate on first run.
    # --public-base names the host; the URL uses this relay's port (8443).
    shell-tunnel relay -H 0.0.0.0 -p 8443 --tls-self-signed --public-base https://relay.example.com

    # Behind a proxy that forwards 443 here, name the port devices dial
    shell-tunnel relay -H 0.0.0.0 -p 8443 --public-base https://relay.example.com:443

    # Issue a token that can only read files, confined to one directory
    shell-tunnel -k readonly-key --preset file-read --fs-root /srv/deploy

    # Issue a token scoped to specific capabilities
    shell-tunnel -k ci-key --capabilities exec,session.read
{update_examples}"#
    );
}

/// Print version.
pub fn print_version() {
    println!("shell-tunnel {}", env!("CARGO_PKG_VERSION"));
}

/// Argument parsing errors.
#[derive(Debug)]
pub enum ArgsError {
    /// Lexopt parsing error.
    Lexopt(lexopt::Error),
    /// Invalid argument value.
    InvalidValue(&'static str, String),
    /// Unexpected positional argument.
    UnexpectedArgument(String),
    /// Two mutually exclusive flags were given.
    Conflicting(&'static str, &'static str),
}

impl std::fmt::Display for ArgsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lexopt(e) => write!(f, "{}", e),
            Self::InvalidValue(name, value) => {
                write!(f, "invalid value for --{}: '{}'", name, value)
            }
            Self::UnexpectedArgument(arg) => {
                write!(f, "unexpected argument: '{}'", arg)
            }
            Self::Conflicting(a, b) if a.starts_with("--tls") => {
                write!(f, "{} and {} must be given together", a, b)
            }
            Self::Conflicting(a, b) => {
                write!(f, "{} and {} cannot be used together", a, b)
            }
        }
    }
}

impl std::error::Error for ArgsError {}

impl From<lexopt::Error> for ArgsError {
    fn from(e: lexopt::Error) -> Self {
        Self::Lexopt(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(args: &[&str]) -> Vec<OsString> {
        std::iter::once("shell-tunnel")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn test_default_args() {
        let result = parse_args_from(args(&[])).unwrap();
        assert_eq!(result.host.to_string(), "127.0.0.1");
        assert_eq!(result.port, 3000);
        assert!(!result.no_auth);
    }

    #[test]
    fn test_host_port() {
        let result = parse_args_from(args(&["-H", "0.0.0.0", "-p", "8080"])).unwrap();
        assert_eq!(result.host.to_string(), "0.0.0.0");
        assert_eq!(result.port, 8080);
    }

    #[test]
    fn test_long_options() {
        let result = parse_args_from(args(&["--host", "192.168.1.1", "--port", "9000"])).unwrap();
        assert_eq!(result.host.to_string(), "192.168.1.1");
        assert_eq!(result.port, 9000);
    }

    #[test]
    fn test_api_key() {
        let result = parse_args_from(args(&["-k", "my-secret"])).unwrap();
        assert_eq!(result.api_key, Some("my-secret".to_string()));
    }

    #[test]
    fn test_config_file() {
        let result = parse_args_from(args(&["-c", "/etc/config.json"])).unwrap();
        assert_eq!(result.config, Some(PathBuf::from("/etc/config.json")));
    }

    #[test]
    fn test_no_auth() {
        let result = parse_args_from(args(&["--no-auth"])).unwrap();
        assert!(result.no_auth);
    }

    #[test]
    fn test_require_auth() {
        let result = parse_args_from(args(&["--require-auth"])).unwrap();
        assert!(result.require_auth);
        assert!(!Args::default().require_auth);
    }

    #[test]
    fn test_no_rate_limit() {
        let result = parse_args_from(args(&["--no-rate-limit"])).unwrap();
        assert!(result.no_rate_limit);
    }

    #[test]
    fn test_capabilities_csv() {
        let result = parse_args_from(args(&["--capabilities", "exec,session.read"])).unwrap();
        assert_eq!(result.capabilities, vec!["exec", "session.read"]);
        assert!(Args::default().capabilities.is_empty());
    }

    #[test]
    fn test_capabilities_trims_and_ignores_blanks() {
        let result = parse_args_from(args(&["--capabilities", " exec , , session.read "])).unwrap();
        assert_eq!(result.capabilities, vec!["exec", "session.read"]);
    }

    #[test]
    fn test_capabilities_repeated_accumulate() {
        let result = parse_args_from(args(&[
            "--capabilities",
            "exec",
            "--capabilities",
            "session.read,session.manage",
        ]))
        .unwrap();
        assert_eq!(
            result.capabilities,
            vec!["exec", "session.read", "session.manage"]
        );
    }

    #[test]
    fn test_preset() {
        let result = parse_args_from(args(&["--preset", "operator"])).unwrap();
        assert_eq!(result.preset, Some("operator".to_string()));
        assert!(Args::default().preset.is_none());
    }

    #[test]
    fn test_help_flag() {
        let result = parse_args_from(args(&["-h"])).unwrap();
        assert!(result.help);

        let result = parse_args_from(args(&["--help"])).unwrap();
        assert!(result.help);
    }

    #[test]
    fn test_version_flag() {
        let result = parse_args_from(args(&["-V"])).unwrap();
        assert!(result.version);

        let result = parse_args_from(args(&["--version"])).unwrap();
        assert!(result.version);
    }

    #[test]
    fn test_log_level() {
        let result = parse_args_from(args(&["-l", "debug"])).unwrap();
        assert_eq!(result.log_level, Some("debug".to_string()));
    }

    #[test]
    fn test_invalid_port() {
        let result = parse_args_from(args(&["-p", "invalid"]));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_host() {
        let result = parse_args_from(args(&["-H", "not-an-ip"]));
        assert!(result.is_err());
    }

    #[test]
    fn test_combined_options() {
        let result = parse_args_from(args(&[
            "-H",
            "0.0.0.0",
            "-p",
            "8080",
            "-k",
            "secret",
            "-l",
            "debug",
            "--no-rate-limit",
        ]))
        .unwrap();

        assert_eq!(result.host.to_string(), "0.0.0.0");
        assert_eq!(result.port, 8080);
        assert_eq!(result.api_key, Some("secret".to_string()));
        assert_eq!(result.log_level, Some("debug".to_string()));
        assert!(result.no_rate_limit);
        assert!(!result.no_auth);
    }

    #[test]
    fn test_tunnel_flag() {
        let result = parse_args_from(vec![
            OsString::from("shell-tunnel"),
            OsString::from("--tunnel"),
        ])
        .unwrap();
        assert!(result.tunnel);
        assert!(result.tunnel_command.is_none());
    }

    #[test]
    fn test_tunnel_command_flag() {
        let result = parse_args_from(vec![
            OsString::from("shell-tunnel"),
            OsString::from("--tunnel-command"),
            OsString::from("ngrok http 3000"),
        ])
        .unwrap();
        assert_eq!(result.tunnel_command.as_deref(), Some("ngrok http 3000"));
        assert!(!result.tunnel);
    }

    #[test]
    fn test_tunnel_paths_are_mutually_exclusive() {
        let err = parse_args_from(vec![
            OsString::from("shell-tunnel"),
            OsString::from("--tunnel"),
            OsString::from("--tunnel-command"),
            OsString::from("bore local 3000 --to bore.pub"),
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--tunnel"), "{msg}");
        assert!(msg.contains("cannot be used together"), "{msg}");
    }

    #[test]
    fn test_no_tunnel_by_default() {
        let result = parse_args_from(vec![OsString::from("shell-tunnel")]).unwrap();
        assert!(!result.tunnel);
        assert!(result.tunnel_command.is_none());
    }
}
