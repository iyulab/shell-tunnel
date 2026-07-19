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
    /// Role preset scoping the issued token(s) (operator/read-only/full-control).
    pub preset: Option<String>,
    /// Disable rate limiting.
    pub no_rate_limit: bool,
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
            config: None,
            api_key: None,
            no_auth: false,
            require_auth: false,
            capabilities: Vec::new(),
            preset: None,
            no_rate_limit: false,
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
            Long("cors-allow-any") => {
                result.cors_allow_any = true;
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
            Value(val) => {
                return Err(ArgsError::UnexpectedArgument(val.to_string_lossy().into()));
            }
            _ => return Err(arg.unexpected().into()),
        }
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
Ultra-lightweight shell tunnel for AI agent integration

USAGE:
    shell-tunnel [OPTIONS]

OPTIONS:
    -H, --host <ADDR>       Host address to bind [default: 127.0.0.1]
    -p, --port <PORT>       Port to listen on [default: 3000]
    -c, --config <FILE>     Path to configuration file (JSON)
    -k, --api-key <KEY>     API key for authentication
    -l, --log-level <LVL>   Log level (error, warn, info, debug, trace)
        --no-auth           Disable authentication
        --require-auth      Require auth, auto-generating an API key if none given
        --capabilities <C>  Scope issued token(s): comma-separated capabilities
                            (e.g. exec,session.read). Default: full-control
        --preset <NAME>     Scope issued token(s) by role preset
                            (operator | read-only | full-control)
        --no-rate-limit     Disable rate limiting
        --cors-allow-any    Allow any CORS origin (opt-in; for browser UIs)
{update_opts}    -h, --help              Print help
    -V, --version           Print version

ENVIRONMENT VARIABLES:
    SHELL_TUNNEL_HOST       Host address (overrides config)
    SHELL_TUNNEL_PORT       Port number (overrides config)
    SHELL_TUNNEL_API_KEY    API key (overrides config)
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

    # Issue a fine-grained, read-only token
    shell-tunnel -k readonly-key --preset read-only

    # Issue a token scoped to specific capabilities
    shell-tunnel -k agent-key --capabilities exec,session.read
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
}
