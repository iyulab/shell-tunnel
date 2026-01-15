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
    /// Disable rate limiting.
    pub no_rate_limit: bool,
    /// Log level (error, warn, info, debug, trace).
    pub log_level: Option<String>,
    /// Show version and exit.
    pub version: bool,
    /// Show help and exit.
    pub help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".parse().unwrap(),
            port: 3000,
            config: None,
            api_key: None,
            no_auth: false,
            no_rate_limit: false,
            log_level: None,
            version: false,
            help: false,
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
            Long("no-rate-limit") => {
                result.no_rate_limit = true;
            }
            Short('l') | Long("log-level") => {
                result.log_level = Some(parser.value()?.parse()?);
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
        --no-rate-limit     Disable rate limiting
    -h, --help              Print help
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
"#
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
        let result =
            parse_args_from(args(&["--host", "192.168.1.1", "--port", "9000"])).unwrap();
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
    fn test_no_rate_limit() {
        let result = parse_args_from(args(&["--no-rate-limit"])).unwrap();
        assert!(result.no_rate_limit);
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
