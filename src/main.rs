//! Shell-tunnel binary entry point.

use shell_tunnel::{api::serve, logging, parse_args, print_help, print_version, Config};
use tracing::info;

#[tokio::main]
async fn main() -> shell_tunnel::Result<()> {
    // Parse command-line arguments
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Use --help for usage information");
            std::process::exit(1);
        }
    };

    // Handle help and version flags
    if args.help {
        print_help();
        return Ok(());
    }

    if args.version {
        print_version();
        return Ok(());
    }

    // Load configuration
    let config = match Config::load(&args) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize logging with configured level
    std::env::set_var("RUST_LOG", config.log_filter());
    logging::init();

    info!("shell-tunnel v{}", env!("CARGO_PKG_VERSION"));

    // Convert to server config
    let server_config = match config.to_server_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Start the server
    info!(
        "Starting server on {}:{}",
        server_config.host, server_config.port
    );

    serve(server_config).await
}
