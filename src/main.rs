//! Shell-tunnel binary entry point.

use shell_tunnel::{api::serve, logging, parse_args, print_help, print_version, update, Config};
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

    // Handle update commands
    if args.check_update {
        match update::check_update() {
            Ok(info) => {
                println!("Current version: {}", info.current);
                println!("Latest version:  {}", info.latest);
                if info.update_available {
                    println!("\nUpdate available! Run with --update to install.");
                } else {
                    println!("\nYou are running the latest version.");
                }
            }
            Err(e) => {
                eprintln!("Failed to check for updates: {}", e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    if args.update {
        println!("Checking for updates...");
        match update::self_update() {
            Ok(true) => {
                println!("Successfully updated! Please restart shell-tunnel.");
            }
            Ok(false) => {
                println!("Already running the latest version.");
            }
            Err(e) => {
                eprintln!("Update failed: {}", e);
                std::process::exit(1);
            }
        }
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

    // Background update check (unless disabled)
    if !args.no_update_check {
        update::background_update_check();
    }

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
