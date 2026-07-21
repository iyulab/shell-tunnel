//! Shell-tunnel binary entry point.

use std::net::SocketAddr;
use std::time::Duration;

use shell_tunnel::config::PublicExposure;
use shell_tunnel::relay::{serve_relay, RelayConfig};
use shell_tunnel::tunnel::{self, TunnelHandle};
use shell_tunnel::{logging, parse_args, print_help, print_version, Args, Config};
use tracing::{info, warn};

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

    // Handle update commands (only compiled with the `self-update` feature)
    #[cfg(feature = "self-update")]
    {
        use shell_tunnel::update;

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
    }

    // Relay mode serves devices rather than shells, so it shares only the
    // bind/logging vocabulary with the gateway and returns before any of the
    // gateway's own configuration is resolved.
    if args.relay {
        return run_relay(&args).await;
    }

    // Load configuration
    let mut config = match Config::load(&args) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // A tunnel makes this server internet-facing, which changes what the
    // configuration is allowed to be. Resolved before logging starts so a
    // refusal (e.g. --no-auth) is reported plainly rather than as a log line.
    let provider = match config.tunnel_provider() {
        Ok(provider) => provider,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };
    // Attaching to a relay publishes this machine just as a tunnel does, so it
    // goes through the same hardening rather than a parallel set of rules.
    let public = provider.is_some() || args.relay_url.is_some();
    let exposure = if public {
        match config.harden_for_public_exposure(&args) {
            Ok(exposure) => exposure,
            Err(e) => {
                eprintln!("Configuration error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        PublicExposure::default()
    };

    if args.relay_url.is_some() && args.enroll_token.is_none() {
        eprintln!("Configuration error: --relay requires --enroll-token");
        std::process::exit(1);
    }

    // Serving TLS is a relay-mode capability. Ignoring the flag here would start
    // a plaintext server for someone who asked for an encrypted one — the exact
    // silent failure every other path in this binary refuses to make.
    if args.tls_cert.is_some() {
        eprintln!("Configuration error: --tls-cert/--tls-key apply to `shell-tunnel relay`.");
        eprintln!("A gateway is reached through a tunnel or a relay, which carry their own TLS;");
        eprintln!("to expose one directly, put a reverse proxy in front.");
        std::process::exit(1);
    }
    #[cfg(not(feature = "relay-client"))]
    if args.relay_url.is_some() {
        eprintln!("Configuration error: this build has no relay client.");
        eprintln!("Rebuild with `--features relay-client`, or use --tunnel.");
        std::process::exit(1);
    }

    // Initialize logging with configured level
    std::env::set_var("RUST_LOG", config.log_filter());
    logging::init();

    info!("shell-tunnel v{}", env!("CARGO_PKG_VERSION"));

    // Background update check (unless disabled; only with the `self-update` feature)
    #[cfg(feature = "self-update")]
    if !args.no_update_check {
        shell_tunnel::update::background_update_check();
    }

    // Convert to server config
    let allowed_hosts = config.allowed_hosts(&args, public);
    let server_config = match config.to_server_config() {
        Ok(mut c) => {
            if let Some(hosts) = allowed_hosts {
                c.security = c.security.with_allowed_hosts(hosts);
            }
            c
        }
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // The bound address is logged once the listener exists, by `serve`. Saying
    // it here would be a guess: attaching to a relay lets the OS choose the
    // port, so this line used to announce 3000 while the server bound something
    // else entirely.

    // Opened before serving so a path that cannot be written stops startup,
    // rather than leaving an operator believing there is a trail.
    let audit = match &args.audit_log {
        Some(path) => {
            match shell_tunnel::audit::AuditSink::file_with_limit(path, args.audit_max_bytes) {
                Ok(sink) => std::sync::Arc::new(sink),
                Err(e) => {
                    eprintln!("Configuration error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        None => std::sync::Arc::new(shell_tunnel::audit::AuditSink::Disabled),
    };
    if audit.is_enabled() {
        info!(
            "audit trail: {}",
            args.audit_log.as_ref().unwrap().display()
        );
    }
    let state = shell_tunnel::AppState::new().with_audit(audit);

    #[cfg(feature = "relay-client")]
    if let Some(relay_url) = args.relay_url.clone() {
        return run_with_relay(server_config, &args, relay_url, exposure, state).await;
    }

    let Some(provider) = provider else {
        return shell_tunnel::api::serve_with_state(server_config, state).await;
    };

    let local: SocketAddr = server_config
        .bind_address()
        .parse()
        .expect("bind address is built from a parsed IpAddr and a u16 port");
    let server = tokio::spawn(shell_tunnel::api::serve_with_state(server_config, state));

    // Open the tunnel only once the port actually accepts, so the provider is
    // not racing the listener and reporting connection failures.
    wait_until_listening(local, Duration::from_secs(5)).await;

    let mut tunnel = match tokio::task::spawn_blocking(move || {
        tunnel::start(provider.as_ref(), local, tunnel::URL_TIMEOUT)
    })
    .await
    .expect("tunnel supervisor task panicked")
    {
        Ok(handle) => handle,
        Err(e) => {
            // The caller asked to be reachable. Serving local-only while
            // reporting success would be the worst possible outcome.
            // `ShellTunnelError::Tunnel` already renders as "tunnel error: …";
            // prefixing it again would stutter.
            eprintln!("{}", e);
            server.abort();
            std::process::exit(1);
        }
    };

    for warning in &exposure.warnings {
        warn!("{}", warning);
    }
    print_banner(&tunnel, exposure.generated_key.as_deref());

    // Supervise: if the tunnel client dies, the advertised URL is dead with it
    // (a restart would allocate a different one), so the server goes down too
    // rather than staying up at an address nobody can reach.
    tokio::select! {
        result = server => result.expect("server task panicked"),
        () = tunnel_died(&mut tunnel) => {
            eprintln!("Tunnel closed: the public URL is no longer reachable. Shutting down.");
            std::process::exit(1);
        }
    }
}

/// Run the relay server.
///
/// The enrollment token is generated when unset, mirroring the gateway's API
/// key: an operator can start a working relay with one command, and the secret
/// they need is printed rather than assumed.
async fn run_relay(args: &Args) -> shell_tunnel::Result<()> {
    let bind = SocketAddr::new(args.host, args.port);

    let (enroll_token, generated) = match &args.enroll_token {
        Some(token) => (token.clone(), false),
        None => (shell_tunnel::security::generate_api_key(), true),
    };

    let mut config = RelayConfig::new(bind, &enroll_token);
    if let Some(base) = &args.public_base {
        config = config.with_public_base(base);
    }
    if args.no_rate_limit {
        config = config.without_rate_limit();
    }
    #[cfg(feature = "tls")]
    let mut generated_cert = false;
    #[cfg(feature = "tls")]
    if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
        let files = shell_tunnel::tls::TlsFiles::new(cert, key);

        if args.tls_self_signed {
            let names = shell_tunnel::tls::certificate_names(args.public_base.as_deref(), bind);
            match files.ensure_self_signed(&names) {
                Ok(created) => generated_cert = created,
                Err(e) => {
                    eprintln!("Configuration error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        config = config.with_tls(files);
    }
    #[cfg(not(feature = "tls"))]
    if args.tls_cert.is_some() {
        eprintln!("Configuration error: this build cannot serve TLS.");
        eprintln!("Rebuild with `--features tls`, or put a reverse proxy in front.");
        std::process::exit(1);
    }
    std::env::set_var("RUST_LOG", args.log_level.as_deref().unwrap_or("info"));
    logging::init();

    // `0.0.0.0` is a bind address, not somewhere a device can dial. Printing it
    // as a join URL would hand the operator a command that cannot work off-box,
    // so a wildcard bind reports what it is listening on and leaves the address
    // to them. (Devices themselves are told the address their own connection
    // observed, which is what works behind TLS termination.)
    let scheme = if args.tls_cert.is_some() {
        "https"
    } else {
        "http"
    };
    let reachable = if args.public_base.is_some() {
        Some(config.public_base_or(None))
    } else if !bind.ip().is_unspecified() {
        Some(format!("{scheme}://{bind}"))
    } else {
        None
    };

    match &reachable {
        Some(url) => println!("\nRelay:        {url}"),
        None => println!("\nRelay:        listening on {bind}"),
    }
    if generated {
        println!("Enroll token: {enroll_token}   (generated)");
    }
    let join_url = reachable.unwrap_or_else(|| format!("{scheme}://<this-host>:{}", bind.port()));

    // A self-signed certificate is trusted by nobody until its file reaches the
    // devices. The join line therefore carries `--relay-ca` rather than handing
    // out a command that fails on the first dial.
    #[cfg(feature = "tls")]
    let ca_flag = match (args.tls_self_signed, &args.tls_cert) {
        (true, Some(cert)) => format!(" --relay-ca {}", cert.display()),
        _ => String::new(),
    };
    #[cfg(not(feature = "tls"))]
    let ca_flag = String::new();

    println!(
        "Devices join with:\n    shell-tunnel --relay {join_url} --enroll-token <token>{ca_flag}\n"
    );

    #[cfg(feature = "tls")]
    if args.tls_self_signed {
        if generated_cert {
            println!("Generated a self-signed certificate; restarts reuse it.");
        }
        if let Some(cert) = &args.tls_cert {
            println!("Copy {} to each device for --relay-ca.\n", cert.display());
        }
    }

    serve_relay(config).await
}

/// Serve locally while attached to a self-hosted relay.
///
/// Unlike a spawned tunnel, a dropped relay connection is recoverable: the relay
/// keeps addressing this device by the same id, so the client reconnects with
/// backoff instead of taking the server down with it.
#[cfg(feature = "relay-client")]
async fn run_with_relay(
    server_config: shell_tunnel::ServerConfig,
    args: &Args,
    relay_url: String,
    exposure: PublicExposure,
    state: shell_tunnel::AppState,
) -> shell_tunnel::Result<()> {
    use shell_tunnel::relay::client::{run as run_relay_client, RelayClientConfig};

    // Behind a relay the local listener only ever talks to this process, so the
    // port is an implementation detail — let the OS pick a free one unless the
    // user asked for a specific port. That removes the most common way this
    // setup fails: something else already holding 3000.
    let mut server_config = server_config;
    if !args.port_explicit {
        server_config.port = 0;
    }

    let listener = shell_tunnel::api::bind(&server_config).await?;
    let local = listener
        .local_addr()
        .map_err(shell_tunnel::ShellTunnelError::Io)?;
    let server = tokio::spawn(shell_tunnel::api::serve_on(listener, server_config, state));

    let client_config = RelayClientConfig {
        relay_url,
        enroll_token: args
            .enroll_token
            .clone()
            .expect("checked before logging starts"),
        local,
        label: None,
        // Naming the device after the machine keeps its URL stable across
        // restarts without the operator naming every host by hand.
        device_name: args
            .device_name
            .clone()
            .or_else(shell_tunnel::relay::client::default_device_name),
        ca_file: args.relay_ca.clone(),
    };

    for warning in &exposure.warnings {
        warn!("{}", warning);
    }
    if let Some(key) = &exposure.generated_key {
        println!("API key:     {key}   (generated)");
    }

    tokio::select! {
        result = server => result.expect("server task panicked"),
        result = run_relay_client(client_config) => result,
    }
}

/// Poll until `addr` accepts a connection, or `timeout` elapses.
///
/// A timeout is not fatal: the tunnel client will retry on its own, and failing
/// to start the tunnel over a slow bind would be the worse error.
async fn wait_until_listening(addr: SocketAddr, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Resolve once the tunnel client is no longer running.
async fn tunnel_died(tunnel: &mut TunnelHandle) {
    while tunnel.is_alive() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Print the ready-to-use banner: where the server is, and how to call it.
///
/// The API key is echoed only when shell-tunnel generated it — that is the
/// user's only copy. A key the user supplied is referenced by name instead, so
/// running under a tunnel never writes their secret to stdout.
fn print_banner(tunnel: &TunnelHandle, generated_key: Option<&str>) {
    let url = tunnel.public_url();
    let key_line = match generated_key {
        Some(key) => format!("API key:     {key}   (generated)"),
        None => "API key:     (the key you configured)".to_string(),
    };
    let key_value = generated_key.unwrap_or("$SHELL_TUNNEL_API_KEY");

    println!(
        "\nPublic URL:  {url}   (via {provider})\n\
         {key_line}\n\
         Try:         curl -X POST {url}/api/v1/execute \\\n\
         \x20              -H \"Authorization: Bearer {key_value}\" \\\n\
         \x20              -H \"Content-Type: application/json\" \\\n\
         \x20              -d '{{\"command\":\"echo hi\"}}'\n",
        provider = tunnel.provider(),
    );
}
