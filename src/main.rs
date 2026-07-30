//! Shell-tunnel binary entry point.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use shell_tunnel::config::PublicExposure;
use shell_tunnel::relay::{serve_relay, RelayConfig};
use shell_tunnel::tunnel::{self, TunnelHandle};
use shell_tunnel::{logging, parse_args, print_help, print_version, Args, Config};
use tracing::{info, warn};

fn main() -> shell_tunnel::Result<()> {
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

    // Handle update commands (only compiled with the `self-update` feature).
    // These must run before the async runtime exists: the updater's HTTP
    // client is a blocking one, and creating and dropping it inside a runtime
    // is the panic that took `--check-update` down with it.
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

    // Everything past this point serves connections; the async runtime starts
    // here, once the blocking update paths above have returned.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(args))
}

async fn async_main(args: Args) -> shell_tunnel::Result<()> {
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

    // A root that exists but is a plain file canonicalises fine and then fails
    // every resolve afterward with a confusing 404 — caught here instead, at
    // startup, where an operator will actually see it.
    //
    // Built before the audit sink below (this used to run after it): the
    // sink's `OpenOptions::create(true)` would otherwise create `--audit-log`
    // on disk before the containment check that follows had any chance to
    // refuse it, leaving a stray empty file *inside* the fs jail — creating a
    // file nobody asked for on a path that is about to fail startup anyway.
    let fs_root = if let Some(fs_root) = args.fs_root.as_ref() {
        if !fs_root.is_dir() {
            eprintln!(
                "--fs-root {} cannot be used: not a directory",
                fs_root.display()
            );
            eprintln!("The directory must exist and be readable.");
            std::process::exit(2);
        }
        match shell_tunnel::FsRoot::new(fs_root) {
            Ok(root) => Some(root),
            Err(e) => {
                eprintln!("--fs-root {} cannot be used: {e}", fs_root.display());
                eprintln!("The directory must exist and be readable.");
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    // The audit log must not sit inside the fs jail: from that moment an
    // fs.write token could DELETE or overwrite-by-upload the trail recording
    // its own actions. `.shell-tunnel-uploads` has a reserved-path refusal
    // for exactly this shape of problem (`src/api/fs.rs`); the audit log had
    // nothing, because the audit layer predates the jail and neither knew
    // about the other's path.
    //
    // Checked here, before the audit sink is created below: `--audit-log`
    // does not exist yet in the common case (first startup), only its parent
    // directory does — see `audit_log_is_inside_fs_root`'s own doc comment
    // for why the check works on the parent rather than the whole path.
    // `fs_root`'s path is already canonicalised by `FsRoot::new` above.
    if let (Some(audit_log), Some(root)) = (args.audit_log.as_ref(), fs_root.as_ref()) {
        match audit_log_is_inside_fs_root(audit_log, root.path()) {
            Ok(true) => {
                eprintln!(
                    "--audit-log {} cannot be used: it resolves inside --fs-root {}",
                    audit_log.display(),
                    root.path().display()
                );
                eprintln!(
                    "An fs.write token could delete or overwrite the trail recording its own actions. Point --audit-log outside the fs root."
                );
                std::process::exit(2);
            }
            Ok(false) => {}
            // Not treated as "not inside, proceed": an inability to verify
            // containment is not evidence of its absence. Refusing here is
            // the same fail-closed choice `refuse_if_reserved` makes in
            // `src/api/fs.rs` when it cannot compute a path's canonical
            // form — an approximate "probably fine" would read as a
            // guarantee this check does not have grounds to make.
            Err(e) => {
                eprintln!(
                    "--audit-log {} cannot be checked against --fs-root {}: {e}",
                    audit_log.display(),
                    root.path().display()
                );
                std::process::exit(2);
            }
        }
    }

    // Opened only now, after the check above has had its chance to refuse —
    // so a path that cannot be written still stops startup here rather than
    // leaving an operator believing there is a trail, and a path inside the
    // fs jail never gets this far at all.
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
    let state = match fs_root {
        Some(root) => state.with_fs_root(root),
        None => state,
    };

    // Rejected at startup rather than clamped silently: a chunk size at or
    // above the ceiling would make every relayed transfer 413, and the
    // symptom would look like a server bug rather than a misconfiguration.
    let state = match args.fs_chunk_size {
        Some(size) if size == 0 || size >= shell_tunnel::fs::MAX_CHUNK_SIZE => {
            eprintln!("--fs-chunk-size {size} is out of range.");
            eprintln!("It must be between 1 and 8388607 bytes: a relayed request body is capped at 8 MiB, so a larger chunk fails with 413 on every relayed transfer.");
            std::process::exit(2);
        }
        Some(size) => state.with_chunk_size(size),
        None => state,
    };

    // Sessions never survive a restart, so any `.part` staging file still
    // present is unreachable — nothing can resume it and nothing will
    // complete it. Swept once, here, before the server starts accepting.
    // `sweep_orphaned_uploads` (not the lower-level `fs::sweep_orphan_parts`)
    // so each orphan leaves an `upload.orphaned` audit event rather than
    // vanishing with only a count logged.
    if let Some(root) = state.fs.as_ref() {
        let removed = shell_tunnel::api::fs::sweep_orphaned_uploads(root, &state.audit);
        if removed > 0 {
            info!("removed {removed} orphaned upload staging file(s)");
        }
    }

    // A server that goes quiet after `SESSION_TTL` elapses would otherwise
    // hold every expired session's file descriptor and staging file
    // indefinitely — `create_upload_blocking`'s own opportunistic sweep
    // (`src/api/fs.rs`) only runs when a *new* upload is requested, which
    // never happens on an idle server. This is the actual mechanism; the
    // opportunistic call stays too, bounding staging growth between ticks.
    if state.fs.is_some() {
        let uploads = state.uploads.clone();
        let audit = state.audit.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300));
            loop {
                ticker.tick().await;
                // Both `UploadStore::sweep` (removes staging files) and
                // `AuditSink::record` (opens/writes/flushes the audit log)
                // are blocking I/O, so — unlike the brief this task started
                // from, which called this straight from the spawned async
                // task — the call itself is wrapped in `spawn_blocking` here.
                // Same convention as every filesystem route in
                // `src/api/fs.rs` (`src/execution/executor.rs:209-215`): a
                // slow disk must never stall the worker pool that also runs
                // `/health` and the accept loop.
                let uploads = uploads.clone();
                let audit = audit.clone();
                let dropped = tokio::task::spawn_blocking(move || {
                    shell_tunnel::api::fs::sweep_expired_uploads(
                        &uploads,
                        &audit,
                        shell_tunnel::fs::SESSION_TTL,
                    )
                })
                .await
                .unwrap_or(0);
                if dropped > 0 {
                    info!("swept {dropped} expired upload session(s)");
                }
            }
        });
    }

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
    let mut cert_names: Vec<String> = Vec::new();
    #[cfg(feature = "tls")]
    let mut cert_fingerprint: Option<String> = None;
    #[cfg(feature = "tls")]
    if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
        let files = shell_tunnel::tls::TlsFiles::new(cert, key);

        if args.tls_self_signed {
            let names = shell_tunnel::tls::certificate_names(args.public_base.as_deref(), bind);
            match files.ensure_self_signed(&names) {
                Ok(created) => {
                    generated_cert = created;
                    cert_names = names;
                    // Read back rather than remembering what was written: on a
                    // reused certificate there is nothing in memory to remember.
                    cert_fingerprint = files.fingerprint().ok();
                }
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
    // A self-signed certificate is trusted by nobody until the device is told
    // what to expect. The fingerprint is what goes in the join line: it travels
    // as one string in the text being copied anyway, and it does not care
    // whether the certificate names the address being dialled.
    #[cfg(feature = "tls")]
    let ca_flag = match &cert_fingerprint {
        Some(fp) => format!(" --relay-fingerprint {fp}"),
        None => String::new(),
    };
    #[cfg(not(feature = "tls"))]
    let ca_flag = String::new();

    println!(
        "Devices join with:\n    shell-tunnel --relay {join_url} --enroll-token <token>{ca_flag}\n"
    );

    // A port-less --public-base now inherits this relay's listen port (see
    // RelayConfig::resolved_public_base), so the URLs above already name a port
    // that something is serving — no restart needed for the common direct-expose
    // case. The one setup that wanted the port-less form is a proxy forwarding
    // the scheme default here; that operator names the port explicitly, so tell
    // them what was assumed rather than leaving it silent.
    if let Some(corrected) = config
        .public_base
        .as_deref()
        .and_then(|base| shell_tunnel::relay::public_base_port_hint(base, bind.port()))
    {
        let implied = if corrected.starts_with("https") {
            443
        } else {
            80
        };
        eprintln!(
            "Note: --public-base named no port, so the URLs above use this relay's port {}.",
            bind.port()
        );
        eprintln!(
            "      Fronted by a proxy on port {implied}? Re-run with that port in --public-base."
        );
        eprintln!();
    }

    #[cfg(feature = "tls")]
    if args.tls_self_signed {
        if generated_cert {
            println!("Generated a self-signed certificate; restarts reuse it.");
        }
        // Which names it covers, because a certificate that does not name the
        // address devices dial is the failure that shows up last.
        if !cert_names.is_empty() {
            println!("Certificate covers: {}", cert_names.join(", "));
        }
        // The join line already carries the trust anchor when the fingerprint
        // is known; telling the operator to copy the certificate as well
        // contradicts it, and that contradiction is exactly what a first-time
        // operator trips over. The copy instruction survives only as the
        // fallback for a certificate whose fingerprint could not be read.
        if let Some(cert) = &args.tls_cert {
            if cert_fingerprint.is_some() {
                println!(
                    "Nothing needs copying: the fingerprint in the join line is the trust anchor."
                );
                println!(
                    "(Alternative: copy {} to devices and join with --relay-ca.)\n",
                    cert.display()
                );
            } else {
                println!("Copy {} to each device for --relay-ca.\n", cert.display());
            }
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
        fingerprint: args.relay_fingerprint.clone(),
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

/// Whether `audit_log`'s canonical location sits under `fs_root`.
///
/// `fs_root` is expected already canonicalised (`FsRoot::new` does this
/// once, at construction). `audit_log` itself is checked by canonicalising
/// its *parent* and rejoining the file name lexically, rather than
/// canonicalising the whole path: this check runs before the audit sink is
/// created (see the call site), so in the common case — first startup —
/// `audit_log` does not exist yet at all, only the directory it will be
/// created in does. Canonicalising the whole path would fail with
/// `NotFound` on every first run, making this unusable for the exact case
/// it exists to guard.
///
/// A canonicalise failure (the parent directory does not exist, or is not
/// readable) is reported as `Err`, not folded into `Ok(false)`: an inability
/// to prove containment is not proof of its absence, and the caller refuses
/// to start on `Err` rather than treating it as "probably fine" — see the
/// call site's own comment. In practice this `Err` is not expected to fire
/// before `AuditSink::file_with_limit`'s own parent-must-exist requirement
/// would already have refused startup a different way; it is handled
/// explicitly here anyway rather than assumed unreachable.
fn audit_log_is_inside_fs_root(audit_log: &Path, fs_root: &Path) -> std::io::Result<bool> {
    let file_name = audit_log.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "audit log path has no file name",
        )
    })?;
    let parent = match audit_log.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        // A bare filename (`"audit.jsonl"`, no directory component) resolves
        // relative to the current directory — the same place
        // `OpenOptions::open` would later resolve it, so this must match.
        _ => Path::new("."),
    };
    Ok(parent.canonicalize()?.join(file_name).starts_with(fs_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing in the test suite reaches `async_main` (no test binds a real
    /// server from CLI args), so this is a direct unit test of the pure
    /// comparison. `tests/main_startup_e2e.rs` covers the other half — that
    /// `async_main` actually calls this rather than merely computing the
    /// right boolean nobody consults.
    ///
    /// The audit log file itself is deliberately never created here: this
    /// check runs before the audit sink exists (see the call site in
    /// `async_main`), so in the case that matters — first startup — only the
    /// parent directory exists yet. A test that created the file first would
    /// not catch a regression back to whole-path canonicalisation.
    #[test]
    fn audit_log_under_the_fs_root_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir(&root).expect("mkdir root");
        let audit_log = root.join("audit.jsonl");

        let canonical_root = root.canonicalize().expect("canonicalize root");
        assert!(
            audit_log_is_inside_fs_root(&audit_log, &canonical_root)
                .expect("the parent directory exists"),
            "an audit log inside the root must be detected as inside it"
        );
    }

    #[test]
    fn audit_log_outside_the_fs_root_is_not_flagged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir(&root).expect("mkdir root");
        let audit_log = dir.path().join("audit.jsonl");

        let canonical_root = root.canonicalize().expect("canonicalize root");
        assert!(
            !audit_log_is_inside_fs_root(&audit_log, &canonical_root)
                .expect("the parent directory exists"),
            "a sibling audit log must not be flagged as inside the root"
        );
    }

    /// A nested destination is still detected, not just a direct child —
    /// otherwise `--fs-root /srv/deploy --audit-log /srv/deploy/logs/audit.jsonl`
    /// would slip through the same way a direct child would have.
    #[test]
    fn a_nested_audit_log_under_the_fs_root_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("logs")).expect("mkdir root/logs");
        let audit_log = root.join("logs").join("audit.jsonl");

        let canonical_root = root.canonicalize().expect("canonicalize root");
        assert!(
            audit_log_is_inside_fs_root(&audit_log, &canonical_root)
                .expect("the parent directory exists"),
            "a nested audit log must be detected as inside the root too"
        );
    }

    /// The `Err` arm itself: a path whose *parent* cannot be canonicalised
    /// (nothing exists there) must not be silently treated as "not inside,
    /// proceed".
    #[test]
    fn an_uncheckable_audit_log_path_is_an_error_not_a_silent_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir(&root).expect("mkdir root");
        let canonical_root = root.canonicalize().expect("canonicalize root");

        let never_created = dir.path().join("nonexistent").join("audit.jsonl");
        assert!(
            audit_log_is_inside_fs_root(&never_created, &canonical_root).is_err(),
            "a path whose parent cannot be canonicalised must surface as Err, not Ok(false)"
        );
    }
}
