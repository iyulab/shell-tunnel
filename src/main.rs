//! Shell-tunnel binary entry point.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shell_tunnel::config::{Posture, PublicExposure};
use shell_tunnel::relay::{serve_relay, RelayConfig};
use shell_tunnel::security::CapabilitySet;
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
    // The posture decides the security defaults. Attaching to a relay publishes
    // this machine just as a tunnel does, so it goes through the same hardening
    // rather than a parallel set of rules — and so does a non-loopback bind: a
    // LAN is other people's machines too, and host checking (the DNS rebinding
    // defence) is a different axis that does not fill this gap.
    let posture = config.posture(provider.is_some(), args.relay_url.is_some());
    let mut exposure = if posture == Posture::Exposed {
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
    // Authentication is not only switched on by exposure: `--require-auth`,
    // `--api-key`, a preset and a capability list each turn it on, and a
    // loopback bind never reaches the hardening above. Whichever way it was
    // asked for, the key has to exist *here* — before `to_server_config`
    // below, and while there is still a banner to print it on. Left to the
    // server (`serve_on`) the key was created after the banner, reported only
    // as an `INFO` line, and at `-l warn` a `--require-auth` server started,
    // enforced authentication, and told nobody the key: confirmed by running
    // it, not inferred. `ensure_api_key` returns `None` when the hardening
    // already issued one, so the exposed path is untouched.
    if exposure.generated_key.is_none() {
        exposure.generated_key = config.ensure_api_key();
    }

    if args.relay_url.is_some() && args.enroll_token.is_none() {
        eprintln!("Configuration error: --relay requires --enroll-token");
        std::process::exit(1);
    }

    // Serving TLS is a relay-mode capability. Ignoring the flag here would start
    // a plaintext server for someone who asked for an encrypted one — the exact
    // silent failure every other path in this binary refuses to make.
    if args.tls_cert.is_some() {
        // Names what was actually passed. `--tls-self-signed` fills in
        // `tls_cert`/`tls_key` with defaults during parsing, so reporting the
        // field rather than the flag sent an operator looking for two flags
        // they never wrote.
        // Carries its own verb: one flag applies, two apply.
        let given = if args.tls_self_signed {
            "--tls-self-signed applies"
        } else {
            "--tls-cert/--tls-key apply"
        };
        eprintln!("Configuration error: {given} to `shell-tunnel relay`.");
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
    // Unchanged in outcome by the posture switch above: `allowed_hosts` already
    // declines to check the `Host` header on a non-loopback bind of its own
    // accord, so the one quadrant where the posture is broader than the old
    // `provider.is_some() || relay` test was returning `None` here anyway.
    let allowed_hosts = config.allowed_hosts(&args, posture == Posture::Exposed);
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
            Ok(root) => root,
            Err(e) => {
                eprintln!("--fs-root {} cannot be used: {e}", fs_root.display());
                eprintln!("The directory must exist and be readable.");
                std::process::exit(2);
            }
        }
    } else {
        // No flag means the whole machine, not "off". A token holding `exec`
        // already reads and writes anything this process can, so confining
        // the file API by default withholds nothing from `operator` or
        // `full-control` — it only forces callers onto the slow path for
        // every destination outside the jail. `file-read` and `file-write`
        // hold `fs.*` without `exec`, so that reasoning does not cover them:
        // for those two presets `--fs-root` is the only confinement there
        // is, and it has to be asked for explicitly (see docs/USAGE.md).
        shell_tunnel::FsRoot::machine_wide()
    };

    // Derived once, here. The containment check below and the sink creation
    // after it both read this value — the default path lives in the working
    // directory too, so it can land inside `--fs-root`, and it has to face the
    // same check when it does.
    let audit_log = effective_audit_log(args.audit_log.as_deref(), posture);

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
    //
    // Only when `--fs-root` narrows the scope. Machine-wide there is nowhere
    // outside to point the log at, so this refusal has nothing to offer: the
    // trail is reachable by the file API wherever it sits. (This used to add
    // "as it already is by `exec`, which every preset carrying `fs.*` also
    // carries" — no longer true of `file-read`/`file-write`, which hold `fs.*`
    // without `exec`. The conclusion is unaffected: machine-wide means nothing
    // is outside, whatever the token holds.) The banner says so rather than
    // pretending otherwise.
    if let (Some(path), Some(jail)) = (audit_log.as_ref(), fs_root.jail_path()) {
        match audit_log_is_inside_fs_root(path, jail) {
            // Two refusals, because there are two different mistakes to
            // correct. Telling someone their chosen path is wrong when they
            // never chose one sends them looking for a flag they did not pass.
            Ok(true) => {
                if args.audit_log.is_some() {
                    eprintln!(
                        "--audit-log {} cannot be used: it resolves inside --fs-root {}",
                        path.display(),
                        jail.display()
                    );
                    eprintln!("An fs.write token could delete or overwrite the trail recording its own actions. Point --audit-log outside the fs root.");
                } else {
                    eprintln!(
                        "A publicly reachable server writes an audit trail, and its default location ({}) resolves inside --fs-root {}",
                        DEFAULT_AUDIT_LOG,
                        jail.display()
                    );
                    eprintln!("An fs.write token could delete or overwrite the trail recording its own actions. Pass --audit-log with a path outside the fs root.");
                }
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
                    path.display(),
                    jail.display()
                );
                std::process::exit(2);
            }
        }
    }

    // Opened only now, after the check above has had its chance to refuse —
    // so a path that cannot be written still stops startup here rather than
    // leaving an operator believing there is a trail, and a path inside the
    // fs jail never gets this far at all.
    let audit = match &audit_log {
        Some(path) => {
            match shell_tunnel::audit::AuditSink::file_with_limit(path, args.audit_max_bytes) {
                Ok(sink) => std::sync::Arc::new(sink),
                // Two failures again, for the same reason the containment check
                // above splits: an exposed server in an unwritable working
                // directory never named this path, and a bare `Configuration
                // error:` sends such an operator looking for the flag they did
                // not pass — with no hint that an audit trail exists at all.
                // Reachable without doing anything unusual: a service unit with
                // a read-only working directory, a network share, an install
                // location the account cannot write.
                Err(e) => {
                    if args.audit_log.is_some() {
                        eprintln!("--audit-log {} cannot be used: {e}", path.display());
                        eprintln!("The parent directory must exist and be writable.");
                    } else {
                        eprintln!("A publicly reachable server writes an audit trail, and its default location ({}) cannot be created: {e}", DEFAULT_AUDIT_LOG);
                        eprintln!("Start the server in a writable directory, or pass --audit-log with a path elsewhere.");
                    }
                    std::process::exit(1);
                }
            }
        }
        None => std::sync::Arc::new(shell_tunnel::audit::AuditSink::Disabled),
    };
    if audit.is_enabled() {
        info!("audit trail: {}", audit_log.as_ref().unwrap().display());
    }
    // The banner is the whole mitigation for a file API that no longer needs a
    // flag to exist: an operator who never passes `--fs-root` still has to be
    // told, in one unmissable line, what the API can reach. Printed before the
    // server starts so it is not buried under request logging.
    // Read after `harden_for_public_exposure` (far above), so the promoted
    // `operator` is what gets described rather than the pre-promotion state.
    // An `Err` is unreachable here: `to_server_config` resolved these same two
    // fields earlier and exited on an unknown preset. Should that ever change,
    // falling back to `None` reports the wildcard — the direction that
    // overstates the grant rather than understating it.
    //
    // Resolved once and shared with the file-scope test below. Two call sites
    // resolving the same thing separately is exactly the drift both lines exist
    // to avoid: they must describe one token, not two independent guesses at it.
    let resolved = config.resolved_capabilities().ok().flatten();
    let scope = token_scope(config.security.auth.preset.as_deref(), resolved.as_ref());
    for line in posture_banner(
        posture,
        &scope,
        audit_log.as_deref(),
        !args.allow_hosts.is_empty(),
    ) {
        println!("{line}");
    }
    // The generated key belongs with the reachability it unlocks, not after the
    // file-API block. Only the bare-bind path prints it here: a tunnel prints
    // its own banner once the URL exists (`print_banner`), and a relay prints
    // one beside its attach output (`run_with_relay`), so printing here too
    // would report the same key twice.
    //
    // A loopback bind reaches this line too, and now has something to print:
    // the block above is empty for `Posture::Local` (nothing was narrowed, so
    // there is nothing to report), but a key issued for `--require-auth` is
    // not reachability information — it is the one value the operator cannot
    // start without, whoever can reach the port. stdout, unconditionally, is
    // the only place that survives `-l warn`.
    if provider.is_none() && args.relay_url.is_none() {
        if let Some(key) = &exposure.generated_key {
            println!("API key:     {key}   (generated)");
        }
    }
    println!("File API:    {}", fs_root.describe());
    // The one combination the lines above describe truthfully and still leave
    // an operator to assemble for themselves. For `operator` or `full-control`
    // a machine-wide file API withholds nothing that `exec` did not already
    // grant, so there is nothing to say; for a token holding `fs.*` without
    // `exec` the file API *is* the whole grant, and `--fs-root` is the only
    // thing that would have narrowed it. A preset name that sounds narrow
    // ("file-read") is precisely how this is reached by accident.
    if fs_root.jail_path().is_none()
        && file_scope_is_the_whole_grant(config.security.auth.enabled, resolved.as_ref())
    {
        println!("             this token holds the file API without `exec`, so --fs-root is the only confinement it has — and it was not given");
    }
    if fs_root.jail_path().is_none() && audit_log.is_some() {
        // The `exec` clause this line used to carry ("as it already is for
        // `exec`") assumed every token reaching the file API also holds `exec`.
        // `file-read` and `file-write` hold `fs.*` without it, so the clause was
        // false for exactly the scopes drawn around that boundary — and this
        // line now prints on every exposed run, not only when `--audit-log` was
        // passed. What remains names no capability at all: the subject is the
        // file API's reach, which is what this line actually knows. Naming one
        // — even conditionally, as "a token holding `fs.write` could overwrite
        // it" — puts the same token-shaped assumption back in a different
        // grammatical costume, and under `--preset file-read` no token this
        // server issues holds `fs.write` to begin with.
        println!("             the audit log is within this scope — nothing is outside a machine-wide file API");
    }

    let state = shell_tunnel::AppState::new()
        .with_audit(audit)
        .with_fs_root(fs_root);

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
        // A non-loopback bind reaches here with neither tunnel nor relay to
        // print for it, and it is now hardened like both — so its warnings are
        // reported here as well. The generated key is not: it is printed with
        // the posture banner above, beside the reachability it unlocks.
        // Locally `PublicExposure::default()` is empty and both stay silent, so
        // the zero-friction local path is untouched.
        for warning in &exposure.warnings {
            warn!("{}", warning);
        }
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
        println!("{}", generated_enroll_token_note());
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

/// The file name an audit trail lands on by default once the server is exposed.
///
/// Created in the working directory and reused across restarts — the same
/// structure as the self-signed certificate (`shell-tunnel-cert.pem`).
const DEFAULT_AUDIT_LOG: &str = "shell-tunnel-audit.jsonl";

/// The audit log path actually used.
///
/// An explicitly named path wins. Absent one, an exposed server gets the
/// default path; a local one gets nothing — locally we still create no file
/// nobody asked for.
fn effective_audit_log(explicit: Option<&Path>, posture: Posture) -> Option<PathBuf> {
    match (explicit, posture) {
        (Some(path), _) => Some(path.to_path_buf()),
        (None, Posture::Exposed) => Some(PathBuf::from(DEFAULT_AUDIT_LOG)),
        (None, Posture::Local) => None,
    }
}

/// What a token issued by this server actually holds.
///
/// The banner used to assume the answer was always `operator`, which is only
/// true when nothing was chosen and the default promoted it. Naming the three
/// cases makes the wildcard impossible to describe as a scope by accident.
#[derive(Debug, PartialEq, Eq)]
enum TokenScope {
    /// Every capability, including any added in later versions.
    Wildcard,
    /// A named preset, holding exactly what that name grants.
    Preset(String),
    /// An explicit set of capability strings, in a stable order.
    Explicit(Vec<String>),
}

/// Describe the scope in force from the *resolved* facts.
///
/// `capabilities` is the set that actually reaches the server, so it — not the
/// preset name — decides whether anything is scoped at all. `None` means
/// nothing narrowed it: the full-control default, which is the wildcard.
///
/// The preset name is used only when it still describes the whole set. A preset
/// with capabilities unioned on top grants more than its name promises, and
/// naming it there would understate the token.
fn token_scope(preset: Option<&str>, capabilities: Option<&CapabilitySet>) -> TokenScope {
    let Some(set) = capabilities else {
        return TokenScope::Wildcard;
    };
    if set.is_wildcard() {
        return TokenScope::Wildcard;
    }
    match preset {
        Some(name) if shell_tunnel::security::preset(name).as_ref() == Some(set) => {
            TokenScope::Preset(name.to_string())
        }
        _ => {
            // Sorted because the set is a `HashSet`: unsorted, the same
            // configuration would print a different banner on every run.
            let mut listed: Vec<String> = set.iter().cloned().collect();
            listed.sort();
            TokenScope::Explicit(listed)
        }
    }
}

/// Whether the file API is the whole of what a token this server issues holds.
///
/// True exactly when authentication is on and the token reaches `fs.read` or
/// `fs.write` without holding `exec`. That is the one shape for which
/// `--fs-root` confines anything: with `exec` the file API grants no reach the
/// token did not already have, so its absence is not a hazard worth a line.
///
/// Decided from the *resolved* capability set rather than the preset name, so
/// it cannot drift from what the router enforces — and so it covers
/// `--capabilities fs.read` as readily as `--preset file-read`. `None` is the
/// full-control default, which is the wildcard: `satisfies` answers `true` for
/// `exec` there, so the wildcard falls out of the same test rather than needing
/// its own arm.
///
/// `auth_enabled` is not a refinement of that test but a precondition for it
/// meaning anything. With authentication off, `capability_auth_middleware`
/// (`src/api/router.rs`) returns before a token is ever looked for, so every
/// route is open — `exec` included — no matter what `--preset` or
/// `security.auth.preset` says. Describing such a server as holding a scope
/// without `exec` would be false in the reassuring direction, on the one
/// surface meant to be trusted. Reachable with `--no-auth --preset file-read`
/// and with `auth.enabled: false` alongside a preset in a config file; an
/// exposed server cannot reach it, since the posture turns authentication on
/// and refuses `--no-auth`.
fn file_scope_is_the_whole_grant(auth_enabled: bool, capabilities: Option<&CapabilitySet>) -> bool {
    let Some(set) = capabilities.filter(|_| auth_enabled) else {
        return false;
    };
    !set.satisfies("exec") && (set.satisfies("fs.read") || set.satisfies("fs.write"))
}

/// The note printed beside an enrolment token this process generated.
///
/// The certificate is the contrast that makes this worth saying: a self-signed
/// one is written to disk and reused, so its fingerprint survives a restart and
/// the join lines built around it keep working. The enrolment token is
/// generated the same way and kept nowhere, so a relay restarted without
/// `--enroll-token` invalidates every attached device's join line at once — and
/// the devices do not report it, they retry in backoff against a token the
/// relay no longer knows. Nothing said so at the one moment an operator is
/// looking at the token.
///
/// Aligned to the fourteen columns the labels above it use, so it reads as a
/// continuation of the line it qualifies rather than a new fact.
fn generated_enroll_token_note() -> &'static str {
    "              not saved: a restart generates a new one and every attached device's join line stops working. Pass --enroll-token to keep it across restarts."
}

/// The banner lines announcing the posture. Local is an empty list — with
/// nothing narrowed there is nothing to report.
///
/// The strings come out of a function so that tests can hold them in place.
/// User-facing text in this repository has broken four times, every one of
/// them somewhere no test was looking.
fn posture_banner(
    posture: Posture,
    scope: &TokenScope,
    audit_log: Option<&Path>,
    allow_host_given: bool,
) -> Vec<String> {
    if posture == Posture::Local {
        return Vec::new();
    }
    // The wildcard line deliberately avoids the word "scoped": the wildcard is
    // the absence of scoping, and this line is the only place a consumer
    // confirms which of the two they have.
    let reach = match scope {
        TokenScope::Wildcard => "Reachable:   from other machines — tokens hold the wildcard `*`: every capability, including any added in later versions".to_string(),
        TokenScope::Preset(name) => {
            format!("Reachable:   from other machines — tokens are scoped to `{name}`, not wildcard")
        }
        // Each capability is backticked, as the `Preset` arm backticks its
        // name: unquoted, "scoped to exec, fs.read, not wildcard" reads as if
        // `not wildcard` were a third item in the list.
        TokenScope::Explicit(listed) => {
            let quoted: Vec<String> = listed.iter().map(|c| format!("`{c}`")).collect();
            format!(
                "Reachable:   from other machines — tokens are scoped to {}, not wildcard",
                quoted.join(", ")
            )
        }
    };
    let mut lines = vec![reach];
    // `--allow-host` is read only on a loopback bind with no public path, and
    // that is exactly the posture this function returns early for — so on
    // every line below it the flag did nothing at all. Turning the check off
    // here is right: a published server is reached under a name it may not
    // know (the tunnel provider assigns one, a relay routes by path), and host
    // checking answers DNS rebinding rather than being access control, so
    // there is no rebinding to stop and a check would refuse legitimate
    // traffic. What was wrong is that a flag asking for a defence was
    // discarded in silence. The banner already exists to say what is actually
    // in force; this is one more thing that is not.
    if allow_host_given {
        lines.push(
            "             --allow-host was not applied — a published server answers to any Host, since it is reached under names it cannot know".to_string(),
        );
    }
    if let Some(path) = audit_log {
        lines.push(format!("Audit trail: {}", path.display()));
    }
    lines
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

    #[test]
    fn an_exposed_run_gets_an_audit_trail_it_did_not_ask_for() {
        // Same shape as the self-signed certificate: being exposed is the
        // circumstance that justifies an exception to the "create no file
        // nobody asked for" rule.
        let derived = effective_audit_log(None, Posture::Exposed);
        assert_eq!(derived, Some(PathBuf::from(DEFAULT_AUDIT_LOG)));
    }

    #[test]
    fn a_local_run_still_creates_nothing() {
        assert_eq!(effective_audit_log(None, Posture::Local), None);
    }

    #[test]
    fn an_explicit_audit_path_wins_in_either_posture() {
        let chosen = PathBuf::from("/var/log/st.jsonl");
        assert_eq!(
            effective_audit_log(Some(&chosen), Posture::Exposed),
            Some(chosen.clone())
        );
        assert_eq!(
            effective_audit_log(Some(&chosen), Posture::Local),
            Some(chosen)
        );
    }

    /// Resolve a preset name the way `Config` does, for the tests below.
    fn resolved(name: &str) -> CapabilitySet {
        shell_tunnel::security::preset(name).expect("preset exists")
    }

    #[test]
    fn the_exposed_banner_names_the_scope_and_the_trail() {
        // The default-promoted case: no preset and no capabilities were given,
        // so `harden_for_public_exposure` set `operator`.
        let path = PathBuf::from("shell-tunnel-audit.jsonl");
        let scope = token_scope(Some("operator"), Some(&resolved("operator")));
        let lines = posture_banner(Posture::Exposed, &scope, Some(&path), false);
        let text = lines.join("\n");
        assert!(text.contains("Reachable:"), "{text}");
        assert!(
            text.contains("operator"),
            "must name the scope in force: {text}"
        );
        assert!(
            text.contains("shell-tunnel-audit.jsonl"),
            "must name the trail: {text}"
        );
        // Two facts never fold onto one line — a banner is skimmed, not read.
        assert!(lines.len() >= 2, "{lines:?}");
    }

    /// The defect this signature exists to fix: `--preset full-control` resolves
    /// to the wildcard, and the banner used to call it "scoped to `operator`"
    /// regardless — false on the one surface a consumer uses to confirm what a
    /// token can do.
    #[test]
    fn a_wildcard_scope_is_never_described_as_scoped() {
        let scope = token_scope(Some("full-control"), Some(&resolved("full-control")));
        let text = posture_banner(Posture::Exposed, &scope, None, false).join("\n");
        assert!(
            !text.contains("operator"),
            "a wildcard token must not be reported as `operator`: {text}"
        );
        assert!(
            !text.contains("scoped"),
            "the wildcard is the absence of scoping — saying `scoped` here is the lie being fixed: {text}"
        );
        assert!(
            text.contains("wildcard"),
            "it must say plainly that the token holds the wildcard: {text}"
        );
    }

    /// A `None` resolution is the legacy full-control default, which is also the
    /// wildcard — it must not be mistaken for "nothing granted".
    #[test]
    fn an_unresolved_scope_is_the_wildcard() {
        assert_eq!(token_scope(None, None), TokenScope::Wildcard);
    }

    #[test]
    fn an_explicit_preset_is_named_rather_than_the_promoted_one() {
        let scope = token_scope(Some("file-read"), Some(&resolved("file-read")));
        let text = posture_banner(Posture::Exposed, &scope, None, false).join("\n");
        assert!(text.contains("file-read"), "{text}");
        assert!(
            !text.contains("operator"),
            "the preset in force is file-read, not the default: {text}"
        );
    }

    #[test]
    fn an_explicit_capability_list_is_spelled_out() {
        let caps: CapabilitySet = ["exec", "fs.read"].into_iter().collect();
        let scope = token_scope(None, Some(&caps));
        let text = posture_banner(Posture::Exposed, &scope, None, false).join("\n");
        assert!(text.contains("exec"), "{text}");
        assert!(text.contains("fs.read"), "{text}");
    }

    /// A preset with extra capabilities unioned on top holds more than the
    /// preset's name promises, so the name alone would understate the grant.
    #[test]
    fn a_preset_with_extras_is_listed_rather_than_named() {
        let mut caps = resolved("file-read");
        caps.insert("exec");
        let scope = token_scope(Some("file-read"), Some(&caps));
        let text = posture_banner(Posture::Exposed, &scope, None, false).join("\n");
        assert!(
            !text.contains("file-read"),
            "naming the preset would hide the `exec` unioned on top of it: {text}"
        );
        assert!(text.contains("exec"), "{text}");
    }

    /// Capability order must not depend on `HashSet` iteration order, or the
    /// banner would differ between runs of the same configuration.
    #[test]
    fn an_explicit_capability_list_is_ordered() {
        let caps: CapabilitySet = ["session.read", "exec", "fs.read"].into_iter().collect();
        match token_scope(None, Some(&caps)) {
            TokenScope::Explicit(listed) => {
                assert_eq!(listed, vec!["exec", "fs.read", "session.read"]);
            }
            other => panic!("expected an explicit list, got {other:?}"),
        }
    }

    /// The presets drawn on the far side of the `exec` boundary: for these the
    /// file API is the entire grant, so a machine-wide one is the hazard the
    /// extra banner line names.
    #[test]
    fn the_file_presets_have_nothing_but_the_file_api() {
        assert!(file_scope_is_the_whole_grant(
            true,
            Some(&resolved("file-read"))
        ));
        assert!(file_scope_is_the_whole_grant(
            true,
            Some(&resolved("file-write"))
        ));
    }

    /// With authentication off there is no token: `capability_auth_middleware`
    /// returns before it looks for one, so `exec` answers every caller whatever
    /// the preset says. Claiming a scope without `exec` there would be a
    /// reassuring falsehood on the surface this banner exists to be trusted on.
    /// Reachable as `--no-auth --preset file-read`, and from a config file
    /// pairing `auth.enabled: false` with `security.auth.preset`.
    #[test]
    fn an_unauthenticated_server_has_no_token_to_describe() {
        assert!(!file_scope_is_the_whole_grant(
            false,
            Some(&resolved("file-read"))
        ));
        assert!(!file_scope_is_the_whole_grant(
            false,
            Some(&resolved("file-write"))
        ));
        let named: CapabilitySet = ["fs.read"].into_iter().collect();
        assert!(!file_scope_is_the_whole_grant(false, Some(&named)));
    }

    /// The line must not fire for a token holding `exec`: there a machine-wide
    /// file API grants nothing `exec` did not already reach, and printing a
    /// confinement warning would train operators to ignore it.
    #[test]
    fn a_token_holding_exec_is_not_confined_by_the_file_root() {
        assert!(!file_scope_is_the_whole_grant(
            true,
            Some(&resolved("operator"))
        ));
        assert!(!file_scope_is_the_whole_grant(
            true,
            Some(&resolved("full-control"))
        ));
        // The wildcard has no arm of its own — `satisfies("exec")` answers for
        // it. Asserted so that stays true if the predicate is rewritten.
        assert!(resolved("full-control").is_wildcard());
    }

    /// `None` is the legacy full-control default, which is the wildcard — not
    /// "nothing granted", which would make this the loudest possible line on
    /// the most permissive possible token.
    #[test]
    fn an_unresolved_scope_is_not_treated_as_file_only() {
        assert!(!file_scope_is_the_whole_grant(true, None));
    }

    /// Named capabilities reach the same state as `--preset file-read` and were
    /// always able to; deciding from the resolved set rather than the preset
    /// name is what makes this case covered rather than merely adjacent.
    #[test]
    fn an_explicit_file_capability_list_counts_too() {
        let read: CapabilitySet = ["fs.read"].into_iter().collect();
        assert!(file_scope_is_the_whole_grant(true, Some(&read)));

        let with_exec: CapabilitySet = ["fs.read", "exec"].into_iter().collect();
        assert!(!file_scope_is_the_whole_grant(true, Some(&with_exec)));

        // Neither half of the file API: nothing to confine, so nothing to say.
        let sessions: CapabilitySet = ["session.read"].into_iter().collect();
        assert!(!file_scope_is_the_whole_grant(true, Some(&sessions)));
    }

    /// A flag that asks for a defence and is then discarded has to say so.
    /// `--allow-host` is read only on a loopback bind with no public path;
    /// published, `Config::allowed_hosts` returns before it looks at the flag,
    /// and until this line nothing warned, refused, or logged. The operator
    /// believed the server answered to one name while it answered to every
    /// name — a silence in the reassuring direction.
    #[test]
    fn the_exposed_banner_says_allow_host_did_nothing() {
        let scope = token_scope(Some("operator"), Some(&resolved("operator")));
        let text = posture_banner(Posture::Exposed, &scope, None, true).join(
            "
",
        );
        assert!(
            text.contains("--allow-host"),
            "the flag has to be named, not merely alluded to: {text}"
        );
        assert!(
            text.contains("not applied"),
            "and it has to say the flag did nothing: {text}"
        );
    }

    /// The other half: no line when the flag was not given. A banner that
    /// mentions every flag nobody passed is one nobody reads.
    #[test]
    fn the_exposed_banner_is_silent_about_an_allow_host_nobody_gave() {
        let scope = token_scope(Some("operator"), Some(&resolved("operator")));
        let text = posture_banner(Posture::Exposed, &scope, None, false).join(
            "
",
        );
        assert!(!text.contains("--allow-host"), "{text}");
    }

    /// The relay prints a generated enrolment token and, until now, nothing
    /// else — while the self-signed certificate beside it *is* persisted, so
    /// an operator had every reason to assume the token was too. It is not,
    /// and the failure is silent on both ends: the relay forgets it, and the
    /// devices retry in backoff against a token nobody holds any more.
    #[test]
    fn a_generated_enroll_token_says_it_is_not_saved() {
        let note = generated_enroll_token_note();
        assert!(
            note.contains("not saved"),
            "the fact has to be stated, not implied: {note}"
        );
        assert!(
            note.contains("--enroll-token"),
            "and it has to name the flag that fixes it: {note}"
        );
        // The line qualifies `Enroll token:` above it, whose label is fourteen
        // columns wide. Left-aligned it reads as an unrelated fact.
        assert!(note.starts_with("              "), "{note:?}");
    }

    #[test]
    fn the_local_banner_says_nothing() {
        // Local is zero friction. Nothing was narrowed, so there is nothing
        // to report.
        assert!(posture_banner(Posture::Local, &TokenScope::Wildcard, None, true).is_empty());
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
