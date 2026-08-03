//! Logging initialization and configuration.
//!
//! # Why colour is off
//!
//! Both initializers below pass `with_ansi(false)`, and that is not a style
//! choice. The `fmt` layer colours its output whenever `tracing-subscriber`'s
//! `ansi` feature is compiled in, and that default asks nothing about what is
//! downstream: it does not test whether stderr is a terminal, and on Windows
//! it does not enable the console's virtual-terminal mode either. Escapes
//! therefore reached every consumer of the logs — the file a service
//! definition redirects to, an agent reading the pipe, and consoles that
//! print them literally as `←[2m` in front of every line.
//!
//! Colour is switched off rather than made conditional, because the condition
//! cannot be answered honestly here. `IsTerminal` alone does not settle it on
//! Windows, where a console handle reports as a terminal whether or not it
//! will interpret an escape; answering it properly means enabling
//! virtual-terminal mode through the Win32 console API and falling back when
//! that fails — a direct platform dependency and a block of `unsafe` FFI,
//! bought for decoration on a headless gateway whose output is read by service
//! managers, log files and agents far more often than by a person. The one
//! surface an operator actually reads, the startup banner, is `println!` on
//! stdout and was never coloured.
//!
//! This also holds the program's own logs to the rule its command output
//! already follows: piped output is escape-free, because that is what makes it
//! usable as structured data.
//!
//! `tests/main_startup_e2e.rs::the_log_stream_carries_no_ansi_escapes` is what
//! keeps this true. A record's *text* is identical either way, so only a real
//! process writing to a real pipe can tell the two apart — no unit test in
//! this module can.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the logging system.
///
/// Uses the `RUST_LOG` environment variable for filtering. If not set,
/// defaults to `shell_tunnel=info`.
///
/// Diagnostics go to stderr, which leaves stdout for the things a caller wants
/// to read: the public URL, the API key, the command to try. Sharing one stream
/// means `shell-tunnel --tunnel | grep "Public URL"` picks up log lines instead.
///
/// # Panics
///
/// Panics if called more than once, or if another tracing subscriber
/// has already been set.
pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("shell_tunnel=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_ansi(false)
                .with_writer(std::io::stderr),
        )
        .init();
}

/// Try to initialize the logging system.
///
/// Returns `Ok(())` if successful, or `Err` if logging has already been
/// initialized.
pub fn try_init() -> Result<(), tracing_subscriber::util::TryInitError> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("shell_tunnel=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_ansi(false)
                .with_writer(std::io::stderr),
        )
        .try_init()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_init_idempotent() {
        // First call may or may not succeed depending on test order
        let _ = try_init();
        // Second call should return error (already initialized)
        // or succeed if this is the first test to run
        let _ = try_init();
        // Either way, we shouldn't panic
    }

    #[test]
    fn test_logging_works() {
        // Ensure we can emit log messages without panicking
        let _ = try_init();

        tracing::info!("test info message");
        tracing::debug!("test debug message");
        tracing::warn!("test warn message");
        tracing::error!("test error message");
        // If we get here without panicking, the test passes
    }
}
