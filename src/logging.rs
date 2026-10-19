//! Logging initialization and configuration.
//!
//! # Why colour is off
//!
//! The layer below is built with `with_ansi(false)`, and that is not a style
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

/// Initialize the logging system with an explicit filter.
///
/// `filter` is an `EnvFilter` directive string (`info`, `shell_tunnel=debug`,
/// …). One that does not parse falls back to `shell_tunnel=info`, the same
/// default [`try_init`] uses when `RUST_LOG` is unset.
///
/// The binary calls this rather than [`try_init`], and that is not a
/// convenience. It used to hand its resolved level to the subscriber by
/// writing it into its own `RUST_LOG` first — and every command `execute`
/// starts inherits the server's environment, so each one ran with a
/// `RUST_LOG` the caller never set, and every Rust tool among them logged at
/// that level into the output the caller asked for. A filter passed as an
/// argument reaches the subscriber and nothing else.
///
/// Diagnostics go to stderr, which leaves stdout for the things a caller wants
/// to read: the public URL, the API key, the command to try. Sharing one stream
/// means `shell-tunnel --tunnel | grep "Public URL"` picks up log lines instead.
///
/// # Panics
///
/// Panics if called more than once, or if another tracing subscriber
/// has already been set.
pub fn init(filter: &str) {
    install(EnvFilter::try_new(filter).unwrap_or_else(|_| default_filter()))
        .expect("logging is initialized once, before any other subscriber is set");
}

/// Try to initialize the logging system from the environment.
///
/// Filters by `RUST_LOG`, or `shell_tunnel=info` when it is unset or does not
/// parse. Returns `Err` if logging has already been initialized. This is the
/// entry point for a program embedding the library, which owns its own
/// environment; the binary uses [`init`].
pub fn try_init() -> Result<(), tracing_subscriber::util::TryInitError> {
    install(EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter()))
}

fn default_filter() -> EnvFilter {
    EnvFilter::new("shell_tunnel=info")
}

/// The one place the subscriber is assembled. `init` and `try_init` used to
/// build the same layer separately, and a change to it had to be made twice —
/// the `with_ansi(false)` below is there because that is exactly what happened
/// once already.
fn install(filter: EnvFilter) -> Result<(), tracing_subscriber::util::TryInitError> {
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

    /// A second `try_init` reports failure rather than panicking — the contract
    /// `init` turns back into a panic.
    ///
    /// Asserting on the *second* call is what makes this independent of test
    /// order: whether or not a subscriber was already set when this test began,
    /// one is certainly set after the first call, so the second must be `Err`.
    /// This used to call `try_init` twice and assert nothing at all, on the
    /// grounds that the first call's result depends on ordering — true of the
    /// first call, and the reason to check the second one instead.
    #[test]
    fn a_second_try_init_fails_instead_of_panicking() {
        let _ = try_init();
        assert!(
            try_init().is_err(),
            "a subscriber is set by now, so initializing again must report failure"
        );
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
