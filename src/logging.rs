//! Logging initialization and configuration.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the logging system.
///
/// Uses the `RUST_LOG` environment variable for filtering. If not set,
/// defaults to `shell_tunnel=info`.
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
        .with(tracing_subscriber::fmt::layer().compact())
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
        .with(tracing_subscriber::fmt::layer().compact())
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
