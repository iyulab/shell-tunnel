//! Shell-tunnel binary entry point.

use shell_tunnel::{logging, NativePty, PtySize, SessionConfig, SessionStore};
use tracing::info;

#[tokio::main]
async fn main() -> shell_tunnel::Result<()> {
    // Initialize logging
    logging::init();

    info!("shell-tunnel v{}", env!("CARGO_PKG_VERSION"));
    info!("Starting shell-tunnel server...");

    // Create session store
    let store = SessionStore::new();
    info!("Session store initialized");

    // Create a test session
    let session_id = store.create(SessionConfig::default())?;
    info!("Test session created: {}", session_id);

    // Spawn a PTY
    let pty = NativePty::new();
    let handle = pty.spawn_default(PtySize::default())?;
    info!("PTY spawned with PID: {}", handle.pid);

    // Update session state
    store.update(&session_id, |s| {
        s.state = shell_tunnel::SessionState::Active;
    })?;

    info!("Session {} is now active", session_id);
    info!("shell-tunnel initialized successfully");

    // TODO: Start API server in Phase 3

    Ok(())
}
