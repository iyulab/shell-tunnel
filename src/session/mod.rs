//! Session management module.
//!
//! This module provides types and utilities for managing shell sessions,
//! including session identification, state tracking, and storage.

mod busy;
mod context;
mod id;
mod state;
mod store;

use std::time::Duration;

/// How long a session may sit idle before it is swept.
///
/// The same hour upload sessions have used since they were introduced
/// (`fs::SESSION_TTL`), and deliberately the same figure rather than a second
/// one to reason about: both answer "how long does an abandoned thing stay?" for
/// the same product, and an operator who has learned one should not have to
/// learn the other. Kept as its own constant because the two are different
/// resources — an upload session holds an open file handle and a staging file,
/// a shell session holds bookkeeping — and either may need to move without the
/// other.
///
/// Comfortably above `execution::MAX_TIMEOUT`, so a session cannot age out
/// merely because one long command ran in it.
pub const IDLE_TTL: Duration = Duration::from_secs(3600);

pub(crate) use busy::BusySession;
pub use context::SessionContext;
pub use id::SessionId;
pub use state::SessionState;
pub use store::{Session, SessionStore};
