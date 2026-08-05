//! Session management module.
//!
//! This module provides types and utilities for managing shell sessions,
//! including session identification, state tracking, and storage.

mod busy;
mod context;
mod id;
mod state;
mod store;

pub(crate) use busy::BusySession;
pub use context::SessionContext;
pub use id::SessionId;
pub use state::SessionState;
pub use store::{Session, SessionStore};
