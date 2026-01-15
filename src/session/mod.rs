//! Session management module.
//!
//! This module provides types and utilities for managing shell sessions,
//! including session identification, state tracking, and storage.

mod context;
mod id;
mod state;
mod store;

pub use context::{SessionContext, StateProbe};
pub use id::SessionId;
pub use state::SessionState;
pub use store::{Session, SessionConfig, SessionStore};
