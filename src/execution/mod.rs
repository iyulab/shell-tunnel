//! Command execution engine.
//!
//! This module provides command execution capabilities:
//! - Synchronous and asynchronous execution
//! - Timeout handling
//! - Streaming output
//!
//! # Example
//!
//! ```no_run
//! use shell_tunnel::execution::{Command, execute_simple};
//!
//! // Simple one-shot execution
//! let result = execute_simple("echo hello").unwrap();
//! println!("Output: {}", result.text_output);
//!
//! // Command with options
//! use std::time::Duration;
//! let cmd = Command::new("cargo build")
//!     .timeout(Duration::from_secs(60))
//!     .capture_output(true);
//! ```

mod command;
mod executor;
mod result;

pub use command::{Command, CommandBuilder};
pub use executor::{execute_simple, execute_with_timeout, CommandExecutor, DEFAULT_TIMEOUT};
pub use result::{ExecutionResult, OutputChunk, OutputSource};
