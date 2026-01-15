//! Output processing and sanitization.
//!
//! This module provides tools for processing terminal output:
//! - ANSI escape code stripping
//! - Virtual terminal screen emulation
//!
//! # Example
//!
//! ```
//! use shell_tunnel::output::{OutputSanitizer, VirtualScreen};
//!
//! // Strip ANSI codes from raw output
//! let raw = b"\x1b[31mRed text\x1b[0m";
//! let clean = OutputSanitizer::strip_ansi(raw);
//! assert_eq!(clean, "Red text");
//!
//! // Use virtual screen for interactive apps
//! let mut screen = VirtualScreen::new();
//! screen.process(b"Hello\r\nWorld");
//! let lines = screen.non_empty_lines();
//! ```

mod sanitizer;
mod screen;

pub use sanitizer::OutputSanitizer;
pub use screen::VirtualScreen;
