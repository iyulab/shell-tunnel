//! PTY (Pseudo-Terminal) abstraction layer.
//!
//! This module provides a platform-independent interface for working with
//! pseudo-terminals. It supports both Unix PTY and Windows ConPTY.

mod async_adapter;
mod native;

pub use async_adapter::{AsyncPtyReader, AsyncPtyWriter};
pub use native::{default_shell, NativePty};

use std::io::{Read, Write};

/// Size of a PTY in characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    /// Number of rows (height).
    pub rows: u16,
    /// Number of columns (width).
    pub cols: u16,
}

impl PtySize {
    /// Create a new PtySize with the given dimensions.
    pub fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }
}

impl Default for PtySize {
    fn default() -> Self {
        Self { rows: 24, cols: 80 }
    }
}

/// A handle to a spawned PTY process.
pub struct PtyHandle<R: Read + Send, W: Write + Send> {
    /// Reader for the PTY output.
    pub reader: R,
    /// Writer for the PTY input.
    pub writer: W,
    /// Process ID of the spawned child.
    pub pid: u32,
    /// The underlying PTY pair (kept alive to prevent cleanup).
    _pty: Box<dyn std::any::Any + Send>,
}

impl<R: Read + Send, W: Write + Send> PtyHandle<R, W> {
    /// Create a new PtyHandle.
    pub fn new(reader: R, writer: W, pid: u32, pty: Box<dyn std::any::Any + Send>) -> Self {
        Self {
            reader,
            writer,
            pid,
            _pty: pty,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_size_default() {
        let size = PtySize::default();
        assert_eq!(size.rows, 24);
        assert_eq!(size.cols, 80);
    }

    #[test]
    fn test_pty_size_new() {
        let size = PtySize::new(40, 120);
        assert_eq!(size.rows, 40);
        assert_eq!(size.cols, 120);
    }

    #[test]
    fn test_pty_size_equality() {
        let size1 = PtySize::new(24, 80);
        let size2 = PtySize::default();
        assert_eq!(size1, size2);

        let size3 = PtySize::new(30, 100);
        assert_ne!(size1, size3);
    }
}
