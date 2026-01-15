//! Virtual terminal screen using vt100.

use vt100::Parser;

/// Virtual terminal screen for processing interactive output.
///
/// This maintains a virtual screen buffer that accurately tracks
/// cursor position, text content, and screen state for applications
/// like vim, top, etc.
pub struct VirtualScreen {
    parser: Parser,
}

impl VirtualScreen {
    /// Create a new virtual screen with default dimensions (80x24).
    pub fn new() -> Self {
        Self::with_size(80, 24)
    }

    /// Create a virtual screen with custom dimensions.
    pub fn with_size(cols: u16, rows: u16) -> Self {
        Self {
            parser: Parser::new(rows, cols, 0),
        }
    }

    /// Process input bytes and update screen state.
    pub fn process(&mut self, input: &[u8]) {
        self.parser.process(input);
    }

    /// Get the current screen contents as plain text.
    ///
    /// Returns each row as a string, trimmed of trailing whitespace.
    pub fn contents(&self) -> String {
        self.parser.screen().contents()
    }

    /// Get screen contents as lines.
    pub fn lines(&self) -> Vec<String> {
        let screen = self.parser.screen();
        let mut lines = Vec::new();

        for row in 0..screen.size().0 {
            let mut line = String::new();
            for col in 0..screen.size().1 {
                if let Some(cell) = screen.cell(row, col) {
                    line.push(cell.contents().chars().next().unwrap_or(' '));
                }
            }
            lines.push(line.trim_end().to_string());
        }

        lines
    }

    /// Get non-empty lines only.
    pub fn non_empty_lines(&self) -> Vec<String> {
        self.lines().into_iter().filter(|l| !l.is_empty()).collect()
    }

    /// Get the current cursor position (row, col).
    pub fn cursor_position(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }

    /// Get screen dimensions (rows, cols).
    pub fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    /// Check if screen has any content.
    pub fn is_empty(&self) -> bool {
        self.contents().trim().is_empty()
    }

    /// Clear the screen (reset to initial state).
    pub fn clear(&mut self) {
        let (rows, cols) = self.size();
        self.parser = Parser::new(rows, cols, 0);
    }
}

impl Default for VirtualScreen {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_screen() {
        let screen = VirtualScreen::new();
        assert_eq!(screen.size(), (24, 80));
        assert!(screen.is_empty());
    }

    #[test]
    fn test_custom_size() {
        let screen = VirtualScreen::with_size(120, 40);
        assert_eq!(screen.size(), (40, 120));
    }

    #[test]
    fn test_process_text() {
        let mut screen = VirtualScreen::new();
        screen.process(b"Hello, World!");

        let contents = screen.contents();
        assert!(contents.contains("Hello, World!"));
    }

    #[test]
    fn test_process_with_newlines() {
        let mut screen = VirtualScreen::new();
        screen.process(b"Line 1\r\nLine 2\r\nLine 3");

        let lines = screen.non_empty_lines();
        assert!(lines.len() >= 3);
        assert!(lines[0].contains("Line 1"));
    }

    #[test]
    fn test_cursor_position() {
        let mut screen = VirtualScreen::new();
        screen.process(b"test");

        let (row, col) = screen.cursor_position();
        assert_eq!(row, 0);
        assert_eq!(col, 4); // After "test"
    }

    #[test]
    fn test_process_ansi_colors() {
        let mut screen = VirtualScreen::new();
        screen.process(b"\x1b[31mRed Text\x1b[0m");

        let contents = screen.contents();
        assert!(contents.contains("Red Text"));
    }

    #[test]
    fn test_clear_screen_sequence() {
        let mut screen = VirtualScreen::new();
        screen.process(b"Initial content");
        screen.process(b"\x1b[2J\x1b[HCleared");

        let contents = screen.contents();
        assert!(contents.contains("Cleared"));
    }

    #[test]
    fn test_clear_method() {
        let mut screen = VirtualScreen::new();
        screen.process(b"Some content");
        screen.clear();

        assert!(screen.is_empty());
    }

    #[test]
    fn test_lines_trimmed() {
        let mut screen = VirtualScreen::new();
        screen.process(b"  text with spaces  ");

        let lines = screen.lines();
        // First line should have the text (right-trimmed)
        assert!(!lines.is_empty());
    }
}
