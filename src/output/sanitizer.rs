//! Output sanitization for stripping ANSI escape codes.

use vte::{Params, Parser, Perform};

/// Output sanitizer using VTE parser.
pub struct OutputSanitizer;

impl OutputSanitizer {
    /// Strip ANSI escape codes from raw bytes.
    ///
    /// Returns clean UTF-8 text with all control sequences removed.
    pub fn strip_ansi(input: &[u8]) -> String {
        let mut extractor = PlainTextExtractor::new();
        let mut parser = Parser::new();

        parser.advance(&mut extractor, input);

        extractor.into_string()
    }

    /// Strip ANSI codes from a string.
    pub fn strip_ansi_str(input: &str) -> String {
        Self::strip_ansi(input.as_bytes())
    }
}

/// VTE performer that extracts plain text.
struct PlainTextExtractor {
    output: Vec<u8>,
}

impl PlainTextExtractor {
    fn new() -> Self {
        Self { output: Vec::new() }
    }

    fn into_string(self) -> String {
        String::from_utf8_lossy(&self.output).into_owned()
    }
}

impl Perform for PlainTextExtractor {
    fn print(&mut self, c: char) {
        let mut buf = [0u8; 4];
        let encoded = c.encode_utf8(&mut buf);
        self.output.extend_from_slice(encoded.as_bytes());
    }

    fn execute(&mut self, byte: u8) {
        // Handle control characters
        match byte {
            // Newline, carriage return, tab
            0x0A | 0x0D | 0x09 => self.output.push(byte),
            // Ignore other control characters
            _ => {}
        }
    }

    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _action: char) {
        // Ignore DCS sequences
    }

    fn put(&mut self, _byte: u8) {
        // Ignore DCS data
    }

    fn unhook(&mut self) {
        // Ignore DCS end
    }

    fn osc_dispatch(&mut self, _params: &[&[u8]], _bell_terminated: bool) {
        // Ignore OSC sequences
    }

    fn csi_dispatch(
        &mut self,
        _params: &Params,
        _intermediates: &[u8],
        _ignore: bool,
        _action: char,
    ) {
        // Ignore CSI sequences (cursor movement, colors, etc.)
    }

    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {
        // Ignore escape sequences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_text() {
        let input = b"hello world";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "hello world");
    }

    #[test]
    fn test_strip_color_codes() {
        // "\x1b[31mred\x1b[0m" - red text with reset
        let input = b"\x1b[31mred\x1b[0m";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "red");
    }

    #[test]
    fn test_strip_bold() {
        // "\x1b[1mbold\x1b[0m"
        let input = b"\x1b[1mbold\x1b[0m";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "bold");
    }

    #[test]
    fn test_preserve_newlines() {
        let input = b"line1\nline2\nline3";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "line1\nline2\nline3");
    }

    #[test]
    fn test_strip_cursor_movement() {
        // "\x1b[2J\x1b[H" - clear screen and home cursor
        let input = b"\x1b[2J\x1b[Hcontent";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "content");
    }

    #[test]
    fn test_complex_sequence() {
        // Mix of colors, bold, cursor movement
        let input = b"\x1b[32m\x1b[1mGreen Bold\x1b[0m Normal \x1b[34mBlue\x1b[0m";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "Green Bold Normal Blue");
    }

    #[test]
    fn test_osc_title() {
        // "\x1b]0;Window Title\x07" - set window title
        let input = b"\x1b]0;Window Title\x07actual content";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "actual content");
    }

    #[test]
    fn test_strip_ansi_str() {
        let input = "\x1b[31mcolored\x1b[0m";
        let output = OutputSanitizer::strip_ansi_str(input);
        assert_eq!(output, "colored");
    }

    #[test]
    fn test_preserve_tabs() {
        let input = b"col1\tcol2\tcol3";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "col1\tcol2\tcol3");
    }

    #[test]
    fn test_empty_input() {
        let output = OutputSanitizer::strip_ansi(b"");
        assert_eq!(output, "");
    }

    #[test]
    fn test_only_escape_codes() {
        let input = b"\x1b[31m\x1b[0m\x1b[2J";
        let output = OutputSanitizer::strip_ansi(input);
        assert_eq!(output, "");
    }
}
