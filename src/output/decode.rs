//! Turning a command's output bytes into text.
//!
//! Output is UTF-8 when it can be. On Windows it often is not: a console
//! program writes in the machine's OEM code page (949 on a Korean system, 437 or
//! 850 on a Western one), and reading those bytes as UTF-8 turns every
//! non-ASCII character into U+FFFD — a loss the caller cannot undo, because the
//! original bytes are gone by the time it sees the text.
//!
//! The rule is: **UTF-8 when the bytes are UTF-8, the machine's OEM code page
//! otherwise.** The order matters. Reading everything in the code page would
//! break the programs that do write UTF-8 (`git`, `node`, anything that called
//! `chcp 65001` or `SetConsoleOutputCP`), while UTF-8 is a strict enough format
//! that real text in a legacy code page essentially never passes it.
//!
//! The unit is the **run of non-ASCII bytes between ASCII ones**, not the whole
//! output: one command can print UTF-8 from one program and a localized error
//! from `cmd` in the same stream, and ASCII bytes — escape sequences, newlines,
//! digits — are the same in every encoding involved, so cutting at them is safe.
//!
//! What this does not know: which code page a child *actually* used. A child
//! that switched its own console (`chcp 437`) and wrote something that is not
//! UTF-8 is read as the machine's OEM page. Unix has no machine code page to
//! name, so there non-UTF-8 bytes stay lossy as they always were.

/// A way of reading bytes that are not UTF-8.
trait Legacy: Sync {
    /// The code page's number, as `cp949` names it in a response.
    fn code_page(&self) -> u32;

    /// `run` — non-ASCII bytes only — as text, or `None` if it cannot be read.
    fn decode(&self, run: &[u8]) -> Option<String>;

    /// How many bytes at the end of `run` begin a character the run does not
    /// finish. A double-byte page has lead bytes whose second half may not have
    /// arrived yet; a single-byte page has none.
    fn incomplete_tail(&self, run: &[u8]) -> usize;
}

/// Output as text, and whether a legacy code page was needed to read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The text. UTF-8 where the bytes were UTF-8, the legacy page's characters
    /// where they were not.
    pub text: String,
    /// The code page some of the text was read from, when some of it was not
    /// UTF-8 — `None` when every byte was UTF-8 or no page could be applied.
    pub code_page: Option<u32>,
}

/// Decode one complete output.
pub fn decode_output(raw: &[u8]) -> Decoded {
    decode_with(raw, machine_legacy())
}

/// How many leading bytes of `raw` can be decoded now without cutting a
/// character in two: all of them unless `raw` ends in the middle of one.
///
/// For a reader that gets output in pieces and must hand each piece on as text.
pub fn decodable_len(raw: &[u8]) -> usize {
    decodable_len_with(raw, machine_legacy())
}

/// Decodes output that arrives in pieces, holding back the bytes of a
/// character split across two of them.
///
/// Decoding each piece alone turns a character cut by the chunk boundary into
/// replacement characters even when the output is plain UTF-8.
#[derive(Debug, Default)]
pub struct OutputDecoder {
    pending: Vec<u8>,
}

impl OutputDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The text of everything received so far that is a whole character.
    pub fn push(&mut self, piece: &[u8]) -> Decoded {
        self.push_with(piece, machine_legacy())
    }

    /// The text of what was held back, now that no more bytes are coming.
    pub fn finish(&mut self) -> Decoded {
        self.finish_with(machine_legacy())
    }

    fn finish_with(&mut self, legacy: Option<&dyn Legacy>) -> Decoded {
        let rest = std::mem::take(&mut self.pending);
        decode_with(&rest, legacy)
    }

    fn push_with(&mut self, piece: &[u8], legacy: Option<&dyn Legacy>) -> Decoded {
        self.pending.extend_from_slice(piece);
        let ready = decodable_len_with(&self.pending, legacy);
        let decoded = decode_with(&self.pending[..ready], legacy);
        self.pending.drain(..ready);
        decoded
    }
}

fn decode_with(raw: &[u8], legacy: Option<&dyn Legacy>) -> Decoded {
    let mut text = String::with_capacity(raw.len());
    let mut code_page = None;
    let mut rest = raw;
    while !rest.is_empty() {
        let error = match std::str::from_utf8(rest) {
            Ok(valid) => {
                text.push_str(valid);
                break;
            }
            Err(error) => error,
        };
        let bad_at = error.valid_up_to();
        // The whole run of non-ASCII bytes the first invalid byte sits in —
        // widened backwards over any bytes in it that happen to be valid UTF-8,
        // since a legacy page's text can contain a pair that is — and forwards
        // to the next ASCII byte.
        let mut start = bad_at;
        while start > 0 && rest[start - 1] >= 0x80 {
            start -= 1;
        }
        let end = rest[bad_at..]
            .iter()
            .position(|byte| *byte < 0x80)
            .map_or(rest.len(), |at| bad_at + at);
        if let Ok(valid) = std::str::from_utf8(&rest[..start]) {
            text.push_str(valid);
        }
        let run = &rest[start..end];
        match legacy.and_then(|page| Some((page.decode(run)?, page.code_page()))) {
            Some((decoded, page)) => {
                text.push_str(&decoded);
                code_page = Some(page);
            }
            None => text.push_str(&String::from_utf8_lossy(run)),
        }
        rest = &rest[end..];
    }
    Decoded { text, code_page }
}

fn decodable_len_with(raw: &[u8], legacy: Option<&dyn Legacy>) -> usize {
    let run_start = raw
        .iter()
        .rposition(|byte| *byte < 0x80)
        .map_or(0, |at| at + 1);
    let run = &raw[run_start..];
    let held = match std::str::from_utf8(run) {
        Ok(_) => 0,
        // Everything before the error is valid and the error is the end of the
        // input: a UTF-8 character with its tail still to come.
        Err(error) if error.error_len().is_none() => run.len() - error.valid_up_to(),
        Err(_) => legacy.map_or(0, |page| page.incomplete_tail(run)),
    };
    raw.len() - held
}

#[cfg(windows)]
fn machine_legacy() -> Option<&'static dyn Legacy> {
    use std::sync::OnceLock;
    static OEM: OnceLock<Option<windows::CodePage>> = OnceLock::new();
    OEM.get_or_init(windows::oem_code_page)
        .as_ref()
        .map(|page| page as &dyn Legacy)
}

#[cfg(not(windows))]
fn machine_legacy() -> Option<&'static dyn Legacy> {
    None
}

#[cfg(windows)]
mod windows {
    use super::Legacy;
    use windows_sys::Win32::Globalization::{GetOEMCP, IsDBCSLeadByteEx, MultiByteToWideChar};

    /// UTF-8 as a *system* code page (the "Beta: Use Unicode UTF-8" setting).
    /// Output in it is read as UTF-8 already; there is no legacy page to fall
    /// back to.
    const CP_UTF8: u32 = 65001;

    #[derive(Debug, Clone, Copy)]
    pub(super) struct CodePage(pub(super) u32);

    /// The page a console program writes in unless something changed it.
    pub(super) fn oem_code_page() -> Option<CodePage> {
        // SAFETY: no arguments, no memory.
        let page = unsafe { GetOEMCP() };
        (page != 0 && page != CP_UTF8).then_some(CodePage(page))
    }

    impl Legacy for CodePage {
        fn code_page(&self) -> u32 {
            self.0
        }

        fn decode(&self, run: &[u8]) -> Option<String> {
            decode_with_page(self.0, run)
        }

        fn incomplete_tail(&self, run: &[u8]) -> usize {
            incomplete_tail_in(self.0, run)
        }
    }

    pub(super) fn decode_with_page(page: u32, run: &[u8]) -> Option<String> {
        let len = i32::try_from(run.len()).ok()?;
        // SAFETY: `run` is `len` readable bytes; a null output with length 0
        // asks only for the size needed.
        let needed =
            unsafe { MultiByteToWideChar(page, 0, run.as_ptr(), len, std::ptr::null_mut(), 0) };
        if needed <= 0 {
            return None;
        }
        let mut wide = vec![0u16; needed as usize];
        // SAFETY: `wide` has `needed` writable elements, the size just asked for.
        let written =
            unsafe { MultiByteToWideChar(page, 0, run.as_ptr(), len, wide.as_mut_ptr(), needed) };
        if written <= 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&wide[..written as usize]))
    }

    /// Walk the run from its start: a lead byte takes the byte after it, so the
    /// run's last byte is the first half of a character exactly when the walk
    /// lands on it as a lead. Looking only at the last byte would mistake a
    /// second half (whose range overlaps the lead range) for a first.
    pub(super) fn incomplete_tail_in(page: u32, run: &[u8]) -> usize {
        let mut at = 0;
        while at < run.len() {
            // SAFETY: plain value arguments.
            let lead = unsafe { IsDBCSLeadByteEx(page, run[at]) } != 0;
            if lead {
                if at + 1 >= run.len() {
                    return 1;
                }
                at += 2;
            } else {
                at += 1;
            }
        }
        0
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // Korean (949) is installed on every Windows, whatever its locale, so
        // the conversion is testable on a machine that is not Korean.
        const HANGEUL_949: &[u8] = &[0xC7, 0xD1, 0xB1, 0xDB];

        #[test]
        fn a_code_page_run_becomes_its_characters() {
            assert_eq!(decode_with_page(949, HANGEUL_949).as_deref(), Some("한글"));
        }

        #[test]
        fn a_double_byte_character_cut_in_two_is_held() {
            // C7 D1 B1 | DB: the walk takes C7+D1 as one character and finds B1
            // alone, so one byte is held.
            assert_eq!(incomplete_tail_in(949, &HANGEUL_949[..3]), 1);
            assert_eq!(incomplete_tail_in(949, HANGEUL_949), 0);
            // A second half whose value is also in the lead range is not a lead:
            // C7 D1 alone is complete although D1 could begin a character.
            assert_eq!(incomplete_tail_in(949, &HANGEUL_949[..2]), 0);
        }

        #[test]
        fn a_single_byte_page_has_no_lead_bytes() {
            // 437: 0x82 is é; nothing is ever left waiting for a second byte.
            assert_eq!(decode_with_page(437, &[0x82]).as_deref(), Some("é"));
            assert_eq!(incomplete_tail_in(437, &[0x82]), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in legacy page that reads each character as `<hex>`, with
    /// `0xB0..=0xC8` as lead bytes taking the byte after them: enough to see
    /// *which bytes* were handed to a legacy page without depending on an
    /// operating system's tables, so these tests run the same on every platform.
    /// Character by character, like a real page: cutting a run between two
    /// characters must not change what it reads as.
    struct Fake;

    impl Legacy for Fake {
        fn code_page(&self) -> u32 {
            949
        }
        fn decode(&self, run: &[u8]) -> Option<String> {
            let mut text = String::new();
            let mut at = 0;
            while at < run.len() {
                let width = if (0xB0..=0xC8).contains(&run[at]) {
                    2
                } else {
                    1
                };
                let end = (at + width).min(run.len());
                let hex: String = run[at..end].iter().map(|b| format!("{b:02x}")).collect();
                text.push_str(&format!("<{hex}>"));
                at = end;
            }
            Some(text)
        }
        fn incomplete_tail(&self, run: &[u8]) -> usize {
            let mut at = 0;
            while at < run.len() {
                if (0xB0..=0xC8).contains(&run[at]) {
                    if at + 1 >= run.len() {
                        return 1;
                    }
                    at += 2;
                } else {
                    at += 1;
                }
            }
            0
        }
    }

    static FAKE: Fake = Fake;

    fn decode(raw: &[u8]) -> Decoded {
        decode_with(raw, Some(&FAKE))
    }

    #[test]
    fn utf8_is_left_as_it_is_and_no_page_is_named() {
        let decoded = decode("한글 and é, 100%\r\n".as_bytes());
        assert_eq!(decoded.text, "한글 and é, 100%\r\n");
        assert_eq!(decoded.code_page, None);
    }

    #[test]
    fn bytes_that_are_not_utf8_are_read_in_the_legacy_page() {
        let decoded = decode(b"ok \xC7\xD1\xB1\xDB done\r\n");
        assert_eq!(decoded.text, "ok <c7d1><b1db> done\r\n");
        assert_eq!(decoded.code_page, Some(949));
    }

    #[test]
    fn without_a_legacy_page_the_bytes_stay_lossy_as_before() {
        let decoded = decode_with(b"x \xC7\xD1 y", None);
        assert_eq!(decoded.text, "x \u{FFFD}\u{FFFD} y");
        assert_eq!(decoded.code_page, None);
    }

    #[test]
    fn utf8_and_legacy_text_in_one_output_are_each_read_as_what_they_are() {
        // A UTF-8 line from one program, a legacy-page line from another.
        let mut raw = "한글\n".as_bytes().to_vec();
        raw.extend_from_slice(b"\xC7\xD1\n");
        let decoded = decode(&raw);
        assert_eq!(decoded.text, "한글\n<c7d1>\n");
        assert_eq!(decoded.code_page, Some(949));
    }

    #[test]
    fn a_run_is_read_whole_even_where_part_of_it_is_valid_utf8() {
        // C3 A9 is `é` in UTF-8, but it sits in the same run as the bytes that
        // are not, so the run is one legacy-page text.
        let decoded = decode(b"a \xC3\xA9\xC7\xD1 b");
        assert_eq!(decoded.text, "a <c3a9><c7d1> b");
    }

    #[test]
    fn ascii_around_a_run_is_never_inside_it() {
        let decoded = decode(b"\x1b[31m\xC7\xD1\x1b[0m");
        assert_eq!(decoded.text, "\x1b[31m<c7d1>\x1b[0m");
    }

    #[test]
    fn a_utf8_character_cut_by_the_end_of_a_piece_is_held() {
        let han = "한".as_bytes(); // ED 95 9C
        assert_eq!(decodable_len_with(&han[..2], None), 0);
        assert_eq!(decodable_len_with(&han[..3], None), 3);
        let mut raw = b"ab".to_vec();
        raw.extend_from_slice(&han[..1]);
        assert_eq!(decodable_len_with(&raw, None), 2);
    }

    #[test]
    fn a_legacy_character_cut_by_the_end_of_a_piece_is_held() {
        assert_eq!(decodable_len_with(b"a\xC7\xD1\xB1", Some(&FAKE)), 3);
        assert_eq!(decodable_len_with(b"a\xC7\xD1\xB1\xDB", Some(&FAKE)), 5);
        // Ending in ASCII, nothing is ever held.
        assert_eq!(decodable_len_with(b"\xC7\xD1\r\n", Some(&FAKE)), 4);
    }

    #[test]
    fn pieces_decode_to_what_the_whole_decodes_to() {
        let mut raw = b"first \xC7\xD1\xB1\xDB mid ".to_vec();
        raw.extend_from_slice("한글 end".as_bytes());
        let whole = decode(&raw);
        // Every way of cutting the stream into two pieces, and into singles.
        for cut in 0..=raw.len() {
            let mut decoder = OutputDecoder::new();
            let mut text = decoder.push_with(&raw[..cut], Some(&FAKE)).text;
            text.push_str(&decoder.push_with(&raw[cut..], Some(&FAKE)).text);
            // `finish` reads what is left with the machine's page; nothing may
            // be left here because the input ends on ASCII.
            assert!(decoder.pending.is_empty(), "cut at {cut}");
            assert_eq!(text, whole.text, "cut at {cut}");
        }
        let mut decoder = OutputDecoder::new();
        let mut text = String::new();
        for byte in &raw {
            text.push_str(&decoder.push_with(&[*byte], Some(&FAKE)).text);
        }
        assert_eq!(text, whole.text);
    }

    #[test]
    fn finishing_hands_back_what_was_held() {
        let mut decoder = OutputDecoder::new();
        let han = "한".as_bytes();
        assert_eq!(decoder.push_with(&han[..2], None).text, "");
        // The stream ended mid-character: what arrived is all there will be.
        assert_eq!(decoder.finish_with(None).text, "\u{FFFD}");
        assert!(decoder.pending.is_empty());
    }
}
