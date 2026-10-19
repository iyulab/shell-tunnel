//! Reading an HTTP/1.1 response as it arrives.
//!
//! A device replays each relayed request against its local server and has to
//! hand the answer back. Reading the whole response first and passing the raw
//! body on had two faults: nothing reached the caller before the end, and a
//! `chunked` body crossed the relay still chunk-encoded while the relay drops
//! `transfer-encoding` as a hop-by-hop header — so the caller would have read
//! the chunk-size lines as data. This reader decodes the framing as bytes come
//! in and yields the head once, then body bytes, then the end.
//!
//! Pure: no I/O, so every framing and every way of being cut short is tested
//! here byte by byte.

/// One thing the reader learned from the bytes fed to it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplayEvent {
    /// The status and the headers worth forwarding (hop-by-hop ones dropped).
    Head {
        status: u16,
        headers: Vec<(String, String)>,
    },
    /// Decoded body bytes.
    Body(Vec<u8>),
    /// The body is complete by its own framing.
    End,
}

/// Why a response could not be read to its end.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplayError {
    /// The status line or the framing was not HTTP/1.1 this reader understands.
    Malformed(&'static str),
    /// The connection ended before the framing said the body was complete.
    CutShort,
}

#[derive(Debug)]
enum State {
    Head,
    Sized(u64),
    UntilEof,
    ChunkSize,
    ChunkData(u64),
    ChunkDataEnd,
    Trailers,
    Done,
}

/// Longest head (status line and headers) this reader will hold.
const MAX_HEAD: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct ResponseReader {
    state: State,
    buf: Vec<u8>,
    /// The request was `HEAD`: the response has headers only, whatever length
    /// they declare.
    to_head: bool,
}

impl Default for ResponseReader {
    fn default() -> Self {
        Self {
            state: State::Head,
            buf: Vec::new(),
            to_head: false,
        }
    }
}

impl ResponseReader {
    /// A reader for the response to a request with this method.
    ///
    /// The method matters for exactly one: a response to `HEAD` carries the
    /// `content-length` the `GET` would have, and no body (RFC 9110 §9.3.2).
    /// Read by its headers alone it waits for bytes that never come, and the
    /// connection closing reads as a response cut short.
    pub(crate) fn for_method(method: &str) -> Self {
        Self {
            to_head: method.eq_ignore_ascii_case("HEAD"),
            ..Self::default()
        }
    }

    /// Feed bytes as they arrive; returns what they completed.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<Vec<ReplayEvent>, ReplayError> {
        self.buf.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            let progressed = match self.state {
                State::Head => self.head(&mut events)?,
                State::Sized(remaining) => {
                    let take = (self.buf.len() as u64).min(remaining) as usize;
                    if take > 0 {
                        events.push(ReplayEvent::Body(self.buf.drain(..take).collect()));
                    }
                    let left = remaining - take as u64;
                    if left == 0 {
                        self.state = State::Done;
                        events.push(ReplayEvent::End);
                    } else {
                        self.state = State::Sized(left);
                    }
                    left == 0 && !self.buf.is_empty()
                }
                State::UntilEof => {
                    if !self.buf.is_empty() {
                        events.push(ReplayEvent::Body(std::mem::take(&mut self.buf)));
                    }
                    false
                }
                State::ChunkSize => match self.line() {
                    None => false,
                    Some(line) => {
                        let size_text = line.split(';').next().unwrap_or("").trim();
                        let size = u64::from_str_radix(size_text, 16)
                            .map_err(|_| ReplayError::Malformed("bad chunk size"))?;
                        self.state = if size == 0 {
                            State::Trailers
                        } else {
                            State::ChunkData(size)
                        };
                        true
                    }
                },
                State::ChunkData(remaining) => {
                    let take = (self.buf.len() as u64).min(remaining) as usize;
                    if take > 0 {
                        events.push(ReplayEvent::Body(self.buf.drain(..take).collect()));
                    }
                    let left = remaining - take as u64;
                    self.state = if left == 0 {
                        State::ChunkDataEnd
                    } else {
                        State::ChunkData(left)
                    };
                    left == 0
                }
                State::ChunkDataEnd => {
                    if self.buf.len() < 2 {
                        false
                    } else if self.buf.starts_with(b"\r\n") {
                        self.buf.drain(..2);
                        self.state = State::ChunkSize;
                        true
                    } else {
                        return Err(ReplayError::Malformed("chunk not followed by CRLF"));
                    }
                }
                State::Trailers => match self.line() {
                    None => false,
                    Some(line) if line.is_empty() => {
                        self.state = State::Done;
                        events.push(ReplayEvent::End);
                        false
                    }
                    Some(_) => true,
                },
                State::Done => {
                    self.buf.clear();
                    false
                }
            };
            if !progressed {
                return Ok(events);
            }
        }
    }

    /// The connection closed. Completes a body framed by the close itself,
    /// and reports any other framing left unfinished.
    pub(crate) fn finish(&mut self) -> Result<Vec<ReplayEvent>, ReplayError> {
        match self.state {
            State::Done => Ok(Vec::new()),
            State::UntilEof => {
                self.state = State::Done;
                let mut events = Vec::new();
                if !self.buf.is_empty() {
                    events.push(ReplayEvent::Body(std::mem::take(&mut self.buf)));
                }
                events.push(ReplayEvent::End);
                Ok(events)
            }
            _ => Err(ReplayError::CutShort),
        }
    }

    /// Take one CRLF-terminated line off the buffer, if a whole one is there.
    fn line(&mut self) -> Option<String> {
        let end = self.buf.windows(2).position(|w| w == b"\r\n")?;
        let line = String::from_utf8_lossy(&self.buf[..end]).into_owned();
        self.buf.drain(..end + 2);
        Some(line)
    }

    fn head(&mut self, events: &mut Vec<ReplayEvent>) -> Result<bool, ReplayError> {
        let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            if self.buf.len() > MAX_HEAD {
                return Err(ReplayError::Malformed("response head too long"));
            }
            return Ok(false);
        };
        let head = String::from_utf8_lossy(&self.buf[..end]).into_owned();
        self.buf.drain(..end + 4);
        let mut lines = head.split("\r\n");
        let status: u16 = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or(ReplayError::Malformed("no status line"))?;

        let mut headers = Vec::new();
        let mut length: Option<u64> = None;
        let mut chunked = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let (name, value) = (name.trim(), value.trim());
            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.to_ascii_lowercase().contains("chunked");
            } else if name.eq_ignore_ascii_case("content-length") {
                length = Some(
                    value
                        .parse()
                        .map_err(|_| ReplayError::Malformed("bad content-length"))?,
                );
            }
            if super::proxy::is_forwardable(name) {
                headers.push((name.to_string(), value.to_string()));
            }
        }
        if chunked {
            // A chunked body is decoded here and re-framed by the relay, so a
            // length the sender also gave describes nothing the caller gets.
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-length"));
        }
        events.push(ReplayEvent::Head { status, headers });

        // RFC 9112 §6.3: no body for these, whatever the headers say.
        let bodiless =
            self.to_head || (100..200).contains(&status) || status == 204 || status == 304;
        self.state = if bodiless {
            events.push(ReplayEvent::End);
            State::Done
        } else if chunked {
            State::ChunkSize
        } else if let Some(n) = length {
            if n == 0 {
                events.push(ReplayEvent::End);
                State::Done
            } else {
                State::Sized(n)
            }
        } else {
            State::UntilEof
        };
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `raw` one byte at a time — the worst split there is — then close.
    fn read_bytewise(raw: &[u8]) -> Result<Vec<ReplayEvent>, ReplayError> {
        let mut reader = ResponseReader::default();
        let mut events = Vec::new();
        for byte in raw {
            events.extend(reader.feed(std::slice::from_ref(byte))?);
        }
        events.extend(reader.finish()?);
        Ok(events)
    }

    fn body_of(events: &[ReplayEvent]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                ReplayEvent::Body(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[test]
    fn a_sized_body_ends_at_its_length() {
        let events =
            read_bytewise(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-a: 1\r\n\r\nhello").unwrap();
        assert_eq!(
            events[0],
            ReplayEvent::Head {
                status: 200,
                headers: vec![
                    ("content-length".into(), "5".into()),
                    ("x-a".into(), "1".into())
                ],
            }
        );
        assert_eq!(body_of(&events), b"hello");
        assert_eq!(events.last(), Some(&ReplayEvent::End));
    }

    #[test]
    fn a_chunked_body_is_decoded_and_loses_its_framing_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n7\r\n, world\r\n0\r\nx-trailer: t\r\n\r\n";
        let events = read_bytewise(raw).unwrap();
        assert_eq!(
            events[0],
            ReplayEvent::Head {
                status: 200,
                headers: vec![]
            },
            "transfer-encoding is hop-by-hop and is not forwarded"
        );
        assert_eq!(body_of(&events), b"hello, world");
        assert_eq!(events.last(), Some(&ReplayEvent::End));
    }

    #[test]
    fn a_body_framed_by_the_close_ends_at_the_close() {
        let events = read_bytewise(b"HTTP/1.1 200 OK\r\n\r\nuntil eof").unwrap();
        assert_eq!(body_of(&events), b"until eof");
        assert_eq!(events.last(), Some(&ReplayEvent::End));
    }

    #[test]
    fn a_bodiless_status_ends_at_its_head() {
        let mut reader = ResponseReader::default();
        let events = reader
            .feed(b"HTTP/1.1 204 No Content\r\ncontent-length: 10\r\n\r\n")
            .unwrap();
        assert_eq!(events.last(), Some(&ReplayEvent::End));
    }

    #[test]
    fn a_body_cut_short_is_an_error_not_an_end() {
        let mut reader = ResponseReader::default();
        let events = reader
            .feed(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhalf")
            .unwrap();
        assert!(!events.contains(&ReplayEvent::End));
        assert_eq!(reader.finish(), Err(ReplayError::CutShort));

        let mut reader = ResponseReader::default();
        reader
            .feed(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhel")
            .unwrap();
        assert_eq!(reader.finish(), Err(ReplayError::CutShort));
    }

    #[test]
    fn nothing_after_the_framing_is_taken_as_body() {
        let events = read_bytewise(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nokEXTRA").unwrap();
        assert_eq!(body_of(&events), b"ok");
    }

    #[test]
    fn a_malformed_head_is_refused() {
        let mut reader = ResponseReader::default();
        assert_eq!(
            reader.feed(b"garbage\r\n\r\n"),
            Err(ReplayError::Malformed("no status line"))
        );
        let mut reader = ResponseReader::default();
        assert_eq!(
            reader.feed(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n"),
            Err(ReplayError::Malformed("bad chunk size"))
        );
    }

    /// A response to `HEAD` ends at its head, whatever length it declares.
    #[test]
    fn a_response_to_head_has_no_body_whatever_its_length_says() {
        let mut reader = ResponseReader::for_method("HEAD");
        let events = reader
            .feed(b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\n\r\n")
            .unwrap();
        assert_eq!(
            events,
            vec![
                ReplayEvent::Head {
                    status: 200,
                    headers: vec![("content-length".into(), "12".into())],
                },
                ReplayEvent::End,
            ]
        );
        assert_eq!(reader.finish().unwrap(), vec![]);

        // The same head to a GET waits for its twelve bytes.
        let mut reader = ResponseReader::for_method("GET");
        reader
            .feed(b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\n\r\n")
            .unwrap();
        assert_eq!(reader.finish(), Err(ReplayError::CutShort));
    }
}
