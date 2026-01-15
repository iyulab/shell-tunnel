//! Session identifier type.

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for session ID generation.
static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Unique identifier for a shell session.
///
/// Session IDs are generated using an atomic counter, ensuring uniqueness
/// within a single process lifetime. The ID is displayed as `sess-XXXXXXXX`
/// where X is a hexadecimal digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Create a new unique session ID.
    pub fn new() -> Self {
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Get the raw u64 value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Create a SessionId from a raw u64 value.
    ///
    /// This is primarily for testing and deserialization.
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sess-{:08x}", self.0)
    }
}

impl FromStr for SessionId {
    type Err = crate::error::ShellTunnelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix("sess-")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .map(SessionId)
            .ok_or_else(|| crate::error::ShellTunnelError::SessionNotFound(s.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_uniqueness() {
        let mut ids = HashSet::new();
        for _ in 0..10_000 {
            let id = SessionId::new();
            assert!(ids.insert(id), "Duplicate ID generated: {}", id);
        }
        assert_eq!(ids.len(), 10_000);
    }

    #[test]
    fn test_display_format() {
        let id = SessionId::from_raw(255);
        assert_eq!(id.to_string(), "sess-000000ff");

        let id2 = SessionId::from_raw(0x12345678);
        assert_eq!(id2.to_string(), "sess-12345678");
    }

    #[test]
    fn test_parse_valid() {
        let id: SessionId = "sess-000000ff".parse().unwrap();
        assert_eq!(id.as_u64(), 255);

        let id2: SessionId = "sess-12345678".parse().unwrap();
        assert_eq!(id2.as_u64(), 0x12345678);
    }

    #[test]
    fn test_parse_invalid() {
        // Missing prefix
        assert!("000000ff".parse::<SessionId>().is_err());

        // Wrong prefix
        assert!("session-000000ff".parse::<SessionId>().is_err());

        // Invalid hex
        assert!("sess-gggggggg".parse::<SessionId>().is_err());

        // Empty
        assert!("".parse::<SessionId>().is_err());
    }

    #[test]
    fn test_roundtrip() {
        let original = SessionId::new();
        let s = original.to_string();
        let parsed: SessionId = s.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_hash_eq() {
        let id1 = SessionId::from_raw(42);
        let id2 = SessionId::from_raw(42);
        let id3 = SessionId::from_raw(43);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);

        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
        assert!(!set.contains(&id3));
    }
}
