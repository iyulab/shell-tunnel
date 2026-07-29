//! SHA-256 over files and over streams.
//!
//! Two shapes because the two callers differ: `list` hashes a file that already
//! exists, while an upload hashes bytes as they arrive and can never hold the
//! whole file in memory.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Read size for file hashing. Large enough that syscall overhead disappears,
/// small enough to stay off the stack pressure of a big buffer.
const READ_CHUNK: usize = 64 * 1024;

/// Hash a whole file, returning lowercase hex.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; READ_CHUNK];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

/// Incremental hasher for bytes that arrive over time.
#[derive(Debug, Default)]
pub struct Hasher {
    inner: Sha256,
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    /// Consume the hasher and render the digest as lowercase hex.
    pub fn finish(self) -> String {
        hex(&self.inner.finalize())
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nist_vector_for_abc() {
        let mut hasher = Hasher::new();
        hasher.update(b"abc");
        assert_eq!(
            hasher.finish(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_empty_input_vector() {
        assert_eq!(
            Hasher::new().finish(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn incremental_updates_match_a_single_update() {
        let mut split = Hasher::new();
        split.update(b"ab");
        split.update(b"c");

        let mut whole = Hasher::new();
        whole.update(b"abc");

        assert_eq!(split.finish(), whole.finish());
    }

    #[test]
    fn hashing_a_file_matches_hashing_its_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"abc").expect("write");
        assert_eq!(
            hash_file(&path).expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
