//! Cross-platform filesystem differences, absorbed in one place.
//!
//! Path separators, reserved names, and stream syntax differ enough between
//! Windows and Unix that scattering the checks would guarantee one of them is
//! forgotten. ROADMAP:29 asks for this to exist from the start rather than be
//! retrofitted.

/// Windows device names, which resolve to devices rather than files no matter
/// which directory they appear in. Compared without extension: `CON.txt` is
/// still the console.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Whether one path component is acceptable as-is.
///
/// Applied on every platform, not just Windows. A tree written on Linux and
/// read on Windows would otherwise contain names the other side cannot open,
/// and a jail that behaves differently per host is not a jail anyone can reason
/// about.
///
/// `..` is *not* rejected here — escape is decided by canonicalisation
/// (`FsRoot::resolve_existing`), and a substring rule would also reject the
/// perfectly ordinary `my..file.txt`.
pub fn check_component(component: &str) -> Result<(), &'static str> {
    if component.is_empty() {
        return Err("empty path component");
    }
    if component.contains('\0') {
        return Err("path contains a null byte");
    }
    // Alternate Data Streams: `file.txt:secret` addresses hidden content on
    // NTFS. Nothing legitimate in a transfer API needs it.
    if component.contains(':') {
        return Err("path contains a stream separator");
    }
    if component.ends_with('.') || component.ends_with(' ') {
        return Err("path component ends with a dot or space");
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        return Err("path component is a reserved device name");
    }
    Ok(())
}

/// A number that changes when the path starts referring to a different file.
///
/// Unix has an inode; Windows has no equivalent reachable from
/// `std::fs::metadata` (`file_index()` is only populated through a `File`
/// handle), so it contributes nothing there and the ETag rests on size and
/// mtime alone. Recorded rather than worked around: a validator that claims
/// more than the platform gives is worse than one that is honest.
#[cfg(unix)]
pub fn file_identity(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
pub fn file_identity(_meta: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_pass() {
        assert!(check_component("config.json").is_ok());
        assert!(check_component("my-app_v2").is_ok());
    }

    #[test]
    fn a_name_containing_two_dots_is_not_traversal() {
        // The bug the old substring rule had: `..` inside a name is ordinary.
        assert!(check_component("my..file.txt").is_ok());
        assert!(check_component("..config").is_ok());
    }

    #[test]
    fn reserved_device_names_are_refused() {
        assert!(check_component("CON").is_err());
        assert!(check_component("con").is_err());
        assert!(check_component("NUL.txt").is_err());
        assert!(check_component("COM1.log").is_err());
        // Not reserved: the stem differs.
        assert!(check_component("CONSOLE").is_ok());
    }

    #[test]
    fn stream_separators_are_refused() {
        assert!(check_component("file.txt:secret").is_err());
    }

    #[test]
    fn trailing_dot_or_space_is_refused() {
        assert!(check_component("name.").is_err());
        assert!(check_component("name ").is_err());
    }

    #[test]
    fn null_bytes_are_refused() {
        assert!(check_component("na\0me").is_err());
    }

    #[test]
    fn empty_components_are_refused() {
        assert!(check_component("").is_err());
    }
}
