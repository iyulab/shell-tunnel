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

/// Remove one filesystem entry, choosing the syscall a symlink actually needs.
///
/// `meta` must come from `symlink_metadata` (lstat), never `metadata` (stat)
/// — the caller needs to know about the entry itself, not whatever it points
/// to, or every symlink looks identical to its target and this can never
/// tell a directory symlink from a real directory.
#[cfg(unix)]
pub fn remove_entry(path: &std::path::Path, _meta: &std::fs::Metadata) -> std::io::Result<()> {
    // `unlink` removes the link itself no matter what it points to — file,
    // directory, or nothing — so there is no branch to make here.
    std::fs::remove_file(path)
}

/// Windows counterpart of the Unix `remove_entry` above.
///
/// `DeleteFileW` (which `std::fs::remove_file` wraps) refuses a directory
/// reparse point outright, even though unlinking one is exactly as safe as
/// unlinking a file symlink — nothing under it is touched either way.
/// `RemoveDirectoryW` (`std::fs::remove_dir`) is what actually unlinks a
/// directory reparse point without recursing into it; it only recurses into
/// a *real* directory's contents, which is why the `not-a-file` refusal in
/// `api::fs::delete_file` runs before this is ever reached.
#[cfg(windows)]
pub fn remove_entry(path: &std::path::Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
    if meta.is_symlink() {
        // Follows the link on purpose — the one place in this function that
        // means to — to learn whether the target is a directory.
        if let Ok(target) = std::fs::metadata(path) {
            if target.is_dir() {
                return std::fs::remove_dir(path);
            }
        }
    }
    std::fs::remove_file(path)
}

#[cfg(not(any(unix, windows)))]
pub fn remove_entry(path: &std::path::Path, _meta: &std::fs::Metadata) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

/// Whether `err` reports that the filesystem has run out of space.
///
/// Checked against the numeric OS error code, never the rendered message: an
/// earlier version of the upload API answered this by matching substrings
/// like `"space"` or `"full"` in `io::Error`'s `Display` output, which
/// renders in the system locale (wrong on a non-English system) and would
/// also fire on an ordinary error that happens to name a directory "full".
/// A caller distinguishing "the disk is full, retry after freeing space"
/// from "the server has a bug, file a report" needs this to be reliable —
/// the two respond completely differently.
///
/// `ENOSPC` (`libc::ENOSPC`) is the same constant `src/pty/native.rs` and
/// `src/pty/async_adapter.rs` already compare against for `EIO`, so this
/// follows an established pattern rather than introducing a new way of
/// reading `raw_os_error()`. `EDQUOT` (`libc::EDQUOT`) is its quota-analogue
/// sibling — a per-user or per-directory quota can be exhausted well before
/// the volume itself is full, and from a client's perspective both answers
/// are the same instruction ("free something up and retry"). Both are
/// `libc`'s *named* constants rather than a literal number precisely
/// because their numeric value is not portable across Unix-likes (`EDQUOT`
/// is 122 on Linux, 69 on macOS and the BSDs) — `libc` already carries the
/// platform-correct value for each target, so naming it is also more
/// correct than hardcoding one.
///
/// Windows has two counterparts, not one: `ERROR_DISK_FULL` (112) and
/// `ERROR_HANDLE_DISK_FULL` (39/`0x27`) — the latter is what a handle-based
/// write (exactly the path `UploadStore::append`'s `Write` impl takes)
/// reports for a full volume, per `winerror.h`. Both are documented literals
/// rather than named constants: there is no crate in this tree's dependency
/// graph that names them (no `windows-sys`, and this task adds no new
/// dependencies).
#[cfg(unix)]
pub fn is_out_of_space(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if code == libc::ENOSPC || code == libc::EDQUOT)
}

#[cfg(windows)]
pub fn is_out_of_space(err: &std::io::Error) -> bool {
    /// `ERROR_DISK_FULL`, from `winerror.h`.
    const ERROR_DISK_FULL: i32 = 112;
    /// `ERROR_HANDLE_DISK_FULL` (`0x27`), from `winerror.h` — reported for a
    /// full volume on a handle-based write, which is the path uploads take.
    const ERROR_HANDLE_DISK_FULL: i32 = 39;
    // `io::Error::raw_os_error()` reports the raw Win32 error code, not an
    // `errno` — neither of these is to be confused with any POSIX `ENOSPC`
    // or `EDQUOT` numbering.
    matches!(
        err.raw_os_error(),
        Some(code) if code == ERROR_DISK_FULL || code == ERROR_HANDLE_DISK_FULL
    )
}

#[cfg(not(any(unix, windows)))]
pub fn is_out_of_space(_err: &std::io::Error) -> bool {
    false
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

    /// Cannot deterministically fill a disk to force a real `ENOSPC` in a
    /// test, so this is the honest substitute: pin `is_out_of_space` against
    /// the raw OS codes directly, the same numeric values `raw_os_error()`
    /// would actually report.
    #[cfg(unix)]
    #[test]
    fn is_out_of_space_matches_enospc_and_edquot_only() {
        let enospc = std::io::Error::from_raw_os_error(libc::ENOSPC);
        assert!(is_out_of_space(&enospc));

        // The quota-analogue sibling must match too, not just ENOSPC itself.
        let edquot = std::io::Error::from_raw_os_error(libc::EDQUOT);
        assert!(is_out_of_space(&edquot));

        // A different errno — e.g. ENOENT — must not be mistaken for either.
        let enoent = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert!(!is_out_of_space(&enoent));

        // Not an OS error at all.
        let other = std::io::Error::other("not an os error");
        assert!(!is_out_of_space(&other));
    }

    #[cfg(windows)]
    #[test]
    fn is_out_of_space_matches_disk_full_codes_only() {
        const ERROR_DISK_FULL: i32 = 112;
        const ERROR_HANDLE_DISK_FULL: i32 = 39;

        let disk_full = std::io::Error::from_raw_os_error(ERROR_DISK_FULL);
        assert!(is_out_of_space(&disk_full));

        // The handle-based-write sibling must match too — this is the code
        // an actual full-volume `Write` (the path uploads take) reports.
        let handle_disk_full = std::io::Error::from_raw_os_error(ERROR_HANDLE_DISK_FULL);
        assert!(is_out_of_space(&handle_disk_full));

        // A different Win32 code — e.g. ERROR_FILE_NOT_FOUND (2) — must not
        // be mistaken for either.
        let not_found = std::io::Error::from_raw_os_error(2);
        assert!(!is_out_of_space(&not_found));

        let other = std::io::Error::other("not an os error");
        assert!(!is_out_of_space(&other));
    }
}
