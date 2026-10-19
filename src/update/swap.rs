//! Putting a staged binary in place of the running one, putting the previous
//! one back, and restarting into whichever is on disk.
//!
//! Replacing happens on disk while the old image keeps running: both Unix and
//! Windows let a running executable be renamed, and the process that renamed
//! it only meets the new file when it starts again.

use std::io;
use std::path::{Path, PathBuf};

use crate::ShellTunnelError;

/// `<exe>.<suffix>`, next to `exe`.
fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    exe.with_file_name(name)
}

/// Where the replaced binary is kept until the new one has proved itself.
pub fn prev_path(exe: &Path) -> PathBuf {
    sibling(exe, "prev")
}

/// `Ok` when files can be created and removed in the executable's directory —
/// the one thing every step of an update needs. Checked at startup, so an
/// update that could never be applied is refused before it is attempted.
pub fn can_replace(exe: &Path) -> Result<(), String> {
    let dir = exe
        .parent()
        .ok_or_else(|| format!("{} has no directory", exe.display()))?;
    let probe = dir.join(format!(".shell-tunnel-write-probe-{}", std::process::id()));
    std::fs::write(&probe, b"")
        .and_then(|()| std::fs::remove_file(&probe))
        .map_err(|e| format!("{}: {e}", dir.display()))
}

/// Move `exe` to `<exe>.prev` and `staged` to `exe`; returns the `.prev` path.
///
/// If the second move fails the first is undone, so a failure leaves the
/// executable where it was.
pub fn swap_in(exe: &Path, staged: &Path) -> io::Result<PathBuf> {
    let prev = prev_path(exe);
    remove_if_present(&prev)?;
    std::fs::rename(exe, &prev)?;
    if let Err(e) = std::fs::rename(staged, exe) {
        // Best effort: the error being reported is the one that matters.
        let _ = std::fs::rename(&prev, exe);
        return Err(e);
    }
    Ok(prev)
}

/// Put `prev` back as `exe`, keeping what was there as `<exe>.failed` so the
/// binary that failed can still be looked at.
pub fn restore(exe: &Path, prev: &Path) -> io::Result<()> {
    let failed = sibling(exe, "failed");
    remove_if_present(&failed)?;
    if exe.exists() {
        std::fs::rename(exe, &failed)?;
    }
    std::fs::rename(prev, exe)
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Start again as whatever binary is now at this executable's path.
///
/// On Unix this replaces the process image in place (same pid, same
/// arguments), so it returns only if that failed. Windows has no such call:
/// the process ends with [`ShellTunnelError::Updated`], which `main` turns
/// into an exit its supervisor answers by starting it again.
pub fn restart() -> ShellTunnelError {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => return ShellTunnelError::Update(format!("cannot restart: {e}")),
        };
        let err = std::process::Command::new(&exe)
            .args(std::env::args_os().skip(1))
            .exec();
        ShellTunnelError::Update(format!("cannot restart as {}: {err}", exe.display()))
    }
    #[cfg(not(unix))]
    {
        ShellTunnelError::Updated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in files {
            std::fs::write(dir.path().join(name), body).unwrap();
        }
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn swap_then_restore_leaves_the_original_in_place() {
        let dir = dir_with(&[("st", b"old"), ("st.staged", b"new")]);
        let exe = dir.path().join("st");

        let prev = swap_in(&exe, &dir.path().join("st.staged")).unwrap();
        assert_eq!(prev, dir.path().join("st.prev"));
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(std::fs::read(&prev).unwrap(), b"old");
        assert_eq!(names(dir.path()), ["st", "st.prev"]);

        restore(&exe, &prev).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
        assert_eq!(std::fs::read(dir.path().join("st.failed")).unwrap(), b"new");
        assert_eq!(names(dir.path()), ["st", "st.failed"]);
    }

    #[test]
    fn a_failed_swap_leaves_nothing_moved() {
        // The staged file does not exist, so the second move fails.
        let dir = dir_with(&[("st", b"old")]);
        let exe = dir.path().join("st");

        assert!(swap_in(&exe, &dir.path().join("st.staged")).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
        assert_eq!(names(dir.path()), ["st"]);
    }

    #[test]
    fn a_leftover_prev_from_an_earlier_update_is_replaced() {
        let dir = dir_with(&[("st", b"v2"), ("st.prev", b"v1"), ("st.staged", b"v3")]);
        let exe = dir.path().join("st");

        let prev = swap_in(&exe, &dir.path().join("st.staged")).unwrap();
        assert_eq!(std::fs::read(&prev).unwrap(), b"v2");
        assert_eq!(std::fs::read(&exe).unwrap(), b"v3");
    }

    /// Not a check: the long-running process `a_running_executable_can_be_swapped_out`
    /// starts from a copy of this test binary. Returns at once unless asked.
    #[test]
    fn helper_stays_running_when_asked() {
        if std::env::var_os("SHELL_TUNNEL_SWAP_HELPER").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    #[test]
    fn a_running_executable_can_be_swapped_out() {
        // The premise of updating in place: an executable can be renamed while
        // a process is running from it. Checked on a running copy of this binary.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir
            .path()
            .join(if cfg!(windows) { "held.exe" } else { "held" });
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        std::fs::write(dir.path().join("staged"), b"new").unwrap();
        let mut child = std::process::Command::new(&exe)
            .args([
                "--exact",
                "update::swap::tests::helper_stays_running_when_asked",
            ])
            .env("SHELL_TUNNEL_SWAP_HELPER", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let running = child.try_wait().unwrap().is_none();
        let swapped = swap_in(&exe, &dir.path().join("staged"));
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            running,
            "the helper exited before the swap; nothing was proven"
        );
        let prev = swapped.unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert!(prev.exists());
    }

    #[test]
    fn can_replace_reports_a_directory_it_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(can_replace(&dir.path().join("st")), Ok(()));
        assert_eq!(names(dir.path()), Vec::<String>::new());

        let missing = dir.path().join("gone").join("st");
        let err = can_replace(&missing).unwrap_err();
        assert!(err.contains("gone"), "{err}");
    }
}
