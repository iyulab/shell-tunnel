//! Shared child-process primitives.
//!
//! Both command execution and tunnel supervision spawn children that may create
//! grandchildren, so the platform-specific tree-termination and shell-invocation
//! logic lives here rather than being duplicated per caller.

use std::process::Command as OsCommand;

/// Kill a child process and its entire descendant tree.
///
/// A shell child (`cmd /c` / `sh -c`) or a tunnel client may have spawned
/// grandchildren that keep pipes open and outlive a plain `kill`. On Windows
/// this uses `taskkill /T`; on Unix it signals the process group, which is why
/// callers spawn children with [`detach_process_group`].
pub(crate) fn kill_tree(pid: u32) {
    #[cfg(windows)]
    {
        use std::process::Stdio;

        let _ = OsCommand::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        // SAFETY: kill with a negative pid targets the process group; harmless
        // if the group is already gone (returns ESRCH).
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

/// Put the child in its own process group so [`kill_tree`] can signal the whole
/// tree with a single `kill(-pgid)`. No-op on Windows, where `taskkill /T`
/// walks the tree instead.
pub(crate) fn detach_process_group(cmd: &mut OsCommand) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid only detaches the child into a new session/group; it
        // touches no shared state in the forked child before exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        let _ = cmd;
    }
}

/// Build the platform shell command that runs `command_line` non-interactively.
pub(crate) fn shell_command(command_line: &str) -> OsCommand {
    #[cfg(windows)]
    {
        let mut c = OsCommand::new("cmd.exe");
        c.arg("/c").arg(command_line);
        c
    }
    #[cfg(unix)]
    {
        let mut c = OsCommand::new("/bin/sh");
        c.arg("-c").arg(command_line);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn shell_command_runs_a_trivial_command() {
        let output = shell_command("echo shell-tunnel")
            .stdin(Stdio::null())
            .output()
            .expect("shell should be available");
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("shell-tunnel"));
    }

    #[test]
    fn kill_tree_on_a_dead_pid_is_harmless() {
        // A finished child's pid may be recycled, but signalling a group that no
        // longer exists must not panic or block.
        let mut child = shell_command("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let pid = child.id();
        let _ = child.wait();
        kill_tree(pid);
    }
}
