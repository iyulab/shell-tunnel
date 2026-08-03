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
///
/// On Windows the command line is passed with [`CommandExt::raw_arg`] rather
/// than `arg`. `arg` applies the argument-encoding rules of the C runtime —
/// among them, escaping `"` as `\"` — and `cmd.exe` does not parse its command
/// line that way. The result was that a quote written by the caller arrived at
/// the shell as a literal backslash-quote, so every command needing quoting
/// failed: `dir /b "D:\some\path"` was a syntax error, `powershell -c "a | b"`
/// ran only `a`, and a path containing a space had no working form at all.
/// Measured both ways before choosing; `raw_arg` fixes each of those and leaves
/// unquoted commands byte-identical.
///
/// This grants the caller nothing new. `/execute` hands its string to a shell
/// by definition, so a token holding `exec` could already run anything the
/// account can; what changed is that quoting now means what it says.
///
/// Unix needs no equivalent: `arg` there places the string into `argv` with no
/// encoding step, which is already what `sh -c` expects.
pub(crate) fn shell_command(command_line: &str) -> OsCommand {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut c = OsCommand::new("cmd.exe");
        // Two `raw_arg` calls, and the trailing space in the first, are load
        // bearing: raw arguments are concatenated verbatim, so `/c` and the
        // command must be separated here or they arrive as one token.
        c.raw_arg("/c ").raw_arg(command_line);
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

    /// A quote written by the caller must reach the shell as a quote.
    ///
    /// `arg` encodes for the C runtime's parser and turns `"` into `\"`, which
    /// `cmd.exe` does not undo — so the shell saw a literal backslash. This
    /// covers the round trip; `a_quoted_path_is_one_argument` below covers the
    /// case with no workaround.
    #[test]
    fn a_quoted_command_reaches_the_shell_intact() {
        let output = shell_command(r#"echo ["quoted"]"#)
            .stdin(Stdio::null())
            .output()
            .expect("shell should be available");
        let text = String::from_utf8_lossy(&output.stdout);

        // The two shells disagree about what `echo` does with a quote, and the
        // disagreement is what makes each output proof. `cmd.exe` echoes its
        // line verbatim, quotes included. `sh` consumes them as syntax, so the
        // quotes are gone from its output precisely *because* they arrived as
        // quotes — a mangled `\"` would make `sh` print the quote literally,
        // which is the Windows-correct string. Asserting one expectation on
        // both platforms therefore fails on whichever one it was not written
        // for; this test asserted the Windows string and had only ever run on
        // Windows.
        #[cfg(windows)]
        let expected = r#"["quoted"]"#;
        #[cfg(unix)]
        let expected = "[quoted]";

        assert!(
            text.contains(expected),
            "the quote must reach the shell as a quote; wanted {expected:?}, got {text:?}"
        );
        assert!(
            !text.contains(r#"\""#),
            "a backslash the caller never wrote must not appear: {text:?}"
        );
    }

    /// A path in quotes is what quoting exists for, and it is the case with no
    /// workaround: an unquoted path containing a space cannot be expressed at
    /// all. `Cargo.toml` at the crate root is the fixture because it is present
    /// wherever the tests run.
    #[test]
    fn a_quoted_path_is_one_argument() {
        let root = env!("CARGO_MANIFEST_DIR");
        #[cfg(windows)]
        let line = format!(r#"dir /b "{root}\Cargo.toml""#);
        #[cfg(unix)]
        let line = format!(r#"ls "{root}/Cargo.toml""#);

        let output = shell_command(&line)
            .stdin(Stdio::null())
            .output()
            .expect("shell should be available");
        assert!(
            output.status.success(),
            "a quoted path must be understood: {:?} / {:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
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
