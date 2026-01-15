//! Native PTY implementation using portable-pty.

use portable_pty::{native_pty_system, CommandBuilder, PtySize as NativePtySize};
use std::io::{Read, Write};

use super::{PtyHandle, PtySize};
use crate::error::ShellTunnelError;
use crate::Result;

/// Get the default shell for the current platform.
pub fn default_shell() -> &'static str {
    #[cfg(unix)]
    {
        std::env::var("SHELL")
            .ok()
            .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
            .unwrap_or("/bin/sh")
    }
    #[cfg(windows)]
    {
        "powershell.exe"
    }
}

/// Wrapper around the native PTY system.
pub struct NativePty {
    pty_system: Box<dyn portable_pty::PtySystem + Send>,
}

impl NativePty {
    /// Create a new NativePty instance.
    pub fn new() -> Self {
        Self {
            pty_system: native_pty_system(),
        }
    }

    /// Spawn a shell process in a new PTY.
    ///
    /// # Arguments
    ///
    /// * `shell` - The shell command to execute (e.g., "bash", "powershell.exe").
    /// * `size` - The initial size of the PTY.
    ///
    /// # Returns
    ///
    /// A `PtyHandle` containing the reader, writer, and process ID.
    pub fn spawn(
        &self,
        shell: &str,
        size: PtySize,
    ) -> Result<PtyHandle<Box<dyn Read + Send>, Box<dyn Write + Send>>> {
        let native_size = NativePtySize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = self
            .pty_system
            .openpty(native_size)
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))?;

        let cmd = CommandBuilder::new(shell);

        // Note: We don't use -l flag as it can cause issues with some shells
        // The environment is inherited from the parent process

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))?;

        let pid = child.process_id().unwrap_or(0);

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))?;

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))?;

        Ok(PtyHandle::new(
            reader,
            writer,
            pid,
            Box::new((pair.master, child)),
        ))
    }

    /// Spawn a shell process with the default shell.
    pub fn spawn_default(
        &self,
        size: PtySize,
    ) -> Result<PtyHandle<Box<dyn Read + Send>, Box<dyn Write + Send>>> {
        self.spawn(default_shell(), size)
    }

    /// Spawn a shell process with optional working directory.
    ///
    /// This is a convenience method for command execution that spawns
    /// a shell with default size and optionally sets the working directory.
    pub fn spawn_shell(&mut self, working_dir: Option<&std::path::Path>) -> Result<SpawnedShell> {
        let native_size = NativePtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = self
            .pty_system
            .openpty(native_size)
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))?;

        let mut cmd = CommandBuilder::new(default_shell());

        if let Some(dir) = working_dir {
            cmd.cwd(dir);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))?;

        Ok(SpawnedShell {
            master: pair.master,
            child,
            reader: None,
            writer: None,
        })
    }

    /// Spawn a command directly (non-interactive).
    ///
    /// This runs a single command and exits when done.
    /// The command is executed via `sh -c "command"` (Unix) or `cmd /c command` (Windows).
    pub fn spawn_command(
        &mut self,
        command_line: &str,
        working_dir: Option<&std::path::Path>,
    ) -> Result<SpawnedShell> {
        let native_size = NativePtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = self
            .pty_system
            .openpty(native_size)
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))?;

        #[cfg(unix)]
        let mut cmd = {
            let mut c = CommandBuilder::new("/bin/sh");
            c.arg("-c");
            c.arg(command_line);
            c
        };

        #[cfg(windows)]
        let mut cmd = {
            let mut c = CommandBuilder::new("cmd.exe");
            c.arg("/c");
            c.arg(command_line);
            c
        };

        if let Some(dir) = working_dir {
            cmd.cwd(dir);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))?;

        Ok(SpawnedShell {
            master: pair.master,
            child,
            reader: None,
            writer: None,
        })
    }
}

/// A spawned shell process with PTY.
pub struct SpawnedShell {
    master: Box<dyn portable_pty::MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    reader: Option<Box<dyn Read + Send>>,
    writer: Option<Box<dyn Write + Send>>,
}

impl SpawnedShell {
    /// Take the writer (can only be called once).
    pub fn take_writer(&mut self) -> Result<Box<dyn Write + Send>> {
        if let Some(writer) = self.writer.take() {
            return Ok(writer);
        }
        self.master
            .take_writer()
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))
    }

    /// Take the reader (can only be called once).
    pub fn take_reader(&mut self) -> Result<Box<dyn Read + Send>> {
        if let Some(reader) = self.reader.take() {
            return Ok(reader);
        }
        self.master
            .try_clone_reader()
            .map_err(|e| ShellTunnelError::Pty(e.to_string()))
    }

    /// Try to wait for the child process without blocking.
    pub fn try_wait(&mut self) -> std::io::Result<Option<portable_pty::ExitStatus>> {
        self.child.try_wait()
    }

    /// Wait for the child process to exit.
    pub fn wait(&mut self) -> std::io::Result<portable_pty::ExitStatus> {
        self.child.wait()
    }
}

impl Default for NativePty {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_shell() {
        let shell = default_shell();
        assert!(!shell.is_empty());

        #[cfg(unix)]
        {
            // Should be a valid path or command
            assert!(shell.starts_with('/') || !shell.contains('/'));
        }

        #[cfg(windows)]
        {
            assert!(shell.ends_with(".exe"));
        }
    }

    #[test]
    fn test_spawn_shell() {
        let pty = NativePty::new();
        let handle = pty.spawn_default(PtySize::default());

        assert!(handle.is_ok(), "Failed to spawn shell: {:?}", handle.err());

        let handle = handle.unwrap();
        assert!(handle.pid > 0, "PID should be positive");
    }

    // Note: This test is ignored by default because PTY read operations
    // can block indefinitely on some platforms (especially Windows).
    // Run with: cargo test -- --ignored
    #[test]
    #[ignore]
    fn test_write_and_read() {
        use std::time::Duration;

        let pty = NativePty::new();
        let mut handle = pty.spawn_default(PtySize::default()).unwrap();

        // Write a simple echo command followed by exit
        #[cfg(unix)]
        let cmd = "echo SHELL_TUNNEL_TEST_OUTPUT; exit\n";
        #[cfg(windows)]
        let cmd = "echo SHELL_TUNNEL_TEST_OUTPUT\r\nexit\r\n";

        handle.writer.write_all(cmd.as_bytes()).unwrap();
        handle.writer.flush().unwrap();

        // Read with a simple timeout approach
        let mut output = Vec::new();
        let mut buf = [0u8; 1024];
        let deadline = std::time::Instant::now() + Duration::from_secs(5);

        while std::time::Instant::now() < deadline {
            match handle.reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    output.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&output).contains("SHELL_TUNNEL_TEST_OUTPUT") {
                        break;
                    }
                }
                Err(e) => {
                    #[cfg(unix)]
                    if e.raw_os_error() == Some(libc::EIO) {
                        break;
                    }
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    break;
                }
            }
        }

        assert!(!output.is_empty(), "Should have received some output");
    }

    #[test]
    fn test_custom_size() {
        let pty = NativePty::new();
        let size = PtySize::new(40, 120);
        let handle = pty.spawn_default(size);

        assert!(handle.is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn test_spawn_specific_shell() {
        let pty = NativePty::new();
        let handle = pty.spawn("/bin/sh", PtySize::default());

        assert!(handle.is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn test_spawn_cmd() {
        let pty = NativePty::new();
        let handle = pty.spawn("cmd.exe", PtySize::default());

        assert!(handle.is_ok());
    }
}
