//! Command building and representation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// A command to be executed in a shell session.
#[derive(Debug, Clone)]
pub struct Command {
    /// The command line to execute.
    pub command_line: String,
    /// Working directory override (if any).
    pub working_dir: Option<PathBuf>,
    /// Environment variables to set.
    pub env: HashMap<String, String>,
    /// Maximum execution time.
    pub timeout: Option<Duration>,
    /// Whether to capture output.
    pub capture_output: bool,
}

impl Command {
    /// Create a new command with the given command line.
    pub fn new(command_line: impl Into<String>) -> Self {
        Self {
            command_line: command_line.into(),
            working_dir: None,
            env: HashMap::new(),
            timeout: None,
            capture_output: true,
        }
    }

    /// Set the working directory.
    pub fn working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add multiple environment variables.
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.env.insert(k.into(), v.into());
        }
        self
    }

    /// Set the execution timeout.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Set whether to capture output.
    pub fn capture_output(mut self, capture: bool) -> Self {
        self.capture_output = capture;
        self
    }
}

impl Default for Command {
    fn default() -> Self {
        Self::new("")
    }
}

/// Builder for creating commands with fluent API.
#[derive(Debug, Default)]
pub struct CommandBuilder {
    command_line: Option<String>,
    working_dir: Option<PathBuf>,
    env: HashMap<String, String>,
    timeout: Option<Duration>,
    capture_output: bool,
}

impl CommandBuilder {
    /// Create a new command builder.
    pub fn new() -> Self {
        Self {
            capture_output: true,
            ..Default::default()
        }
    }

    /// Set the command line.
    pub fn command_line(mut self, cmd: impl Into<String>) -> Self {
        self.command_line = Some(cmd.into());
        self
    }

    /// Set the working directory.
    pub fn working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set the execution timeout.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Set whether to capture output.
    pub fn capture_output(mut self, capture: bool) -> Self {
        self.capture_output = capture;
        self
    }

    /// Build the command.
    ///
    /// Returns `None` if no command line was specified.
    pub fn build(self) -> Option<Command> {
        self.command_line.map(|cmd| Command {
            command_line: cmd,
            working_dir: self.working_dir,
            env: self.env,
            timeout: self.timeout,
            capture_output: self.capture_output,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_new() {
        let cmd = Command::new("ls -la");
        assert_eq!(cmd.command_line, "ls -la");
        assert!(cmd.working_dir.is_none());
        assert!(cmd.env.is_empty());
        assert!(cmd.timeout.is_none());
        assert!(cmd.capture_output);
    }

    #[test]
    fn test_command_builder_chain() {
        let cmd = Command::new("cargo build")
            .working_dir("/project")
            .env("RUST_LOG", "debug")
            .timeout(Duration::from_secs(60))
            .capture_output(true);

        assert_eq!(cmd.command_line, "cargo build");
        assert_eq!(cmd.working_dir, Some(PathBuf::from("/project")));
        assert_eq!(cmd.env.get("RUST_LOG"), Some(&"debug".to_string()));
        assert_eq!(cmd.timeout, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_command_envs() {
        let vars = [("KEY1", "val1"), ("KEY2", "val2")];
        let cmd = Command::new("echo").envs(vars);

        assert_eq!(cmd.env.len(), 2);
        assert_eq!(cmd.env.get("KEY1"), Some(&"val1".to_string()));
        assert_eq!(cmd.env.get("KEY2"), Some(&"val2".to_string()));
    }

    #[test]
    fn test_command_builder_build() {
        let cmd = CommandBuilder::new()
            .command_line("pwd")
            .working_dir("/tmp")
            .build();

        assert!(cmd.is_some());
        let cmd = cmd.unwrap();
        assert_eq!(cmd.command_line, "pwd");
        assert_eq!(cmd.working_dir, Some(PathBuf::from("/tmp")));
    }

    #[test]
    fn test_command_builder_empty() {
        let cmd = CommandBuilder::new().build();
        assert!(cmd.is_none());
    }
}
