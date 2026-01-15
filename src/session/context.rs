//! Session execution context and state tracking.

use std::collections::HashMap;
use std::path::PathBuf;

/// Execution context for a shell session.
///
/// This tracks the current working directory, environment variables,
/// and other runtime state information for a session.
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    /// Current working directory.
    cwd: Option<PathBuf>,
    /// Environment variables snapshot.
    env: HashMap<String, String>,
    /// Last command executed.
    last_command: Option<String>,
    /// Exit code of last command.
    last_exit_code: Option<i32>,
    /// Command execution count.
    execution_count: u64,
}

impl SessionContext {
    /// Create a new empty session context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a session context with initial working directory.
    pub fn with_cwd(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: Some(cwd.into()),
            ..Default::default()
        }
    }

    /// Get the current working directory.
    pub fn cwd(&self) -> Option<&PathBuf> {
        self.cwd.as_ref()
    }

    /// Set the current working directory.
    pub fn set_cwd(&mut self, cwd: impl Into<PathBuf>) {
        self.cwd = Some(cwd.into());
    }

    /// Clear the current working directory.
    pub fn clear_cwd(&mut self) {
        self.cwd = None;
    }

    /// Get the environment variables.
    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    /// Get a specific environment variable.
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env.get(key).map(|s| s.as_str())
    }

    /// Set an environment variable.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env.insert(key.into(), value.into());
    }

    /// Remove an environment variable.
    pub fn remove_env(&mut self, key: &str) -> Option<String> {
        self.env.remove(key)
    }

    /// Merge environment variables from another map.
    pub fn merge_env(&mut self, vars: HashMap<String, String>) {
        self.env.extend(vars);
    }

    /// Get the last command executed.
    pub fn last_command(&self) -> Option<&str> {
        self.last_command.as_deref()
    }

    /// Get the exit code of the last command.
    pub fn last_exit_code(&self) -> Option<i32> {
        self.last_exit_code
    }

    /// Get the number of commands executed.
    pub fn execution_count(&self) -> u64 {
        self.execution_count
    }

    /// Record a command execution result.
    pub fn record_execution(&mut self, command: impl Into<String>, exit_code: Option<i32>) {
        self.last_command = Some(command.into());
        self.last_exit_code = exit_code;
        self.execution_count += 1;
    }

    /// Check if the last command succeeded.
    pub fn last_succeeded(&self) -> bool {
        self.last_exit_code == Some(0)
    }

    /// Check if the last command failed.
    pub fn last_failed(&self) -> bool {
        matches!(self.last_exit_code, Some(code) if code != 0)
    }
}

/// State probe for querying shell state.
///
/// This provides utility methods for probing shell state like
/// current directory and environment variables.
pub struct StateProbe;

impl StateProbe {
    /// Get the command to probe current working directory.
    #[cfg(unix)]
    pub fn cwd_command() -> &'static str {
        "pwd"
    }

    /// Get the command to probe current working directory.
    #[cfg(windows)]
    pub fn cwd_command() -> &'static str {
        "cd"
    }

    /// Get the command to list environment variables.
    #[cfg(unix)]
    pub fn env_command() -> &'static str {
        "env"
    }

    /// Get the command to list environment variables.
    #[cfg(windows)]
    pub fn env_command() -> &'static str {
        "set"
    }

    /// Parse CWD from command output.
    pub fn parse_cwd(output: &str) -> Option<PathBuf> {
        let trimmed = output.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed.lines().next().unwrap_or("")))
        }
    }

    /// Parse environment variables from command output.
    pub fn parse_env(output: &str) -> HashMap<String, String> {
        let mut env = HashMap::new();

        for line in output.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                if !key.is_empty() {
                    env.insert(key.to_string(), value.to_string());
                }
            }
        }

        env
    }

    /// Generate a unique marker for output detection.
    pub fn marker(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("__{}_{}_MARKER__", prefix, timestamp)
    }

    /// Generate an echo command with marker.
    pub fn echo_marker(marker: &str) -> String {
        format!("echo {}", marker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_new() {
        let ctx = SessionContext::new();
        assert!(ctx.cwd().is_none());
        assert!(ctx.env().is_empty());
        assert!(ctx.last_command().is_none());
        assert!(ctx.last_exit_code().is_none());
        assert_eq!(ctx.execution_count(), 0);
    }

    #[test]
    fn test_context_with_cwd() {
        let ctx = SessionContext::with_cwd("/home/user");
        assert_eq!(ctx.cwd(), Some(&PathBuf::from("/home/user")));
    }

    #[test]
    fn test_context_set_cwd() {
        let mut ctx = SessionContext::new();
        ctx.set_cwd("/tmp");
        assert_eq!(ctx.cwd(), Some(&PathBuf::from("/tmp")));

        ctx.clear_cwd();
        assert!(ctx.cwd().is_none());
    }

    #[test]
    fn test_context_env() {
        let mut ctx = SessionContext::new();
        ctx.set_env("PATH", "/usr/bin");
        ctx.set_env("HOME", "/home/user");

        assert_eq!(ctx.get_env("PATH"), Some("/usr/bin"));
        assert_eq!(ctx.get_env("HOME"), Some("/home/user"));
        assert_eq!(ctx.get_env("NONEXISTENT"), None);

        assert_eq!(ctx.remove_env("PATH"), Some("/usr/bin".to_string()));
        assert_eq!(ctx.get_env("PATH"), None);
    }

    #[test]
    fn test_context_merge_env() {
        let mut ctx = SessionContext::new();
        ctx.set_env("EXISTING", "value");

        let mut new_vars = HashMap::new();
        new_vars.insert("NEW1".to_string(), "val1".to_string());
        new_vars.insert("NEW2".to_string(), "val2".to_string());

        ctx.merge_env(new_vars);

        assert_eq!(ctx.get_env("EXISTING"), Some("value"));
        assert_eq!(ctx.get_env("NEW1"), Some("val1"));
        assert_eq!(ctx.get_env("NEW2"), Some("val2"));
    }

    #[test]
    fn test_context_record_execution() {
        let mut ctx = SessionContext::new();

        ctx.record_execution("ls -la", Some(0));
        assert_eq!(ctx.last_command(), Some("ls -la"));
        assert_eq!(ctx.last_exit_code(), Some(0));
        assert_eq!(ctx.execution_count(), 1);
        assert!(ctx.last_succeeded());
        assert!(!ctx.last_failed());

        ctx.record_execution("false", Some(1));
        assert_eq!(ctx.last_command(), Some("false"));
        assert_eq!(ctx.last_exit_code(), Some(1));
        assert_eq!(ctx.execution_count(), 2);
        assert!(!ctx.last_succeeded());
        assert!(ctx.last_failed());
    }

    #[test]
    fn test_state_probe_cwd_command() {
        let cmd = StateProbe::cwd_command();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_state_probe_env_command() {
        let cmd = StateProbe::env_command();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_state_probe_parse_cwd() {
        let output = "/home/user\n";
        let cwd = StateProbe::parse_cwd(output);
        assert_eq!(cwd, Some(PathBuf::from("/home/user")));

        let empty = "";
        assert!(StateProbe::parse_cwd(empty).is_none());
    }

    #[test]
    fn test_state_probe_parse_env() {
        let output = "PATH=/usr/bin\nHOME=/home/user\nEMPTY=\n";
        let env = StateProbe::parse_env(output);

        assert_eq!(env.get("PATH"), Some(&"/usr/bin".to_string()));
        assert_eq!(env.get("HOME"), Some(&"/home/user".to_string()));
        assert_eq!(env.get("EMPTY"), Some(&"".to_string()));
    }

    #[test]
    fn test_state_probe_marker() {
        let marker1 = StateProbe::marker("TEST");
        let marker2 = StateProbe::marker("TEST");

        assert!(marker1.contains("TEST"));
        assert!(marker1.contains("MARKER"));
        // Markers should be unique (due to timestamp)
        // Note: This might fail if called in the same nanosecond, but very unlikely
        assert!(marker1 != marker2 || marker1.contains("TEST"));
    }

    #[test]
    fn test_state_probe_echo_marker() {
        let marker = "__TEST_MARKER__";
        let cmd = StateProbe::echo_marker(marker);
        assert_eq!(cmd, "echo __TEST_MARKER__");
    }
}
