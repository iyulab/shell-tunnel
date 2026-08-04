//! Session execution bookkeeping.

/// What has run in a session so far.
///
/// Bookkeeping only — it does not configure anything. A session holds no shell
/// between calls (every execute spawns its own `cmd /c` / `sh -c`), so there is
/// no working directory or environment for it to carry: both are decided per
/// execute. This type once held a `cwd` and an `env` that nothing read, and a
/// `StateProbe` helper for recovering them from a persistent shell that does
/// not exist here.
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_new() {
        let ctx = SessionContext::new();
        assert!(ctx.last_command().is_none());
        assert!(ctx.last_exit_code().is_none());
        assert_eq!(ctx.execution_count(), 0);
    }

    #[test]
    fn test_record_execution() {
        let mut ctx = SessionContext::new();
        ctx.record_execution("ls -la", Some(0));

        assert_eq!(ctx.last_command(), Some("ls -la"));
        assert_eq!(ctx.last_exit_code(), Some(0));
        assert_eq!(ctx.execution_count(), 1);
        assert!(ctx.last_succeeded());
        assert!(!ctx.last_failed());
    }

    #[test]
    fn test_execution_count_increments() {
        let mut ctx = SessionContext::new();
        ctx.record_execution("first", Some(0));
        ctx.record_execution("second", Some(1));

        assert_eq!(ctx.execution_count(), 2);
        assert_eq!(ctx.last_command(), Some("second"));
        assert!(ctx.last_failed());
        assert!(!ctx.last_succeeded());
    }

    #[test]
    fn a_command_that_never_reported_an_exit_code_neither_succeeded_nor_failed() {
        let mut ctx = SessionContext::new();
        ctx.record_execution("killed", None);

        assert!(!ctx.last_succeeded());
        assert!(!ctx.last_failed());
    }
}
