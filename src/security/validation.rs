//! Input validation and command sanitization.

use std::time::Duration;

/// Validation configuration.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum command length in characters.
    pub max_command_length: usize,
    /// Maximum output size in bytes.
    pub max_output_size: usize,
    /// Maximum timeout in seconds.
    pub max_timeout_secs: u64,
    /// Minimum timeout in seconds.
    pub min_timeout_secs: u64,
    /// Whether to block dangerous commands.
    pub block_dangerous: bool,
    /// Custom blocked patterns (regex-like simple patterns).
    pub blocked_patterns: Vec<String>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_command_length: 4096,
            max_output_size: 10 * 1024 * 1024, // 10MB
            max_timeout_secs: 300,              // 5 minutes
            min_timeout_secs: 1,
            block_dangerous: true,
            blocked_patterns: Vec::new(),
        }
    }
}

impl ValidationConfig {
    /// Create a permissive config (for trusted environments).
    pub fn permissive() -> Self {
        Self {
            max_command_length: 65536,
            max_output_size: 100 * 1024 * 1024, // 100MB
            max_timeout_secs: 3600,              // 1 hour
            min_timeout_secs: 1,
            block_dangerous: false,
            blocked_patterns: Vec::new(),
        }
    }

    /// Create a strict config (for untrusted environments).
    pub fn strict() -> Self {
        Self {
            max_command_length: 1024,
            max_output_size: 1024 * 1024, // 1MB
            max_timeout_secs: 60,
            min_timeout_secs: 1,
            block_dangerous: true,
            blocked_patterns: vec![
                "rm -rf".to_string(),
                "mkfs".to_string(),
                "dd if=".to_string(),
                ":(){".to_string(), // Fork bomb
                ">(w)".to_string(),
            ],
        }
    }
}

/// Command validator.
#[derive(Debug)]
pub struct CommandValidator {
    config: ValidationConfig,
}

impl CommandValidator {
    /// Create a new validator with the given config.
    pub fn new(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a command string.
    pub fn validate_command(&self, command: &str) -> Result<(), ValidationError> {
        // Check length
        if command.len() > self.config.max_command_length {
            return Err(ValidationError::CommandTooLong {
                length: command.len(),
                max: self.config.max_command_length,
            });
        }

        // Check for empty command
        if command.trim().is_empty() {
            return Err(ValidationError::EmptyCommand);
        }

        // Check for dangerous patterns
        if self.config.block_dangerous {
            if let Some(pattern) = self.check_dangerous_patterns(command) {
                return Err(ValidationError::DangerousCommand {
                    pattern: pattern.to_string(),
                });
            }
        }

        // Check custom blocked patterns
        for pattern in &self.config.blocked_patterns {
            if command.contains(pattern) {
                return Err(ValidationError::BlockedPattern {
                    pattern: pattern.clone(),
                });
            }
        }

        // Check for null bytes
        if command.contains('\0') {
            return Err(ValidationError::InvalidCharacter('\0'));
        }

        Ok(())
    }

    /// Validate a timeout value.
    pub fn validate_timeout(&self, timeout_secs: u64) -> Result<Duration, ValidationError> {
        if timeout_secs < self.config.min_timeout_secs {
            return Err(ValidationError::TimeoutTooShort {
                value: timeout_secs,
                min: self.config.min_timeout_secs,
            });
        }

        if timeout_secs > self.config.max_timeout_secs {
            return Err(ValidationError::TimeoutTooLong {
                value: timeout_secs,
                max: self.config.max_timeout_secs,
            });
        }

        Ok(Duration::from_secs(timeout_secs))
    }

    /// Validate working directory path.
    pub fn validate_working_dir(&self, path: &str) -> Result<(), ValidationError> {
        // Check for path traversal attempts
        if path.contains("..") {
            return Err(ValidationError::PathTraversal);
        }

        // Check for null bytes
        if path.contains('\0') {
            return Err(ValidationError::InvalidCharacter('\0'));
        }

        // Basic length check
        if path.len() > 4096 {
            return Err(ValidationError::PathTooLong {
                length: path.len(),
                max: 4096,
            });
        }

        Ok(())
    }

    /// Check for common dangerous command patterns.
    fn check_dangerous_patterns(&self, command: &str) -> Option<&'static str> {
        let lower = command.to_lowercase();

        // Dangerous file operations
        if lower.contains("rm -rf /") || lower.contains("rm -fr /") {
            return Some("rm -rf /");
        }

        // Format/partition commands
        if lower.contains("mkfs") || lower.contains("fdisk") || lower.contains("parted") {
            return Some("disk formatting");
        }

        // Raw disk access
        if lower.contains("dd if=/dev") && lower.contains("of=/dev") {
            return Some("raw disk write");
        }

        // Fork bomb patterns
        if lower.contains(":(){") || lower.contains(":(){ :|:& };:") {
            return Some("fork bomb");
        }

        // Shutdown/reboot
        if lower.contains("shutdown") || lower.contains("reboot") || lower.contains("init 0") {
            return Some("system shutdown");
        }

        // Dangerous redirections
        if lower.contains("> /dev/sd") || lower.contains("> /dev/nvme") {
            return Some("device overwrite");
        }

        None
    }

    /// Get the max output size.
    pub fn max_output_size(&self) -> usize {
        self.config.max_output_size
    }
}

impl Default for CommandValidator {
    fn default() -> Self {
        Self::new(ValidationConfig::default())
    }
}

/// Validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Command exceeds maximum length.
    CommandTooLong { length: usize, max: usize },
    /// Command is empty.
    EmptyCommand,
    /// Command contains dangerous pattern.
    DangerousCommand { pattern: String },
    /// Command matches blocked pattern.
    BlockedPattern { pattern: String },
    /// Command contains invalid character.
    InvalidCharacter(char),
    /// Timeout is too short.
    TimeoutTooShort { value: u64, min: u64 },
    /// Timeout is too long.
    TimeoutTooLong { value: u64, max: u64 },
    /// Path contains traversal attempt.
    PathTraversal,
    /// Path is too long.
    PathTooLong { length: usize, max: usize },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandTooLong { length, max } => {
                write!(f, "Command too long: {} chars (max: {})", length, max)
            }
            Self::EmptyCommand => write!(f, "Command cannot be empty"),
            Self::DangerousCommand { pattern } => {
                write!(f, "Dangerous command pattern detected: {}", pattern)
            }
            Self::BlockedPattern { pattern } => {
                write!(f, "Command contains blocked pattern: {}", pattern)
            }
            Self::InvalidCharacter(c) => {
                write!(f, "Command contains invalid character: {:?}", c)
            }
            Self::TimeoutTooShort { value, min } => {
                write!(f, "Timeout too short: {}s (min: {}s)", value, min)
            }
            Self::TimeoutTooLong { value, max } => {
                write!(f, "Timeout too long: {}s (max: {}s)", value, max)
            }
            Self::PathTraversal => write!(f, "Path traversal detected"),
            Self::PathTooLong { length, max } => {
                write!(f, "Path too long: {} chars (max: {})", length, max)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Sanitize a command string.
///
/// This removes potentially dangerous characters without blocking the command.
/// Use this for logging or display purposes.
pub fn sanitize_for_display(command: &str) -> String {
    command
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(1000) // Limit display length
        .collect()
}

/// Check if a string looks like a shell injection attempt.
pub fn looks_like_injection(input: &str) -> bool {
    let suspicious_patterns = [
        "$(", "`", "${", "&&", "||", ";", "|", ">", "<", "\\n", "\\r",
    ];

    suspicious_patterns.iter().any(|p| input.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_config_default() {
        let config = ValidationConfig::default();
        assert_eq!(config.max_command_length, 4096);
        assert!(config.block_dangerous);
    }

    #[test]
    fn test_validation_config_strict() {
        let config = ValidationConfig::strict();
        assert_eq!(config.max_command_length, 1024);
        assert!(config.block_dangerous);
        assert!(!config.blocked_patterns.is_empty());
    }

    #[test]
    fn test_validate_command_ok() {
        let validator = CommandValidator::default();

        assert!(validator.validate_command("ls -la").is_ok());
        assert!(validator.validate_command("echo hello world").is_ok());
        assert!(validator.validate_command("cat /etc/passwd").is_ok());
    }

    #[test]
    fn test_validate_command_empty() {
        let validator = CommandValidator::default();

        assert!(matches!(
            validator.validate_command(""),
            Err(ValidationError::EmptyCommand)
        ));
        assert!(matches!(
            validator.validate_command("   "),
            Err(ValidationError::EmptyCommand)
        ));
    }

    #[test]
    fn test_validate_command_too_long() {
        let validator = CommandValidator::new(ValidationConfig {
            max_command_length: 10,
            ..Default::default()
        });

        let result = validator.validate_command("this is a very long command");
        assert!(matches!(
            result,
            Err(ValidationError::CommandTooLong { .. })
        ));
    }

    #[test]
    fn test_validate_dangerous_rm() {
        let validator = CommandValidator::default();

        assert!(matches!(
            validator.validate_command("rm -rf /"),
            Err(ValidationError::DangerousCommand { .. })
        ));
        assert!(matches!(
            validator.validate_command("sudo rm -rf /home"),
            Err(ValidationError::DangerousCommand { .. })
        ));
    }

    #[test]
    fn test_validate_dangerous_fork_bomb() {
        let validator = CommandValidator::default();

        assert!(matches!(
            validator.validate_command(":(){ :|:& };:"),
            Err(ValidationError::DangerousCommand { .. })
        ));
    }

    #[test]
    fn test_validate_dangerous_shutdown() {
        let validator = CommandValidator::default();

        assert!(matches!(
            validator.validate_command("shutdown -h now"),
            Err(ValidationError::DangerousCommand { .. })
        ));
        assert!(matches!(
            validator.validate_command("reboot"),
            Err(ValidationError::DangerousCommand { .. })
        ));
    }

    #[test]
    fn test_validate_null_byte() {
        let validator = CommandValidator::default();

        assert!(matches!(
            validator.validate_command("ls\0 -la"),
            Err(ValidationError::InvalidCharacter('\0'))
        ));
    }

    #[test]
    fn test_validate_timeout() {
        let validator = CommandValidator::default();

        assert!(validator.validate_timeout(30).is_ok());
        assert!(validator.validate_timeout(1).is_ok());
        assert!(validator.validate_timeout(300).is_ok());

        assert!(matches!(
            validator.validate_timeout(0),
            Err(ValidationError::TimeoutTooShort { .. })
        ));
        assert!(matches!(
            validator.validate_timeout(1000),
            Err(ValidationError::TimeoutTooLong { .. })
        ));
    }

    #[test]
    fn test_validate_working_dir() {
        let validator = CommandValidator::default();

        assert!(validator.validate_working_dir("/home/user").is_ok());
        assert!(validator.validate_working_dir("/tmp").is_ok());

        assert!(matches!(
            validator.validate_working_dir("/home/../etc"),
            Err(ValidationError::PathTraversal)
        ));
    }

    #[test]
    fn test_blocked_patterns() {
        let validator = CommandValidator::new(ValidationConfig::strict());

        // "mkfs" is in strict blocked patterns but also dangerous
        // Use a pattern that's only in blocked_patterns
        assert!(matches!(
            validator.validate_command("dd if=/dev/zero"),
            Err(ValidationError::BlockedPattern { .. })
        ));
    }

    #[test]
    fn test_permissive_allows_dangerous() {
        let validator = CommandValidator::new(ValidationConfig::permissive());

        // Permissive mode doesn't block dangerous commands
        assert!(validator.validate_command("rm -rf /").is_ok());
    }

    #[test]
    fn test_sanitize_for_display() {
        assert_eq!(sanitize_for_display("hello"), "hello");
        assert_eq!(sanitize_for_display("hello\nworld"), "hello\nworld");
        assert_eq!(sanitize_for_display("hello\x00world"), "helloworld");

        // Long string is truncated
        let long = "a".repeat(2000);
        assert_eq!(sanitize_for_display(&long).len(), 1000);
    }

    #[test]
    fn test_looks_like_injection() {
        assert!(looks_like_injection("echo $(whoami)"));
        assert!(looks_like_injection("echo `id`"));
        assert!(looks_like_injection("cmd1 && cmd2"));
        assert!(looks_like_injection("cmd1 | cmd2"));

        assert!(!looks_like_injection("echo hello"));
        assert!(!looks_like_injection("ls -la"));
    }
}
