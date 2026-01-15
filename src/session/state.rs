//! Session state machine.

/// Represents the lifecycle state of a shell session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    /// Session has been created but not yet activated.
    #[default]
    Created,
    /// Session is actively processing commands.
    Active,
    /// Session is idle, waiting for commands.
    Idle,
    /// Session has been terminated and cannot be reused.
    Terminated,
}

impl SessionState {
    /// Check if transition to target state is valid.
    ///
    /// Valid transitions:
    /// - Created -> Active
    /// - Active -> Idle
    /// - Active -> Terminated
    /// - Idle -> Active
    /// - Idle -> Terminated
    pub fn can_transition_to(&self, target: SessionState) -> bool {
        use SessionState::*;
        matches!(
            (*self, target),
            (Created, Active)
                | (Active, Idle)
                | (Active, Terminated)
                | (Idle, Active)
                | (Idle, Terminated)
        )
    }

    /// Attempt to transition to a new state.
    ///
    /// Returns `Ok(())` if the transition is valid, or an error otherwise.
    pub fn transition_to(&mut self, target: SessionState) -> crate::Result<()> {
        if self.can_transition_to(target) {
            *self = target;
            Ok(())
        } else {
            Err(crate::error::ShellTunnelError::InvalidStateTransition {
                from: *self,
                to: target,
            })
        }
    }

    /// Check if this is a terminal state (no further transitions possible).
    pub fn is_terminal(&self) -> bool {
        matches!(self, SessionState::Terminated)
    }

    /// Check if session can accept commands.
    pub fn can_execute(&self) -> bool {
        matches!(self, SessionState::Active | SessionState::Idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        // Created -> Active
        let mut state = SessionState::Created;
        assert!(state.transition_to(SessionState::Active).is_ok());
        assert_eq!(state, SessionState::Active);

        // Active -> Idle
        assert!(state.transition_to(SessionState::Idle).is_ok());
        assert_eq!(state, SessionState::Idle);

        // Idle -> Active (resume)
        assert!(state.transition_to(SessionState::Active).is_ok());
        assert_eq!(state, SessionState::Active);

        // Active -> Terminated
        assert!(state.transition_to(SessionState::Terminated).is_ok());
        assert_eq!(state, SessionState::Terminated);
    }

    #[test]
    fn test_invalid_created_to_idle() {
        let mut state = SessionState::Created;
        assert!(state.transition_to(SessionState::Idle).is_err());
        // State should remain unchanged
        assert_eq!(state, SessionState::Created);
    }

    #[test]
    fn test_invalid_from_terminated() {
        let mut state = SessionState::Terminated;
        assert!(state.transition_to(SessionState::Active).is_err());
        assert!(state.transition_to(SessionState::Idle).is_err());
        assert!(state.transition_to(SessionState::Created).is_err());
    }

    #[test]
    fn test_is_terminal() {
        assert!(!SessionState::Created.is_terminal());
        assert!(!SessionState::Active.is_terminal());
        assert!(!SessionState::Idle.is_terminal());
        assert!(SessionState::Terminated.is_terminal());
    }

    #[test]
    fn test_can_execute() {
        assert!(!SessionState::Created.can_execute());
        assert!(SessionState::Active.can_execute());
        assert!(SessionState::Idle.can_execute());
        assert!(!SessionState::Terminated.can_execute());
    }

    #[test]
    fn test_default() {
        let state = SessionState::default();
        assert_eq!(state, SessionState::Created);
    }
}
