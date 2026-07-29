//! Capability set — the frozen access-control *mechanism* (Phase A wire contract v1).
//!
//! A token carries a **set** of capability strings. A route declares a
//! **required-capability**; an access decision is a **set-membership** check.
//! The literal `"*"` is a **wildcard** that satisfies every capability check.
//!
//! Only this *mechanism* is contractual (frozen). The capability *vocabulary*
//! (which strings exist, e.g. `exec`, `session.read`) and role *presets* are
//! **non-contract** and grow additively — new strings may be added, but renaming,
//! removing, or tightening an existing string is breaking. See the Phase A spec.

use std::collections::HashSet;

/// The wildcard capability: a token holding it passes every capability check.
pub const WILDCARD: &str = "*";

/// An unordered set of capability strings held by a token.
///
/// Access control is pure set membership with a single special case: the
/// [`WILDCARD`] string satisfies any required capability.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet(HashSet<String>);

impl CapabilitySet {
    /// Create an empty capability set (holds no capabilities).
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Create a wildcard set — satisfies **every** capability check.
    ///
    /// This is the set held by the `full-control` preset and the legacy-key
    /// mapping target (spec §4).
    pub fn wildcard() -> Self {
        let mut set = HashSet::new();
        set.insert(WILDCARD.to_string());
        Self(set)
    }

    /// Whether this set **satisfies** `required` — either it holds the wildcard,
    /// or it directly contains the required capability string.
    ///
    /// This is the frozen access-decision primitive (spec §2.1).
    pub fn satisfies(&self, required: &str) -> bool {
        self.0.contains(WILDCARD) || self.0.contains(required)
    }

    /// Whether this set holds the wildcard capability.
    pub fn is_wildcard(&self) -> bool {
        self.0.contains(WILDCARD)
    }

    /// Insert a capability string into the set.
    pub fn insert(&mut self, capability: impl Into<String>) {
        self.0.insert(capability.into());
    }

    /// Number of capability strings in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set holds no capabilities.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over the capability strings.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.0.iter()
    }
}

impl<S: Into<String>> FromIterator<S> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

/// Resolve a role **preset** name to its capability set (spec §6).
///
/// Presets are a **non-contract** convenience mapping — they may change freely
/// and are not part of the frozen wire contract. Returns `None` for an unknown
/// name so the caller can surface a clear error.
/// Capability strings the router currently maps routes onto.
///
/// Vocabulary, not mechanism — additive by design (see the module header).
/// `fs.read` and `fs.write` are deliberately absent from every preset: adding
/// them to `operator` would hand file access to tokens already issued, which is
/// a privilege change nobody asked for. They are granted only by naming them,
/// e.g. `--capabilities fs.read,fs.write`.
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "exec",
    "session.read",
    "session.manage",
    "fs.read",
    "fs.write",
];

pub fn preset(name: &str) -> Option<CapabilitySet> {
    match name {
        "operator" => Some(
            ["exec", "session.read", "session.manage"]
                .into_iter()
                .collect(),
        ),
        "read-only" => Some(["session.read"].into_iter().collect()),
        "full-control" => Some(CapabilitySet::wildcard()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_set_satisfies_nothing() {
        let set = CapabilitySet::new();
        assert!(set.is_empty());
        assert!(!set.satisfies("exec"));
        assert!(!set.is_wildcard());
    }

    #[test]
    fn test_wildcard_satisfies_everything() {
        let set = CapabilitySet::wildcard();
        assert!(set.is_wildcard());
        assert!(set.satisfies("exec"));
        assert!(set.satisfies("session.read"));
        assert!(set.satisfies("anything.at.all"));
    }

    #[test]
    fn test_membership_is_exact() {
        let set: CapabilitySet = ["session.read"].into_iter().collect();
        assert!(set.satisfies("session.read"));
        // Not a prefix/hierarchy match — membership is exact.
        assert!(!set.satisfies("session.manage"));
        assert!(!set.satisfies("session"));
        assert!(!set.is_wildcard());
    }

    #[test]
    fn test_multiple_capabilities() {
        let set: CapabilitySet = ["exec", "session.read", "session.manage"]
            .into_iter()
            .collect();
        assert_eq!(set.len(), 3);
        assert!(set.satisfies("exec"));
        assert!(set.satisfies("session.read"));
        assert!(set.satisfies("session.manage"));
        assert!(!set.satisfies("fs.read"));
    }

    #[test]
    fn test_insert() {
        let mut set = CapabilitySet::new();
        set.insert("exec");
        assert!(set.satisfies("exec"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_presets() {
        let operator = preset("operator").unwrap();
        assert!(operator.satisfies("exec"));
        assert!(operator.satisfies("session.read"));
        assert!(operator.satisfies("session.manage"));
        assert!(!operator.is_wildcard());

        let read_only = preset("read-only").unwrap();
        assert!(read_only.satisfies("session.read"));
        assert!(!read_only.satisfies("session.manage"));
        assert!(!read_only.satisfies("exec"));

        let full = preset("full-control").unwrap();
        assert!(full.is_wildcard());
        assert!(full.satisfies("anything"));

        assert!(preset("nonexistent").is_none());
    }
}
