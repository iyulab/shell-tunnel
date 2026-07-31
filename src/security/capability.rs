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

/// Capability strings the router currently maps routes onto.
///
/// Vocabulary, not mechanism — additive by design (see the module header).
/// See [`preset`] for why the presets below draw their boundary at `exec`
/// rather than at `fs.*`.
///
/// The practical consequence — and what `src/fs/root.rs` points here for: a
/// `--fs-root` jail confines something only for a token holding `fs.*`
/// **without** `exec`, which is exactly what `file-read` and `file-write`
/// grant. Against `operator` or `full-control` it is a convenience boundary —
/// chunked, resumable, checksummed transfer instead of piping bytes through a
/// command — and not a containment one, because `exec` already reaches every
/// file this process can. Both halves matter: the second is why the file API
/// needs no flag to exist, the first is why `--fs-root` still has a job.
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "exec",
    "session.read",
    "session.manage",
    "fs.read",
    "fs.write",
];

/// Resolve a role **preset** name to its capability set (spec §6).
///
/// Presets are a **non-contract** convenience mapping — they may change freely
/// and are not part of the frozen wire contract. Returns `None` for an unknown
/// name so the caller can surface a clear error.
///
/// **The gradient's cut line is `exec`.** A token holding `exec` reaches every
/// file this process can, so withholding the file API from it confines nothing
/// and only forces callers onto the slow path. The presets below therefore
/// split into "carries exec, and so carries everything" and "carries no exec,
/// and so the file capabilities are a real boundary".
pub fn preset(name: &str) -> Option<CapabilitySet> {
    match name {
        // `fs.read`/`fs.write` sit alongside `exec` here rather than being
        // withheld from it: this preset already grants command execution, which
        // reaches every file this process can. See `KNOWN_CAPABILITIES` above.
        "operator" => Some(
            [
                "exec",
                "session.read",
                "session.manage",
                "fs.read",
                "fs.write",
            ]
            .into_iter()
            .collect(),
        ),
        // No `exec`, so the file capabilities are the whole grant and a
        // `--fs-root` jail actually confines something. `session.*` is
        // deliberately absent: without `exec` there is no session to read.
        "file-write" => Some(["fs.read", "fs.write"].into_iter().collect()),
        "file-read" => Some(["fs.read"].into_iter().collect()),
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
    fn file_presets_carry_no_exec() {
        let read = preset("file-read").expect("file-read must exist");
        assert!(read.satisfies("fs.read"));
        assert!(!read.satisfies("fs.write"));
        assert!(!read.satisfies("exec"));
        // Not slipping in anything the name doesn't promise: without `exec`
        // there is no session to create, so session lookup would be useless.
        assert!(!read.satisfies("session.read"));
        assert_eq!(read.len(), 1);

        let write = preset("file-write").expect("file-write must exist");
        assert!(write.satisfies("fs.read"));
        assert!(write.satisfies("fs.write"));
        assert!(!write.satisfies("exec"));
        assert!(!write.satisfies("session.read"));
        assert_eq!(write.len(), 2);
    }

    #[test]
    fn read_only_is_gone_rather_than_silently_redefined() {
        // This preset's name and behaviour used to disagree ("read-only" that
        // couldn't read a file). Keeping the name as an alias while changing
        // its meaning would be a silent capability escalation for existing
        // tokens picking up `fs.read` — removal is the honest direction.
        assert!(preset("read-only").is_none());
    }

    #[test]
    fn test_presets() {
        let operator = preset("operator").unwrap();
        assert!(operator.satisfies("exec"));
        assert!(operator.satisfies("session.read"));
        assert!(operator.satisfies("session.manage"));
        // Carried because `exec` above already reaches every file this process
        // can: withholding them confined nothing. Asserted rather than left
        // implicit so removing them again has to be a deliberate act.
        assert!(operator.satisfies("fs.read"));
        assert!(operator.satisfies("fs.write"));
        assert!(!operator.is_wildcard());

        let full = preset("full-control").unwrap();
        assert!(full.is_wildcard());
        assert!(full.satisfies("anything"));

        assert!(preset("nonexistent").is_none());
    }
}
