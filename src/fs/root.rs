//! The jail boundary: the only way a path reaches the filesystem.

use std::path::{Component, Path, PathBuf};

use crate::fs::platform;

/// Why a path was refused.
///
/// Deliberately coarse. Distinguishing "outside the root and exists" from
/// "outside the root and does not exist" would make the API an oracle for the
/// filesystem beyond the jail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// The path is not of an acceptable shape (400).
    Malformed(&'static str),
    /// The path resolves outside the root (403).
    Escapes,
    /// The path is inside the root but does not exist (404).
    NotFound,
}

/// A directory the API may touch, and nothing outside it.
///
/// Held by value in the app state; every filesystem path in the API is produced
/// by one of these methods and by no other route.
#[derive(Debug, Clone)]
pub struct FsRoot {
    root: PathBuf,
}

impl FsRoot {
    /// Anchor a jail at `root`, which must already exist.
    ///
    /// Canonicalised once here so every later comparison is against a path with
    /// symlinks already resolved — otherwise a symlinked root would make every
    /// containment check compare unlike things.
    pub fn new(root: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self {
            root: root.as_ref().canonicalize()?,
        })
    }

    /// The jail's own path.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Split a request path into components, refusing anything not of the
    /// documented shape (root-relative, POSIX separators).
    ///
    /// Backslashes are treated as separators too: a Windows-shaped path from a
    /// careless client should be split and checked, not smuggled through as one
    /// giant component that no rule matches.
    fn components(rel: &str) -> Result<Vec<&str>, FsError> {
        if rel.is_empty() {
            return Err(FsError::Malformed("path is empty"));
        }
        if rel.starts_with('/') || rel.starts_with('\\') {
            return Err(FsError::Malformed("path must be relative to the root"));
        }
        // `C:` or any drive-letter prefix.
        let bytes = rel.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            return Err(FsError::Malformed("path must not name a drive"));
        }

        let mut out = Vec::new();
        for part in rel.split(['/', '\\']) {
            if part == "." {
                continue;
            }
            if part == ".." {
                // Kept as a component so canonicalisation can resolve it; the
                // containment check is what decides the outcome.
                out.push(part);
                continue;
            }
            platform::check_component(part).map_err(FsError::Malformed)?;
            out.push(part);
        }
        if out.is_empty() {
            return Err(FsError::Malformed("path is empty"));
        }
        Ok(out)
    }

    /// Resolve a path that must already exist.
    ///
    /// Containment is decided by canonicalising the deepest part of the path
    /// that exists, never by the *kind* of error a full canonicalisation
    /// returned. Branching on the error kind is what leaks: a path whose parent
    /// is a file fails with ENOTDIR while a path whose parent is absent fails
    /// with NotFound, so answering differently tells the caller which files
    /// exist outside the jail. It also mishandles a symlink that points out of
    /// the root — the link resolves, the target does not exist, and a lexical
    /// check sees a path that never left.
    ///
    /// Walking down instead means every real directory on the way is resolved
    /// through its symlinks and checked, and the verdict never depends on an
    /// errno. `resolve_for_create` uses the same discipline.
    pub fn resolve_existing(&self, rel: &str) -> Result<PathBuf, FsError> {
        // `.` names the root itself. Addressing the root is part of the jail's
        // addressing scheme, so it is answered here rather than special-cased by
        // each handler that needs it — `list` needs it first, but it is not the
        // only caller that ever will.
        //
        // `""` deliberately stays an error: an API where an omitted or empty
        // parameter silently means "the entire tree" is a footgun. Naming the
        // root should be explicit.
        //
        // Only the bare `.` needs this. `./app` and `app/.` already work —
        // `components` strips `.` as a no-op, leaving a non-empty path.
        if rel == "." {
            // Already canonicalised in `new`, so containment holds trivially.
            return Ok(self.root.clone());
        }

        let parts = Self::components(rel)?;

        let mut base = self.root.clone();
        let mut missing = false;
        for part in &parts {
            let candidate = base.join(part);
            match candidate.canonicalize() {
                Ok(resolved) => {
                    // Checked at every level, so a symlink out of the jail is
                    // caught the moment it is traversed rather than at the end.
                    if !resolved.starts_with(&self.root) {
                        return Err(FsError::Escapes);
                    }
                    base = resolved;
                }
                Err(_) => {
                    // A name that exists as a symlink but will not canonicalise
                    // is a dangling link, and where it points cannot be checked
                    // — `canonicalize` fails outright on one, revealing neither
                    // that a link was involved nor its target. Refuse it.
                    //
                    // Uniformly `Escapes`, never a split on where the target
                    // would have been: deciding that lexically would answer
                    // differently for a link pointing inside than for one
                    // pointing outside, which is the existence oracle again by
                    // another route. Over-refusing a broken link inside the
                    // jail is the cheap side of that trade.
                    if candidate.symlink_metadata().is_ok() {
                        return Err(FsError::Escapes);
                    }
                    // Nothing further can be resolved. Whether this is a
                    // refusal or a plain miss is decided lexically from here,
                    // identically for every error the OS might have given.
                    missing = true;
                    break;
                }
            }
        }

        if missing {
            let joined = parts.iter().fold(self.root.clone(), |acc, p| acc.join(p));
            return match Self::lexical_within(&self.root, &joined) {
                true => Err(FsError::NotFound),
                false => Err(FsError::Escapes),
            };
        }

        Ok(base)
    }

    /// Resolve a path that does not exist yet (an upload target).
    ///
    /// The target itself cannot be canonicalised, so the nearest existing
    /// ancestor is canonicalised instead and the remaining segments are checked
    /// lexically. Those segments may not contain `..`: with nothing on disk to
    /// resolve against, a traversal there would go unnoticed until the write.
    pub fn resolve_for_create(&self, rel: &str) -> Result<PathBuf, FsError> {
        let parts = Self::components(rel)?;
        if parts.contains(&"..") {
            return Err(FsError::Escapes);
        }

        // Walk down from the root, canonicalising while the path still exists.
        let mut base = self.root.clone();
        let mut tail: Vec<&str> = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            let candidate = base.join(part);
            match candidate.canonicalize() {
                Ok(resolved) => {
                    if !resolved.starts_with(&self.root) {
                        return Err(FsError::Escapes);
                    }
                    base = resolved;
                }
                Err(_) => {
                    // Same dangling-symlink refusal as `resolve_existing`, and
                    // load-bearing here rather than merely tidy: handing back a
                    // path whose last existing component is a link pointing out
                    // of the jail means whatever writes to it writes outside.
                    if candidate.symlink_metadata().is_ok() {
                        return Err(FsError::Escapes);
                    }
                    tail = parts[index..].to_vec();
                    break;
                }
            }
        }

        if !base.starts_with(&self.root) {
            return Err(FsError::Escapes);
        }
        Ok(tail.iter().fold(base, |acc, p| acc.join(p)))
    }

    /// Render an absolute path inside the jail as a root-relative POSIX string.
    ///
    /// Returns `None` for anything outside, so a caller cannot accidentally
    /// publish a path it should not have.
    pub fn relative(&self, abs: &Path) -> Option<String> {
        let rest = abs.strip_prefix(&self.root).ok()?;
        let mut out = String::new();
        for component in rest.components() {
            if let Component::Normal(part) = component {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(&part.to_string_lossy());
            }
        }
        Some(out)
    }

    /// Whether `candidate` sits under `root` by string shape alone.
    ///
    /// Used only to choose between 404 and 403 for a path that does not exist,
    /// where there is nothing on disk to canonicalise.
    fn lexical_within(root: &Path, candidate: &Path) -> bool {
        let mut depth: i64 = 0;
        let Ok(rest) = candidate.strip_prefix(root) else {
            return false;
        };
        for component in rest.components() {
            match component {
                Component::ParentDir => depth -= 1,
                Component::Normal(_) => depth += 1,
                _ => {}
            }
            if depth < 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_with(files: &[&str]) -> (tempfile::TempDir, FsRoot) {
        let dir = tempfile::tempdir().expect("tempdir");
        for file in files {
            let path = dir.path().join(file);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(&path, b"x").expect("write");
        }
        let root = FsRoot::new(dir.path()).expect("root");
        (dir, root)
    }

    /// Like `root_with`, but for a test that also needs to place something
    /// *outside* the jail (a probe file, a sibling directory, a symlink
    /// target).
    ///
    /// The jail root is a subdirectory of the returned `TempDir` rather than
    /// the `TempDir` itself, so anything a test writes as a sibling of the
    /// root is still inside the fixture that auto-cleans on drop. Without
    /// this, a test that panics before a manual cleanup line runs — which is
    /// exactly what these tests are designed to do when `FsRoot` regresses —
    /// leaks a file into the shared OS temp directory permanently.
    fn root_with_outside(files: &[&str]) -> (tempfile::TempDir, FsRoot) {
        let outer = tempfile::tempdir().expect("tempdir");
        let root_dir = outer.path().join("root");
        for file in files {
            let path = root_dir.join(file);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(&path, b"x").expect("write");
        }
        let root = FsRoot::new(&root_dir).expect("root");
        (outer, root)
    }

    /// Create a symlink for a test, tolerating the privilege some Windows
    /// accounts and CI runners lack (`SeCreateSymbolicLinkPrivilege`).
    ///
    /// Returns whether the link was created. A caller uses this to skip the
    /// test body early rather than let a missing privilege turn into a
    /// failing suite — the check under test is about path containment, not
    /// about the environment's symlink permissions.
    fn try_symlink(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            false
        }
    }

    #[test]
    fn a_file_inside_the_root_resolves() {
        let (_dir, root) = root_with(&["app/config.json"]);
        let resolved = root.resolve_existing("app/config.json").expect("resolve");
        assert!(resolved.ends_with("config.json"));
    }

    #[test]
    fn dot_dot_traversal_is_refused() {
        let (_dir, root) = root_with(&["app/config.json"]);
        assert_eq!(
            root.resolve_existing("../outside.txt"),
            Err(FsError::Escapes)
        );
        assert_eq!(
            root.resolve_existing("app/../../outside.txt"),
            Err(FsError::Escapes)
        );
    }

    #[test]
    fn a_filename_containing_two_dots_resolves() {
        // Regression against the old `validate_working_dir` substring rule.
        let (_dir, root) = root_with(&["my..file.txt"]);
        assert!(root.resolve_existing("my..file.txt").is_ok());
    }

    #[test]
    fn absolute_paths_are_refused() {
        let (_dir, root) = root_with(&["app/config.json"]);
        assert!(matches!(
            root.resolve_existing("/etc/passwd"),
            Err(FsError::Malformed(_))
        ));
        assert!(matches!(
            root.resolve_existing("C:/Windows/System32/config"),
            Err(FsError::Malformed(_))
        ));
        assert!(matches!(
            root.resolve_existing("\\\\server\\share\\file"),
            Err(FsError::Malformed(_))
        ));
    }

    #[test]
    fn reserved_and_stream_names_are_refused() {
        let (_dir, root) = root_with(&["app/config.json"]);
        assert!(matches!(
            root.resolve_existing("NUL"),
            Err(FsError::Malformed(_))
        ));
        assert!(matches!(
            root.resolve_existing("app/config.json:hidden"),
            Err(FsError::Malformed(_))
        ));
    }

    #[test]
    fn a_missing_file_inside_the_root_is_not_found() {
        let (_dir, root) = root_with(&["app/config.json"]);
        assert_eq!(
            root.resolve_existing("app/absent.json"),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn a_single_dot_names_the_root_itself() {
        // `list` needs to enumerate the root; without this there is no way to
        // name it at all.
        let (_dir, root) = root_with(&["app/config.json"]);
        assert_eq!(root.resolve_existing("."), Ok(root.path().to_path_buf()));

        // An empty path stays an error: "the whole tree" must be asked for
        // explicitly, never by omission.
        assert!(matches!(
            root.resolve_existing(""),
            Err(FsError::Malformed(_))
        ));

        // The root is not a creatable target.
        assert!(root.resolve_for_create(".").is_err());
    }

    #[test]
    fn an_escape_looks_the_same_whether_or_not_the_target_exists() {
        // The oracle this guards against: if a caller can tell "outside and
        // real" from "outside and absent", the jail reports on the filesystem
        // beyond it.
        let (outer, root) = root_with_outside(&["app/config.json"]);

        let present = outer.path().join("st-probe-present.txt");
        std::fs::write(&present, b"secret").expect("write probe");

        let existing = root.resolve_existing("../st-probe-present.txt");
        let absent = root.resolve_existing("../st-probe-absent.txt");

        assert_eq!(existing, Err(FsError::Escapes));
        assert_eq!(absent, Err(FsError::Escapes));
        assert_eq!(existing, absent, "the refusal must not reveal existence");
    }

    #[test]
    fn an_escape_through_an_existing_directory_is_refused() {
        // Exercises the walk's containment check directly rather than the
        // lexical fallback: every component here resolves to something that
        // is really on disk, so the "missing" branch never trips and the
        // verdict can only come from `!resolved.starts_with(&self.root)`. If
        // that check were removed, this would resolve successfully to a real
        // file outside the jail instead of failing.
        let (outer, root) = root_with_outside(&["app/config.json"]);
        let sibling = outer.path().join("st-sibling-dir");
        std::fs::create_dir_all(&sibling).expect("mkdir sibling");
        std::fs::write(sibling.join("target.txt"), b"secret").expect("write sibling file");

        let result = root.resolve_existing("app/../../st-sibling-dir/target.txt");

        assert_eq!(result, Err(FsError::Escapes));
    }

    #[test]
    fn a_dangling_symlink_pointing_outside_the_root_is_refused_by_resolve_existing() {
        // `canonicalize` fails outright on a dangling link, handing back
        // nothing to decide containment from — the exact gap that let a
        // dangling link into a missing outside target through as `NotFound`
        // instead of `Escapes`.
        let (outer, root) = root_with_outside(&["app/config.json"]);
        let link = root.path().join("dangle-existing");
        let missing_target = outer.path().join("st-dangling-target.txt"); // never created

        if !try_symlink(&missing_target, &link) {
            return; // symlink privilege unavailable on this runner; skip
        }

        assert_eq!(
            root.resolve_existing("dangle-existing"),
            Err(FsError::Escapes)
        );
    }

    #[test]
    fn a_dangling_symlink_pointing_outside_the_root_is_refused_by_resolve_for_create() {
        // Load-bearing rather than merely tidy: `resolve_for_create` feeds
        // upload destinations, so handing back a path through this link would
        // mean the write itself lands outside the root.
        let (outer, root) = root_with_outside(&["app/config.json"]);
        let link = root.path().join("dangle-create");
        let missing_target = outer.path().join("st-dangling-target-2.txt"); // never created

        if !try_symlink(&missing_target, &link) {
            return; // symlink privilege unavailable on this runner; skip
        }

        assert_eq!(
            root.resolve_for_create("dangle-create/new.bin"),
            Err(FsError::Escapes)
        );
    }

    #[test]
    fn a_create_target_need_not_exist_yet() {
        let (_dir, root) = root_with(&["app/config.json"]);
        let target = root
            .resolve_for_create("app/new.bin")
            .expect("create target");
        assert!(target.ends_with("new.bin"));
        assert!(!target.exists());
    }

    #[test]
    fn a_create_target_may_not_escape_through_a_missing_segment() {
        let (_dir, root) = root_with(&["app/config.json"]);
        assert!(matches!(
            root.resolve_for_create("app/../../escape.bin"),
            Err(FsError::Escapes) | Err(FsError::Malformed(_))
        ));
    }

    #[test]
    fn relative_renders_posix_separators() {
        let (_dir, root) = root_with(&["app/config.json"]);
        let abs = root.resolve_existing("app/config.json").expect("resolve");
        assert_eq!(root.relative(&abs).as_deref(), Some("app/config.json"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        let (dir, root) = root_with(&["app/config.json"]);
        let outside = dir
            .path()
            .parent()
            .expect("parent")
            .join("st-outside-target");
        std::fs::write(&outside, b"secret").expect("write outside");
        std::os::unix::fs::symlink(&outside, dir.path().join("link")).expect("symlink");

        assert_eq!(root.resolve_existing("link"), Err(FsError::Escapes));

        std::fs::remove_file(&outside).ok();
    }
}
