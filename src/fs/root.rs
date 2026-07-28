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
    /// Canonicalisation is what decides escape: it resolves `..` *and* follows
    /// symlinks, so a link pointing out of the jail is caught by the same check
    /// that catches `../`. A substring rule catches neither reliably.
    pub fn resolve_existing(&self, rel: &str) -> Result<PathBuf, FsError> {
        let parts = Self::components(rel)?;
        let joined = parts.iter().fold(self.root.clone(), |acc, p| acc.join(p));

        let resolved = match joined.canonicalize() {
            Ok(resolved) => resolved,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Report NotFound only for a path that would have been inside
                // the jail; otherwise the distinction leaks what is outside.
                return match Self::lexical_within(&self.root, &joined) {
                    true => Err(FsError::NotFound),
                    false => Err(FsError::Escapes),
                };
            }
            Err(_) => return Err(FsError::NotFound),
        };

        if resolved.starts_with(&self.root) {
            Ok(resolved)
        } else {
            Err(FsError::Escapes)
        }
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
