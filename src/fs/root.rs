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

/// Drop Windows' verbatim prefix (`\\?\`) from an already-rendered path.
///
/// `canonicalize` returns verbatim paths, and every path this module hands
/// outward came through it. The prefix is correct and is never what a caller
/// sent, so leaving it in means one file has two names — one on the wire and
/// one in the banner. One helper because there are two consumers already and a
/// third would otherwise open-code it again: `relative` and `describe` each
/// stripped it separately before this existed.
fn strip_verbatim(rendered: &str) -> &str {
    rendered.strip_prefix(r"\\?\").unwrap_or(rendered)
}

/// What the API is allowed to reach.
///
/// Two shapes, one resolver. Every path still reaches the disk through the same
/// walk-down-and-check discipline in `resolve_existing`/`resolve_for_create` —
/// only the anchor a request is measured against, and the containment verdict,
/// differ. Adding a second path-resolution route instead would mean the
/// existence-oracle, symlink, and traversal reasoning those two functions carry
/// has to hold in a place it was never reviewed for.
#[derive(Debug, Clone)]
enum Scope {
    /// One subtree. Request paths are relative to it; nothing outside is
    /// reachable. This is what `--fs-root` selects.
    Jailed(PathBuf),
    /// Everything the account running this process can already reach. Request
    /// paths are absolute, and each is measured against the filesystem anchor
    /// it names (a drive root on Windows, `/` on Unix).
    ///
    /// Not a hole in the jail — the jail was never a boundary against a token
    /// holding `exec`, which can read and write anything this process can. See
    /// `KNOWN_CAPABILITIES` in `src/security/capability.rs`. What this shape
    /// buys is that the file API reaches the same places `exec` does, so an
    /// agent does not have to fall back to piping bytes through a command for
    /// any destination outside one chosen subtree.
    Machine(Vec<PathBuf>),
}

/// What the filesystem API may touch.
///
/// Held by value in the app state; every filesystem path in the API is produced
/// by one of these methods and by no other route.
#[derive(Debug, Clone)]
pub struct FsRoot {
    scope: Scope,
}

impl FsRoot {
    /// Anchor a jail at `root`, which must already exist.
    ///
    /// Canonicalised once here so every later comparison is against a path with
    /// symlinks already resolved — otherwise a symlinked root would make every
    /// containment check compare unlike things.
    pub fn new(root: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self {
            scope: Scope::Jailed(root.as_ref().canonicalize()?),
        })
    }

    /// Reach everything this account can, with no subtree restriction.
    ///
    /// The default when `--fs-root` is not given. Anchors are enumerated once,
    /// here, so a drive that appears later is not silently reachable by a
    /// server that started before it existed.
    pub fn machine_wide() -> Self {
        Self {
            scope: Scope::Machine(platform::filesystem_anchors()),
        }
    }

    /// The jail's own path, or `None` when the scope is the whole machine.
    ///
    /// Returns an `Option` rather than a bare `Path` because machine-wide scope
    /// genuinely has no single path: on Windows there is nothing above `C:\`
    /// and `D:\` to name. A caller that needs one — the audit-log containment
    /// check at startup, say — has to say what it does when there isn't one.
    pub fn jail_path(&self) -> Option<&Path> {
        match &self.scope {
            Scope::Jailed(root) => Some(root),
            Scope::Machine(_) => None,
        }
    }

    /// One line naming the effective scope, for the startup banner.
    ///
    /// The banner is the only thing standing between an operator and a scope
    /// wider than they assumed, now that the file API no longer needs a flag to
    /// exist — so this states what is reachable, not which flag was passed.
    pub fn describe(&self) -> String {
        match &self.scope {
            Scope::Jailed(root) => Self::displayable(root),
            Scope::Machine(anchors) => {
                let names: Vec<String> = anchors.iter().map(|a| Self::displayable(a)).collect();
                format!("whole machine ({})", names.join(", "))
            }
        }
    }

    /// A path as an operator would write it.
    ///
    /// `canonicalize` yields verbatim paths on Windows, so an anchor prints as
    /// `\\?\C:\` unless the prefix is stripped — correct, and unreadable in a
    /// banner whose whole job is telling someone at a glance what the file API
    /// can reach.
    fn displayable(path: &Path) -> String {
        strip_verbatim(&path.display().to_string()).to_string()
    }

    /// Whether `resolved` sits inside the scope.
    ///
    /// One predicate for both shapes, so the walk in `resolve_existing` and
    /// `resolve_for_create` stays identical: a jail asks "under the root", a
    /// machine-wide scope asks "under any anchor". The second is close to
    /// vacuous by construction, which is the point — there is no outside to
    /// leak the existence of.
    fn contains(&self, resolved: &Path) -> bool {
        match &self.scope {
            Scope::Jailed(root) => resolved.starts_with(root),
            Scope::Machine(anchors) => anchors.iter().any(|a| resolved.starts_with(a)),
        }
    }

    /// Where a request path is measured from, and the components below it.
    ///
    /// A jail always anchors at its own root and takes a relative path. A
    /// machine-wide scope takes an absolute path and anchors at whatever
    /// filesystem root that path names — so `D:/x` is measured against `D:\`
    /// and `C:/x` against `C:\`, and a symlink from one to the other is still
    /// inside the scope because `contains` asks about every anchor.
    fn anchor_and_parts<'a>(&self, rel: &'a str) -> Result<(PathBuf, Vec<&'a str>), FsError> {
        match &self.scope {
            Scope::Jailed(root) => Ok((root.clone(), Self::components(rel)?)),
            Scope::Machine(anchors) => {
                let (named, rest) = Self::split_absolute(rel)?;
                // Canonicalised before the membership check so both sides are
                // in the same form. On Windows that form is verbatim
                // (`\\?\C:\`), which is what `canonicalize` returns for every
                // resolved path further down — comparing a plain `C:\` against
                // those would fail for everything that exists.
                let anchor = named.canonicalize().map_err(|_| FsError::Escapes)?;
                if !anchors.iter().any(|a| a == &anchor) {
                    // Not "no such drive" — that would answer differently for a
                    // drive that exists than for one that does not, which is the
                    // same existence oracle the jail is careful to avoid, just
                    // one level up.
                    return Err(FsError::Escapes);
                }
                let parts = if rest.is_empty() {
                    Vec::new()
                } else {
                    Self::components(rest)?
                };
                Ok((anchor, parts))
            }
        }
    }

    /// Split an absolute request path into its filesystem anchor and the rest.
    ///
    /// Accepts `C:/x`, `C:\x`, and `/x`; the separator style is the caller's
    /// choice, as it already is inside a jail. A relative path is refused here
    /// rather than resolved against the process's working directory: "relative
    /// to wherever the server happens to have been started" is not something a
    /// remote caller can reason about.
    fn split_absolute(rel: &str) -> Result<(PathBuf, &str), FsError> {
        if rel.is_empty() {
            return Err(FsError::Malformed("path is empty"));
        }
        if rel.starts_with("\\\\") || rel.starts_with("//") {
            return Err(FsError::Malformed(
                "UNC paths are not addressable; name a local path",
            ));
        }
        let bytes = rel.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            let drive = &rel[..2];
            let rest = rel[2..].trim_start_matches(['/', '\\']);
            return Ok((PathBuf::from(format!("{drive}\\")), rest));
        }
        if let Some(rest) = rel.strip_prefix('/') {
            return Ok((PathBuf::from("/"), rest));
        }
        Err(FsError::Malformed(
            "path must be absolute when no --fs-root is set",
        ))
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
            // Machine-wide scope has no "the root" for `.` to name, and falls
            // through to `anchor_and_parts`, which refuses a relative path.
            if let Some(root) = self.jail_path() {
                return Ok(root.to_path_buf());
            }
        }

        let (anchor, parts) = self.anchor_and_parts(rel)?;
        if parts.is_empty() {
            // The anchor itself (`C:/`), already a canonical filesystem root.
            return Ok(anchor);
        }

        let mut base = anchor.clone();
        let mut missing = false;
        for part in &parts {
            let candidate = base.join(part);
            match candidate.canonicalize() {
                Ok(resolved) => {
                    // Checked at every level, so a symlink out of the jail is
                    // caught the moment it is traversed rather than at the end.
                    if !self.contains(&resolved) {
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
            // Measured from the anchor this request named, not from "the root":
            // machine-wide scope has several, and asking the wrong one would
            // turn a plain miss on `D:` into an escape verdict.
            let joined = parts.iter().fold(anchor, |acc, p| acc.join(p));
            return match self.lexically_within(&joined) {
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
        let (anchor, parts) = self.anchor_and_parts(rel)?;
        if parts.contains(&"..") {
            return Err(FsError::Escapes);
        }
        if parts.is_empty() {
            // A filesystem anchor is never a create target.
            return Err(FsError::Malformed("path must name an entry to create"));
        }

        // Walk down from the anchor, canonicalising while the path still exists.
        let mut base = anchor;
        let mut tail: Vec<&str> = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            let candidate = base.join(part);
            match candidate.canonicalize() {
                Ok(resolved) => {
                    if !self.contains(&resolved) {
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

        if !self.contains(&base) {
            return Err(FsError::Escapes);
        }
        Ok(tail.iter().fold(base, |acc, p| acc.join(p)))
    }

    /// Render an absolute path as the string the API names it by.
    ///
    /// Inside a jail that is a root-relative POSIX string. Machine-wide it is
    /// the absolute path itself, with `\` normalised to `/` so one separator
    /// style comes back regardless of which one went in — the value is echoed
    /// in responses, used as the `list` cursor, and keyed on to detect two
    /// uploads racing for one destination, so it has to be stable per file.
    ///
    /// Returns `None` for anything outside the scope, so a caller cannot
    /// accidentally publish a path it should not have.
    pub fn relative(&self, abs: &Path) -> Option<String> {
        let root = match &self.scope {
            Scope::Jailed(root) => root.as_path(),
            Scope::Machine(_) => {
                if !self.contains(abs) {
                    return None;
                }
                // The verbatim prefix is an artefact of `canonicalize` on
                // Windows, not something a caller sent or could send — the
                // request that produced this path spelled it `C:/x`, and
                // echoing back `//?/C:/x` would name the same file a second
                // way. Stripped so one file has exactly one name on the wire.
                let text = abs.to_string_lossy();
                return Some(strip_verbatim(&text).replace('\\', "/"));
            }
        };
        let rest = abs.strip_prefix(root).ok()?;
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

    /// `lexical_within` against whichever anchor applies.
    fn lexically_within(&self, candidate: &Path) -> bool {
        match &self.scope {
            Scope::Jailed(root) => Self::lexical_within(root, candidate),
            Scope::Machine(anchors) => anchors.iter().any(|a| Self::lexical_within(a, candidate)),
        }
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
mod machine_wide_tests {
    use super::*;

    /// A real file, and the absolute path a caller would name it by.
    ///
    /// Machine-wide scope takes absolute paths, so these cannot reuse
    /// `root_with`'s root-relative fixtures — the point of the mode is that
    /// there is no root to be relative to.
    fn a_real_file() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("payload.txt");
        std::fs::write(&file, b"x").expect("write");
        // Canonicalised so the expectation matches what `resolve_existing`
        // returns on a platform whose temp directory is reached through a
        // symlink — the difference that made the walk test fail on macOS.
        let canonical = file.canonicalize().expect("canonicalize");
        // Named the way the API names it, not by hand: on Windows
        // `canonicalize` yields a verbatim path (`\\?\C:\…`) that no caller
        // would send and that `relative` deliberately strips.
        let named = FsRoot::machine_wide()
            .relative(&canonical)
            .expect("a real file is in scope");
        (dir, canonical, named)
    }

    #[test]
    fn an_absolute_path_resolves() {
        let (_dir, canonical, named) = a_real_file();
        let scope = FsRoot::machine_wide();

        assert_eq!(scope.resolve_existing(&named), Ok(canonical));
    }

    /// The mode's whole reason to exist: `--fs-root C:\` cannot reach `D:`,
    /// because Windows has no path above its drives. If this ever regresses to
    /// a single anchor, that limitation comes back and the file API stops
    /// reaching where `exec` does.
    #[test]
    fn every_filesystem_anchor_is_in_scope() {
        let scope = FsRoot::machine_wide();
        let anchors = platform::filesystem_anchors();
        assert!(!anchors.is_empty(), "a machine has at least one");

        for anchor in &anchors {
            let named = scope
                .relative(anchor)
                .expect("an anchor is in its own scope");
            assert_eq!(
                scope.resolve_existing(&named),
                Ok(anchor.clone()),
                "anchor {} must resolve to itself",
                anchor.display()
            );
        }
    }

    /// Not silently resolved against the process's working directory: a remote
    /// caller has no way to know what that is.
    #[test]
    fn a_relative_path_is_refused_rather_than_resolved_against_the_cwd() {
        let scope = FsRoot::machine_wide();

        assert_eq!(
            scope.resolve_existing("payload.txt"),
            Err(FsError::Malformed(
                "path must be absolute when no --fs-root is set"
            ))
        );
        // `.` names the jail's root, and there is no jail here.
        assert!(matches!(
            scope.resolve_existing("."),
            Err(FsError::Malformed(_))
        ));
    }

    /// The value echoed in responses, used as the `list` cursor, and keyed on
    /// to detect two uploads racing for one destination — so one file must
    /// name itself the same way regardless of the separator the caller used.
    #[test]
    fn one_file_gets_one_name() {
        let (_dir, canonical, named) = a_real_file();
        let scope = FsRoot::machine_wide();

        assert_eq!(scope.resolve_existing(&named), Ok(canonical.clone()));
        assert_eq!(scope.relative(&canonical), Some(named));
    }

    /// On Windows `C:\x` and `C:/x` name one file, so both spellings have to
    /// resolve to one path — the upload claim key is this string, and two names
    /// for one destination is the aliasing that lets two sessions race onto it.
    ///
    /// Deliberately not asserted on Unix, where it would be false: `\` is an
    /// ordinary filename character there, not a separator, so `\tmp\x` is a
    /// relative path naming a file called `\tmp\x` — refused rather than
    /// silently treated as absolute. Asserting separator-independence on both
    /// platforms is what made this test fail on Unix; the property is real, it
    /// just belongs to Windows.
    #[cfg(windows)]
    #[test]
    fn both_windows_separators_name_the_same_file() {
        let (_dir, _canonical, named) = a_real_file();
        let scope = FsRoot::machine_wide();

        let via_forward = scope.resolve_existing(&named).expect("forward slashes");
        let via_back = scope
            .resolve_existing(&named.replace('/', "\\"))
            .expect("backslashes");
        assert_eq!(via_forward, via_back);
    }

    /// A backslash-led path is not absolute on Unix, and must not be taken for
    /// one: silently reading it as a rooted path would resolve a request that
    /// named a file this scope was never asked about.
    #[cfg(unix)]
    #[test]
    fn a_backslash_led_path_is_not_absolute_on_unix() {
        let scope = FsRoot::machine_wide();

        assert_eq!(
            scope.resolve_existing("\\tmp\\payload.txt"),
            Err(FsError::Malformed(
                "path must be absolute when no --fs-root is set"
            ))
        );
    }

    #[test]
    fn a_missing_file_is_not_found_rather_than_an_escape() {
        let (dir, _canonical, _named) = a_real_file();
        let absent = dir.path().join("absent.txt");
        let scope = FsRoot::machine_wide();

        assert_eq!(
            scope.resolve_existing(&absent.to_string_lossy().replace('\\', "/")),
            Err(FsError::NotFound)
        );
    }

    /// A UNC path is refused rather than half-supported: `\\server\share` has
    /// no anchor in `filesystem_anchors`, and answering "not in scope" for it
    /// while answering something else for a local path would be a difference
    /// worth reasoning about. Named explicitly so adding UNC support later is
    /// a deliberate act.
    #[test]
    fn a_unc_path_is_refused_as_malformed() {
        let scope = FsRoot::machine_wide();

        assert_eq!(
            scope.resolve_existing("//server/share/x"),
            Err(FsError::Malformed(
                "UNC paths are not addressable; name a local path"
            ))
        );
        assert_eq!(
            scope.resolve_existing("\\\\server\\share\\x"),
            Err(FsError::Malformed(
                "UNC paths are not addressable; name a local path"
            ))
        );
    }

    /// `jail_path` is what every caller that needs a single directory keys on
    /// — the audit-log containment check, the startup orphan sweep, the
    /// staging directory. Each has to behave differently here, so returning
    /// `None` is load-bearing rather than cosmetic.
    #[test]
    fn machine_wide_scope_has_no_single_path() {
        assert!(FsRoot::machine_wide().jail_path().is_none());

        let dir = tempfile::tempdir().expect("tempdir");
        let jailed = FsRoot::new(dir.path()).expect("root");
        assert!(jailed.jail_path().is_some());
    }

    /// The banner is the only thing telling an operator the file API now
    /// reaches past whatever directory they started the server in.
    #[test]
    fn the_banner_line_names_what_is_reachable() {
        let described = FsRoot::machine_wide().describe();
        assert!(described.contains("whole machine"), "{described}");
        for anchor in platform::filesystem_anchors() {
            let readable = FsRoot::displayable(&anchor);
            assert!(
                described.contains(&readable),
                "{described} must name {readable}"
            );
        }
        // The verbatim prefix `canonicalize` produces on Windows is an
        // implementation detail; a banner that printed `\\?\C:\` would be
        // correct and unreadable.
        assert!(!described.contains(r"\\?\"), "{described}");

        let dir = tempfile::tempdir().expect("tempdir");
        let jailed = FsRoot::new(dir.path()).expect("root");
        assert!(!jailed.describe().contains("whole machine"));
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
        assert_eq!(
            root.resolve_existing("."),
            Ok(root.jail_path().expect("jailed").to_path_buf())
        );

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
        let link = root.jail_path().expect("jailed").join("dangle-existing");
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
        let link = root.jail_path().expect("jailed").join("dangle-create");
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
