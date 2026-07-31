//! 디렉터리 트리를 세거나 제거한다.
//!
//! 미리보기(`dry_run`)와 실행이 **같은 순회를 통과**한다. 갈라두면 미리보기가
//! 거짓말을 하게 되고, 그 거짓말은 지운 뒤에야 드러난다.

use std::path::Path;

use crate::fs::{platform, FsRoot};

/// 한 번의 트리 연산 결과.
///
/// `removed`/`bytes`는 항상 정확하다. `entries`는 `limit`까지만 담고 넘치면
/// `truncated`가 선다 — 릴레이 본문 상한이 8 MiB이고, 이 응답의 목적은
/// "얼마나 큰 일인가"를 알리는 것이지 목록을 완전히 나르는 것이 아니다.
#[derive(Debug, Default)]
pub struct TreeOutcome {
    pub removed: u64,
    pub bytes: u64,
    pub entries: Vec<String>,
    pub truncated: bool,
    /// 제거에 실패한 항목. 비어 있지 않으면 호출자가 부분 실패로 보고한다.
    pub failures: Vec<String>,
}

/// `target` 아래를 전부 세고, `dry_run`이 아니면 제거한다.
///
/// 자식을 먼저 처리하고 부모를 나중에 처리한다 — 반대로 하면 부모를 지운
/// 뒤 자식을 셀 수 없다.
///
/// 심볼릭 링크는 **따라가지 않는다**. 링크는 그 자체가 한 항목이고,
/// `platform::remove_entry`가 플랫폼별 올바른 제거(Windows 디렉터리 reparse
/// point 포함)를 한다. 따라가면 트리 밖을 지운다.
pub fn remove_tree(root: &FsRoot, target: &Path, dry_run: bool, limit: usize) -> TreeOutcome {
    let mut outcome = TreeOutcome::default();
    visit(root, target, dry_run, limit, &mut outcome);
    outcome
}

fn visit(root: &FsRoot, path: &Path, dry_run: bool, limit: usize, out: &mut TreeOutcome) {
    // lstat: 링크를 대상으로 착각하면 링크를 디렉터리로 보고 따라 들어간다.
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        out.failures.push(name_of(root, path));
        return;
    };

    if meta.is_dir() {
        // `is_dir()`은 lstat 결과이므로 심링크에는 서지 않는다 — 진짜
        // 디렉터리일 때만 내려간다.
        match std::fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    visit(root, &entry.path(), dry_run, limit, out);
                }
            }
            Err(_) => {
                out.failures.push(name_of(root, path));
                return;
            }
        }
    }

    out.removed += 1;
    if !meta.is_dir() {
        out.bytes += meta.len();
    }
    if out.entries.len() < limit {
        out.entries.push(name_of(root, path));
    } else {
        out.truncated = true;
    }

    if !dry_run {
        // `platform::remove_entry` is for symlinks -- it unlinks the link
        // itself with whichever syscall that needs. A real directory is not
        // its target: the function's own doc comment says its one existing
        // caller refuses directories before ever reaching it, so calling it
        // here on a directory would try to unlink a directory as a file and
        // fail. `meta.is_dir()` comes from `symlink_metadata` (lstat), so it
        // is true only for a genuine directory, never a symlink -- a
        // directory symlink still goes through `remove_entry` below.
        //
        // A recursive walk empties a directory before reaching it here, so
        // `remove_dir` is sufficient. It is also a safety net: `remove_dir`
        // fails on a non-empty directory, so if the children-first order
        // were ever broken, this fails loudly instead of silently leaving
        // files behind.
        let result = if meta.is_dir() {
            std::fs::remove_dir(path)
        } else {
            platform::remove_entry(path, &meta)
        };
        if result.is_err() {
            out.failures.push(name_of(root, path));
        }
    }
}

/// API가 이 경로를 부르는 이름. scope 바깥이면 원시 표기로 떨어진다 —
/// 실패 목록에 이름을 붙이는 것이 목적이므로 여기서 거부할 일은 아니다.
fn name_of(root: &FsRoot, path: &Path) -> String {
    root.relative(path)
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FsRoot;

    fn tree(files: &[&str]) -> (tempfile::TempDir, FsRoot) {
        let dir = tempfile::tempdir().expect("tempdir");
        for file in files {
            let path = dir.path().join(file);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, b"xy").expect("write");
        }
        let root = FsRoot::new(dir.path()).expect("root");
        (dir, root)
    }

    #[test]
    fn a_dry_run_counts_everything_and_removes_nothing() {
        let (dir, root) = tree(&["app/a.txt", "app/deep/b.txt"]);
        let target = root.resolve_existing("app").expect("resolve");

        let outcome = remove_tree(&root, &target, true, 100);

        // app, app/a.txt, app/deep, app/deep/b.txt
        assert_eq!(outcome.removed, 4);
        assert_eq!(outcome.bytes, 4, "두 파일 × 2바이트");
        assert!(outcome.failures.is_empty());
        // 응답이 아니라 디스크로 확인한다: "안 지웠다"는 응답만으로 증명되지 않는다.
        assert!(dir.path().join("app/a.txt").exists());
        assert!(dir.path().join("app/deep/b.txt").exists());
    }

    #[test]
    fn a_real_run_removes_the_whole_tree() {
        let (dir, root) = tree(&["app/a.txt", "app/deep/b.txt"]);
        let target = root.resolve_existing("app").expect("resolve");

        let outcome = remove_tree(&root, &target, false, 100);

        assert_eq!(outcome.removed, 4);
        assert!(outcome.failures.is_empty());
        assert!(!dir.path().join("app").exists(), "트리가 사라져야 한다");
    }

    /// 세는 것은 싸고 나르는 것은 비싸다 — 개수는 정확하고 목록만 잘린다.
    #[test]
    fn the_listing_truncates_but_the_count_does_not() {
        let (_dir, root) = tree(&["app/a.txt", "app/b.txt", "app/c.txt"]);
        let target = root.resolve_existing("app").expect("resolve");

        let outcome = remove_tree(&root, &target, true, 2);

        assert_eq!(outcome.removed, 4, "app 자신 + 파일 3개");
        assert_eq!(outcome.entries.len(), 2);
        assert!(outcome.truncated);
    }

    /// 링크를 따라가면 트리 밖을 지운다.
    #[cfg(unix)]
    #[test]
    fn a_symlink_is_removed_without_touching_its_target() {
        let (dir, root) = tree(&["app/a.txt"]);
        let outside = tempfile::tempdir().expect("outside");
        let target_file = outside.path().join("keep.txt");
        std::fs::write(&target_file, b"keep").expect("write");
        std::os::unix::fs::symlink(&target_file, dir.path().join("app/link")).expect("symlink");

        let target = root.resolve_existing("app").expect("resolve");
        let outcome = remove_tree(&root, &target, false, 100);

        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(!dir.path().join("app").exists());
        assert!(target_file.exists(), "링크의 대상은 남아 있어야 한다");
    }
}
