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

    /// 테스트에서 심볼릭 링크를 만든다. Windows 일부 계정/CI 러너에 없는 권한
    /// (`SeCreateSymbolicLinkPrivilege`)을 관용한다. `tests/fs_api.rs`와
    /// `src/fs/root.rs`의 test 모듈에 있는 같은 이름의 헬퍼를 그대로 본뜬 것
    /// — 테스트 모듈 경계를 넘는 공유보다 이 리포의 기존 방식(중복)에 맞춘다.
    fn try_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            Err(std::io::Error::other(
                "symlinks unsupported on this platform",
            ))
        }
    }

    /// `try_symlink`와 같되 대상이 디렉터리일 때. Windows는 파일 심링크와
    /// 디렉터리 심링크를 생성 시점에 구분한다(`symlink_file` vs
    /// `symlink_dir`); Unix는 구분하지 않는다.
    fn try_symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(target, link)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            Err(std::io::Error::other(
                "symlinks unsupported on this platform",
            ))
        }
    }

    /// 링크를 따라가면 트리 밖을 지운다.
    #[test]
    fn a_symlink_is_removed_without_touching_its_target() {
        let (dir, root) = tree(&["app/a.txt"]);
        let outside = tempfile::tempdir().expect("outside");
        let target_file = outside.path().join("keep.txt");
        std::fs::write(&target_file, b"keep").expect("write");
        if try_symlink(&target_file, &dir.path().join("app/link")).is_err() {
            return; // symlink privilege unavailable on this runner; skip
        }

        let target = root.resolve_existing("app").expect("resolve");
        let outcome = remove_tree(&root, &target, false, 100);

        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(!dir.path().join("app").exists());
        assert!(target_file.exists(), "링크의 대상은 남아 있어야 한다");
    }

    /// 위 파일-심링크 테스트는 이 성질을 전혀 검증하지 않는다: 링크가 파일을
    /// 가리키면 `unlink`은 링크 자체만 끊으므로, `symlink_metadata`를
    /// `metadata`로 바꿔 링크를 따라가게 만들어도 `is_dir()`은 여전히
    /// false이고 결과는 똑같이 통과한다. 위험은 **디렉터리** 심링크다 — 따라
    /// 들어가면 `is_dir()`이 참이 되어 `read_dir`이 대상 디렉터리 안으로
    /// 내려가 그 내용물을 지운다. Windows도 예외가 아니다: 디렉터리 reparse
    /// point도 `metadata`로 보면 디렉터리로 보이므로 같은 메커니즘이 재현된다.
    #[test]
    fn a_directory_symlink_is_removed_without_descending_into_its_target() {
        let (dir, root) = tree(&["app/a.txt"]);
        let outside = tempfile::tempdir().expect("outside");
        let keep_dir = outside.path().join("keep_dir");
        std::fs::create_dir(&keep_dir).expect("mkdir keep_dir");
        let precious = keep_dir.join("precious.txt");
        std::fs::write(&precious, b"precious").expect("write");
        if try_symlink_dir(&keep_dir, &dir.path().join("app/dlink")).is_err() {
            return; // symlink privilege unavailable on this runner; skip
        }

        let target = root.resolve_existing("app").expect("resolve");

        // 미리보기도 링크를 하나의 항목으로만 센다 — 대상 안으로 내려가면
        // 개수가 부풀어 호출자가 "얼마나 큰 일인가"를 오판하게 된다.
        let preview = remove_tree(&root, &target, true, 100);
        assert_eq!(
            preview.removed, 3,
            "app + a.txt + dlink, keep_dir 내용물은 세지 않는다"
        );
        assert!(preview.failures.is_empty(), "{:?}", preview.failures);
        assert!(precious.exists(), "미리보기는 아무것도 지우지 않는다");

        let outcome = remove_tree(&root, &target, false, 100);
        assert_eq!(outcome.removed, 3);
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(!dir.path().join("app").exists(), "트리가 사라져야 한다");
        assert!(keep_dir.exists(), "링크의 대상 디렉터리는 남아 있어야 한다");
        assert!(
            precious.exists(),
            "대상 디렉터리 안의 파일도 남아 있어야 한다"
        );
    }
}
