//! 디렉터리 트리를 세거나 제거한다.
//!
//! 미리보기(`dry_run`)와 실행이 **같은 순회를 통과**한다. 갈라두면 미리보기가
//! 거짓말을 하게 되고, 그 거짓말은 지운 뒤에야 드러난다.

use std::path::Path;

use crate::fs::{platform, FsRoot};

/// 한 번의 트리 연산 결과.
///
/// `removed`/`bytes`는 **`failures`가 비어 있을 때만** 정확하다. 비어 있지
/// 않으면 두 방향으로 어긋난다: 열거나 stat에 실패한 항목은 이름도 크기도
/// 몰라 아예 세지 못했으므로 `removed`/`bytes`는 하한이고, 제거에 실패한
/// 항목은 세어진 뒤에 실패했으므로 `removed`는 "지워진 개수"가 아니라
/// "세어서 시도한 개수"다. 어느 쪽이든 `failures`가 비어 있는지부터 봐야
/// 한다.
///
/// `entries`는 `limit`까지만 담고 넘치면 `truncated`가 선다 — 릴레이 본문
/// 상한이 8 MiB이고, 이 응답의 목적은 "얼마나 큰 일인가"를 알리는 것이지
/// 목록을 완전히 나르는 것이 아니다.
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
                // `entries`를 그대로 넘긴다. `.flatten()`을 끼우면 `Err`이
                // 여기서 사라져 `visit_entry`의 `Err` 갈래가 영영 안 불린다
                // — 그래도 테스트는 전부 통과하므로(확인함) 이 한 줄은
                // 리뷰로만 지켜진다.
                for entry in entries {
                    visit_entry(root, path, entry, dry_run, limit, out);
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

/// 열거가 내놓은 항목 하나를 처리한다.
///
/// `read_dir`의 이터레이터는 `io::Result<DirEntry>`를 낸다. 이 갈래가 별도
/// 함수인 것은 `Err`을 버리지 않는다는 결정을 테스트가 직접 붙잡을 수 있게
/// 하기 위해서다 — 이터레이터가 `Err`을 내도록 플랫폼 독립적으로 유도할
/// 방법이 없다.
///
/// 예전에는 `.flatten()`으로 받아 `Err`을 말없이 버렸다. 그러면 그 항목이
/// `removed`에도 `failures`에도 남지 않는다. 실제 삭제에서는 나중에 부모의
/// `remove_dir`이 "비어 있지 않음"으로 실패해 결국 드러나지만, `dry_run`에는
/// 그 안전망이 없어 미리보기가 `failures`를 비운 채 개수를 틀리게 답했다.
fn visit_entry(
    root: &FsRoot,
    parent: &Path,
    entry: std::io::Result<std::fs::DirEntry>,
    dry_run: bool,
    limit: usize,
    out: &mut TreeOutcome,
) {
    match entry {
        Ok(entry) => visit(root, &entry.path(), dry_run, limit, out),
        // `entries`에도 `removed`에도 넣지 않는다 — 이름도 크기도 모르는 것을
        // 셀 수는 없다. 위 `symlink_metadata` 실패 경로와 같은 처리다.
        Err(_) => out.failures.push(unreadable_entry_name(root, parent)),
    }
}

/// 열거에 실패해 경로조차 모르는 항목의 이름. 아는 것은 어느 디렉터리 안에
/// 있었는가뿐이므로 부모 이름에 매단다.
///
/// 부모 **자신**의 실패는 `name_of`가 낸 이름 그대로 들어가므로 두 사유가
/// 같은 문자열로 섞이지 않는다. `<`/`>`는 Windows 파일명에 쓸 수 없고
/// Unix에서도 드물어 진짜 경로로 오해되지 않는다.
///
/// 한 디렉터리에서 N개가 실패하면 같은 문자열이 N번 들어간다. 그 개수가
/// 정보이므로 의도된 것이다 — 나중에 중복 제거로 "고치지" 말 것.
fn unreadable_entry_name(root: &FsRoot, parent: &Path) -> String {
    let parent_name = name_of(root, parent);
    if parent_name.is_empty() {
        // 부모가 jail 루트 자신이면 `relative`는 빈 문자열을 준다. 그대로
        // 이으면 `/<unreadable entry>`가 되어 절대경로처럼 보인다.
        //
        // jailed scope에서만 생기는 일이다. machine-wide에서는 `relative`가
        // 절대경로를 그대로 주고, scope 밖이면 `name_of`가 원시 표기로
        // 떨어지므로 어느 쪽이든 비지 않는다 — 이 갈래에 오지 않는다.
        "<unreadable entry>".to_string()
    } else {
        format!("{parent_name}/<unreadable entry>")
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

    /// 열거 중 실패한 엔트리는 조용히 사라지지 않는다.
    ///
    /// `read_dir` 이터레이터가 `Err`을 내도록 플랫폼 독립적으로 유도할 방법이
    /// 없어(`readdir`/`FindNextFileW`의 중간 실패는 임의로 만들 수 없다),
    /// 이터레이터가 실제로 내놓는 것과 **같은 타입**을 `visit_entry`에 직접
    /// 건넨다. 결정 로직은 진짜 프로덕션 코드다. 다만 `Err`을 여기까지 실어
    /// 나르는 `visit` 쪽 배선 한 줄은 이 테스트가 덮지 못한다 — 보고서에
    /// 그대로 적었다.
    #[test]
    fn an_entry_that_fails_to_enumerate_lands_in_failures() {
        let (_dir, root) = tree(&["app/a.txt"]);
        let parent = root.resolve_existing("app").expect("resolve");
        let mut out = TreeOutcome::default();

        visit_entry(
            &root,
            &parent,
            Err(std::io::Error::other("enumeration failed")),
            true,
            100,
            &mut out,
        );

        assert_eq!(out.failures, vec!["app/<unreadable entry>".to_string()]);
        // 세지 않는 것이 맞다: 이름도 크기도 모르는 것을 세면 미리보기가
        // 반대 방향으로 거짓말한다. 호출자는 `failures`를 보고 판단한다.
        assert_eq!(out.removed, 0);
        assert_eq!(out.bytes, 0);
        assert!(out.entries.is_empty());
    }

    /// 부모가 jail 루트 자신이면 `relative`가 빈 문자열을 주므로, 그대로 이으면
    /// `/<unreadable entry>`가 되어 절대경로처럼 읽힌다.
    #[test]
    fn an_unreadable_entry_at_the_root_is_not_named_with_a_leading_slash() {
        let (_dir, root) = tree(&["app/a.txt"]);
        let jail = root.jail_path().expect("이 픽스처는 jailed root를 만든다");
        let mut out = TreeOutcome::default();

        visit_entry(
            &root,
            jail,
            Err(std::io::Error::other("enumeration failed")),
            true,
            100,
            &mut out,
        );

        assert_eq!(out.failures, vec!["<unreadable entry>".to_string()]);
    }

    /// 링크 생성 결과를 "계속" 또는 "중단"으로 바꾸되, **어느 쪽이든 보이게**
    /// 한다. 표시 없는 early return은 "테스트가 돌아서 통과한 것"과 구별되지
    /// 않는다 — 조용히 공허하게 통과하는 바로 그 모양이다.
    ///
    /// Unix에는 평범한 사용자의 심링크 생성을 막는 Windows의
    /// `SeCreateSymbolicLinkPrivilege` 같은 관문이 없으므로, 거기서의 실패는
    /// 권한 부재가 아니라 실제로 뭔가 깨졌다는 뜻에 가깝다 — 조용한 skip이
    /// 아니라 하드 실패로 다루고, 진단 가능하도록 `io::Error`를 패닉 메시지에
    /// 함께 싣는다. Windows는 비권한·비개발자모드 계정에 흔히 거부하므로 그
    /// 플랫폼만 명시적으로 표시된 skip을 받는다.
    fn require_symlink(created: std::io::Result<()>, test_name: &str) -> bool {
        match created {
            Ok(()) => true,
            #[cfg(windows)]
            Err(e) => {
                eprintln!("SKIPPED {test_name}: symlink creation failed: {e}");
                false
            }
            #[cfg(not(windows))]
            Err(e) => {
                panic!("{test_name}: symlink creation failed unexpectedly on a non-Windows platform: {e}");
            }
        }
    }

    /// 링크를 따라가면 트리 밖을 지운다.
    #[test]
    fn a_symlink_is_removed_without_touching_its_target() {
        let (dir, root) = tree(&["app/a.txt"]);
        let outside = tempfile::tempdir().expect("outside");
        let target_file = outside.path().join("keep.txt");
        std::fs::write(&target_file, b"keep").expect("write");
        // 심링크 생성 권한이 없는 러너에서는 여기서 멈춘다 — skip은 표준
        // 에러로 표시되므로 통과와 구별된다.
        if !require_symlink(
            try_symlink(&target_file, &dir.path().join("app/link")),
            "a_symlink_is_removed_without_touching_its_target",
        ) {
            return;
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
        // 심링크 생성 권한이 없는 러너에서는 여기서 멈춘다 — skip은 표준
        // 에러로 표시되므로 통과와 구별된다.
        if !require_symlink(
            try_symlink_dir(&keep_dir, &dir.path().join("app/dlink")),
            "a_directory_symlink_is_removed_without_descending_into_its_target",
        ) {
            return;
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
