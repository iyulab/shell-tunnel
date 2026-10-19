//! Staging a release: download, verify, extract, trial-run.
//!
//! Everything here is a refusal unless it is proven otherwise. The binary this
//! produces later replaces a running device's executable, so a checksum that
//! does not match, a publisher that is not ours, or a binary that does not
//! answer `--version` with the expected version stops the update outright.
//!
//! [`stage`] is blocking: `self_update`'s HTTP client is a blocking one, and
//! creating it inside a tokio runtime panics. Call it from a dedicated
//! `std::thread`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use self_update::{ArchiveKind, Compression, Download, Extract, TempDir};
use sha2::{Digest, Sha256};

/// Where releases are downloaded from unless a debug build overrides it.
pub const DEFAULT_BASE_URL: &str = "https://github.com/iyulab/shell-tunnel/releases/download";

/// A verified binary, waiting next to the executable it will replace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// The version the binary reported in its trial run.
    pub version: String,
    /// `shell-tunnel.staged[.exe]`, in the executable's directory.
    pub binary: PathBuf,
}

/// Why a release could not be staged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    /// The release, or its `SHA256SUMS`, answered `404`: not published yet.
    NotYetReleased,
    /// The transfer, the archive, or the filesystem failed.
    Download(String),
    /// The archive does not match the hash `SHA256SUMS` lists for it, or is
    /// not listed at all.
    Checksum,
    /// The binary is not signed by the expected publisher (Windows).
    Signature(String),
    /// The binary did not answer `--version` with the expected version.
    TrialRun(String),
}

/// The release base URL: [`DEFAULT_BASE_URL`], or in a debug build the value
/// of `SHELL_TUNNEL_UPDATE_BASE_URL` when set.
pub fn base_url() -> String {
    #[cfg(debug_assertions)]
    if let Ok(url) = std::env::var("SHELL_TUNNEL_UPDATE_BASE_URL") {
        return url;
    }
    DEFAULT_BASE_URL.to_string()
}

/// How long a staged binary has to answer `--version`.
const TRIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// The file name a staged binary waits under, next to the executable.
#[cfg(windows)]
pub const STAGED_NAME: &str = "shell-tunnel.staged.exe";
#[cfg(not(windows))]
pub const STAGED_NAME: &str = "shell-tunnel.staged";

/// Find the SHA-256 that `SHA256SUMS` lists for `asset`.
///
/// The format is GNU `sha256sum`'s: 64 hex digits, a space, then either a
/// space (text mode) or `*` (binary mode), then the name. Names match whole.
pub fn parse_sha256sums(text: &str, asset: &str) -> Option<[u8; 32]> {
    text.lines().find_map(|line| {
        let line = line.trim_end_matches('\r');
        let (hash, rest) = line.split_once(' ')?;
        let name = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*'))?;
        if name != asset || hash.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hash.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(out)
    })
}

/// Download, verify and trial-run release `version`, leaving it staged next
/// to `exe`. Blocking.
pub fn stage(version: &str, exe: &Path, base_url: &str) -> Result<Staged, StageError> {
    #[cfg(debug_assertions)]
    let check_publisher = std::env::var_os("SHELL_TUNNEL_UPDATE_SKIP_AUTHENTICODE").is_none();
    #[cfg(not(debug_assertions))]
    let check_publisher = true;
    stage_with(version, exe, base_url, check_publisher)
}

fn stage_with(
    version: &str,
    exe: &Path,
    base_url: &str,
    check_publisher: bool,
) -> Result<Staged, StageError> {
    // The version comes from the relay and is spliced into a URL.
    if !is_release_number(version) {
        return Err(StageError::Download(format!(
            "{version:?} is not a release number"
        )));
    }
    let target = super::release_target()
        .ok_or_else(|| StageError::Download("no release is published for this platform".into()))?;
    let (asset, kind) = if cfg!(windows) {
        (format!("shell-tunnel-{target}.zip"), ArchiveKind::Zip)
    } else {
        (
            format!("shell-tunnel-{target}.tar.gz"),
            ArchiveKind::Tar(Some(Compression::Gz)),
        )
    };
    let dir = exe
        .parent()
        .ok_or_else(|| StageError::Download("the executable has no directory".into()))?;
    let release = format!("{}/v{version}", base_url.trim_end_matches('/'));

    let mut sums = Vec::new();
    download(&format!("{release}/SHA256SUMS"), &mut sums)?;
    let expected =
        parse_sha256sums(&String::from_utf8_lossy(&sums), &asset).ok_or(StageError::Checksum)?;

    // Everything below lives in a directory removed on every exit path, so a
    // refusal leaves nothing next to the executable.
    let work = TempDir::new_in(dir).map_err(io_error)?;
    let archive_path = work.path().join(&asset);
    let mut archive = std::fs::File::create(&archive_path).map_err(io_error)?;
    download(&format!("{release}/{asset}"), &mut archive)?;
    drop(archive);

    let bytes = std::fs::read(&archive_path).map_err(io_error)?;
    if Sha256::digest(&bytes).as_slice() != expected {
        return Err(StageError::Checksum);
    }

    Extract::from_source(&archive_path)
        .archive(kind)
        .extract_file(work.path(), super::BIN_NAME)
        .map_err(|e| StageError::Download(format!("extracting {asset}: {e}")))?;
    let extracted = work.path().join(super::BIN_NAME);

    #[cfg(windows)]
    if check_publisher {
        super::authenticode::verify_publisher(&extracted).map_err(StageError::Signature)?;
    }
    #[cfg(not(windows))]
    let _ = check_publisher;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&extracted, std::fs::Permissions::from_mode(0o755))
            .map_err(io_error)?;
    }

    trial_run(&extracted, version)?;

    let binary = dir.join(STAGED_NAME);
    let _ = std::fs::remove_file(&binary);
    std::fs::rename(&extracted, &binary).map_err(io_error)?;
    Ok(Staged {
        version: version.to_string(),
        binary,
    })
}

/// Run `binary --version` and require exit 0 with the line
/// `shell-tunnel <version>`, within [`TRIAL_TIMEOUT`].
pub(crate) fn trial_run(binary: &Path, version: &str) -> Result<(), StageError> {
    let mut child = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| StageError::TrialRun(format!("could not start: {e}")))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < TRIAL_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(StageError::TrialRun(format!(
                    "no answer within {}s",
                    TRIAL_TIMEOUT.as_secs()
                )));
            }
            Err(e) => return Err(StageError::TrialRun(e.to_string())),
        }
    };
    // `--version` prints one short line, well inside a pipe buffer, so the
    // child has exited without blocking on it and the bytes are all there.
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    if !status.success() {
        return Err(StageError::TrialRun(format!(
            "--version exited with {status}"
        )));
    }
    let wanted = format!("shell-tunnel {version}");
    if out.lines().any(|l| l.trim() == wanted) {
        Ok(())
    } else {
        Err(StageError::TrialRun(format!(
            "--version answered {:?}, not {wanted:?}",
            out.trim()
        )))
    }
}

/// `MAJOR.MINOR.PATCH`, digits only.
fn is_release_number(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Fetch `url` into `dest`. A `404` is a release not (fully) published yet.
fn download(url: &str, dest: impl Write) -> Result<(), StageError> {
    let mut d = Download::from_url(url);
    d.show_progress(false);
    d.download_to(dest).map_err(|e| {
        let msg = e.to_string();
        // `self_update` reports an unsuccessful status only as text, as
        // "... failed with status: 404 ..."; a_missing_release_is_not_yet_not_a_failure
        // pins that reading.
        if msg.contains("status: 404") {
            StageError::NotYetReleased
        } else {
            StageError::Download(format!("{url}: {msg}"))
        }
    })
}

fn io_error(e: std::io::Error) -> StageError {
    StageError::Download(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use sha2::{Digest, Sha256};

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn asset() -> String {
        format!(
            "shell-tunnel-{}.{}",
            crate::update::release_target().expect("a published platform"),
            if cfg!(windows) { "zip" } else { "tar.gz" }
        )
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Serves `files` (paths under `/download/`) from its own runtime thread;
    /// everything else is `404`. Returns the base URL. `stage()` must not run
    /// inside a runtime, so the server cannot share one with the caller.
    fn serve(files: HashMap<String, Vec<u8>>) -> String {
        use axum::extract::State;
        use axum::http::{StatusCode, Uri};
        use axum::response::IntoResponse;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let files = Arc::new(files);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let app = axum::Router::new()
                    .fallback(
                        |State(files): State<Arc<HashMap<String, Vec<u8>>>>, uri: Uri| async move {
                            match files.get(uri.path()) {
                                Some(body) => body.clone().into_response(),
                                None => StatusCode::NOT_FOUND.into_response(),
                            }
                        },
                    )
                    .with_state(files);
                axum::serve(listener, app).await.unwrap();
            });
        });
        format!("http://127.0.0.1:{port}/download")
    }

    /// A directory holding a stand-in for the running executable.
    fn exe_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(super::super::BIN_NAME);
        std::fs::write(&exe, b"the running binary").unwrap();
        (dir, exe)
    }

    /// Everything in `dir` other than the stand-in executable.
    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != super::super::BIN_NAME)
            .collect()
    }

    #[test]
    fn parse_sha256sums_finds_the_asset_and_ignores_others() {
        let wanted = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let text = format!(
            "{HASH_A}  shell-tunnel-linux-x64.tar.gz\n\
             {wanted}  shell-tunnel-windows-x64.zip\r\n\
             not a line at all\n\
             {HASH_A}  shell-tunnel-windows-x64.zip.sig\n"
        );
        let found = parse_sha256sums(&text, "shell-tunnel-windows-x64.zip").unwrap();
        assert_eq!(hex(&found), wanted);

        // The binary-mode marker `sha256sum -b` writes.
        let star = format!("{wanted} *shell-tunnel-macos-arm64.tar.gz\n");
        let found = parse_sha256sums(&star, "shell-tunnel-macos-arm64.tar.gz").unwrap();
        assert_eq!(hex(&found), wanted);

        // A name is matched whole, never as a prefix or suffix.
        assert_eq!(parse_sha256sums(&text, "shell-tunnel-windows-x64"), None);
        assert_eq!(parse_sha256sums(&text, "windows-x64.zip"), None);
        assert_eq!(
            parse_sha256sums(&text, "shell-tunnel-macos-x64.tar.gz"),
            None
        );
        // A hash that is not 64 hex digits is not a hash.
        let short = "abc  shell-tunnel-linux-x64.tar.gz\n";
        assert_eq!(
            parse_sha256sums(short, "shell-tunnel-linux-x64.tar.gz"),
            None
        );
        let bad = format!("{}  x\n", "g".repeat(64));
        assert_eq!(parse_sha256sums(&bad, "x"), None);
    }

    #[test]
    fn a_checksum_mismatch_is_refused() {
        let archive = b"bytes that are not what SHA256SUMS describes".to_vec();
        let sums = format!("{HASH_A}  {}\n", asset());
        let base = serve(HashMap::from([
            (format!("/download/v9.9.9/{}", asset()), archive),
            ("/download/v9.9.9/SHA256SUMS".to_string(), sums.into_bytes()),
        ]));
        let (dir, exe) = exe_dir();

        assert_eq!(stage("9.9.9", &exe, &base), Err(StageError::Checksum));
        assert_eq!(leftovers(dir.path()), Vec::<String>::new());
    }

    #[test]
    fn an_asset_missing_from_sha256sums_is_refused() {
        // A published release whose SUMS does not list this platform is broken,
        // not pending: it must not read as "not released yet".
        let archive = b"anything".to_vec();
        let sums = format!(
            "{}  shell-tunnel-other.zip\n",
            hex(&Sha256::digest(&archive))
        );
        let base = serve(HashMap::from([
            (format!("/download/v9.9.9/{}", asset()), archive),
            ("/download/v9.9.9/SHA256SUMS".to_string(), sums.into_bytes()),
        ]));
        let (dir, exe) = exe_dir();

        assert_eq!(stage("9.9.9", &exe, &base), Err(StageError::Checksum));
        assert_eq!(leftovers(dir.path()), Vec::<String>::new());
    }

    #[test]
    fn a_missing_release_is_not_yet_not_a_failure() {
        // Nothing published at all.
        let base = serve(HashMap::new());
        let (dir, exe) = exe_dir();
        assert_eq!(stage("9.9.9", &exe, &base), Err(StageError::NotYetReleased));

        // SUMS is up but the archive is not (a release still uploading).
        let base = serve(HashMap::from([(
            "/download/v9.9.9/SHA256SUMS".to_string(),
            format!("{HASH_A}  {}\n", asset()).into_bytes(),
        )]));
        assert_eq!(stage("9.9.9", &exe, &base), Err(StageError::NotYetReleased));
        assert_eq!(leftovers(dir.path()), Vec::<String>::new());
    }

    #[test]
    fn a_version_that_is_not_a_release_number_is_refused_before_any_request() {
        // The version comes from the relay. It is spliced into a URL, so it must
        // be a plain release number and nothing that could walk the path.
        let base = serve(HashMap::new());
        let (_dir, exe) = exe_dir();
        for bad in ["../../evil", "1.2", "1.2.3-rc.1", "1.2.3/x", ""] {
            match stage(bad, &exe, &base) {
                Err(StageError::Download(_)) => {}
                other => panic!("{bad:?} was not refused: {other:?}"),
            }
        }
    }

    #[test]
    fn a_binary_that_does_not_report_the_version_fails_the_trial() {
        // Exits 0 and prints a version line, but not `shell-tunnel <version>`.
        // `env!("CARGO")` is the cargo running this build: always present.
        let cargo = Path::new(env!("CARGO"));
        let out = std::process::Command::new(cargo)
            .arg("--version")
            .output()
            .unwrap();
        assert!(out.status.success());
        let cargo_version = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string();
        match trial_run(cargo, &cargo_version) {
            Err(StageError::TrialRun(_)) => {}
            other => panic!("cargo passed as shell-tunnel {cargo_version}: {other:?}"),
        }

        // Exits non-zero: the test harness rejects `--version`.
        let me = std::env::current_exe().unwrap();
        match trial_run(&me, "9.9.9") {
            Err(StageError::TrialRun(_)) => {}
            other => panic!("the test harness passed the trial: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_reports_the_version_passes_the_trial() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake");
        std::fs::write(&script, "#!/bin/sh\necho 'shell-tunnel 9.9.9'\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(trial_run(&script, "9.9.9"), Ok(()));
        match trial_run(&script, "9.9.10") {
            Err(StageError::TrialRun(_)) => {}
            other => panic!("9.9.9 passed as 9.9.10: {other:?}"),
        }
    }

    /// Packs `binary` as this platform's release archive, under the name a
    /// release uses, with the system `tar` (bsdtar on Windows writes `.zip`).
    fn pack(binary: &Path) -> Vec<u8> {
        let work = tempfile::tempdir().unwrap();
        std::fs::copy(binary, work.path().join(super::super::BIN_NAME)).unwrap();
        let out = work.path().join(asset());
        let tar = if cfg!(windows) {
            PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32\\tar.exe")
        } else {
            PathBuf::from("tar")
        };
        let mut cmd = std::process::Command::new(tar);
        if cfg!(windows) {
            cmd.arg("-a").arg("-cf");
        } else {
            cmd.arg("-czf");
        }
        let status = cmd
            .arg(&out)
            .arg("-C")
            .arg(work.path())
            .arg(super::super::BIN_NAME)
            .status()
            .unwrap();
        assert!(status.success(), "tar could not build the test archive");
        std::fs::read(out).unwrap()
    }

    #[test]
    fn a_staged_binary_that_fails_the_trial_leaves_nothing_behind() {
        // The whole pipeline up to the trial: the archive matches its SUMS line
        // and extracts, but what is inside is not shell-tunnel 9.9.9.
        let archive = pack(Path::new(env!("CARGO")));
        let sums = format!("{}  {}\n", hex(&Sha256::digest(&archive)), asset());
        let base = serve(HashMap::from([
            (format!("/download/v9.9.9/{}", asset()), archive),
            ("/download/v9.9.9/SHA256SUMS".to_string(), sums.into_bytes()),
        ]));
        let (dir, exe) = exe_dir();

        match stage_with("9.9.9", &exe, &base, false) {
            Err(StageError::TrialRun(_)) => {}
            other => panic!("expected a trial failure: {other:?}"),
        }
        assert_eq!(leftovers(dir.path()), Vec::<String>::new());
    }

    #[cfg(windows)]
    #[test]
    fn an_unsigned_binary_is_refused() {
        // The test harness itself carries no signature.
        let me = std::env::current_exe().unwrap();
        assert!(super::super::authenticode::verify_publisher(&me).is_err());

        // And through the pipeline: a matching archive of an unsigned binary
        // stops at the publisher check, before anything is run.
        let archive = pack(&me);
        let sums = format!("{}  {}\n", hex(&Sha256::digest(&archive)), asset());
        let base = serve(HashMap::from([
            (format!("/download/v9.9.9/{}", asset()), archive),
            ("/download/v9.9.9/SHA256SUMS".to_string(), sums.into_bytes()),
        ]));
        let (dir, exe) = exe_dir();
        match stage_with("9.9.9", &exe, &base, true) {
            Err(StageError::Signature(_)) => {}
            other => panic!("an unsigned binary was not refused: {other:?}"),
        }
        assert_eq!(leftovers(dir.path()), Vec::<String>::new());
    }

    #[cfg(windows)]
    #[test]
    fn the_shipped_signed_release_passes_the_publisher_check() {
        // A signed release binary kept on the development machine. Absent
        // anywhere else (CI included), where this test checks nothing and says so.
        let shipped = Path::new(r"D:\lib\shell-tunnel.exe");
        if !shipped.exists() {
            eprintln!("skipped: no signed release binary at {}", shipped.display());
            return;
        }
        assert_eq!(
            super::super::authenticode::verify_publisher(shipped),
            Ok(())
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_signed_release_is_staged_next_to_the_executable() {
        // The whole pipeline succeeding, publisher check included, on a real
        // signed release binary. Skipped where that binary is absent.
        let shipped = Path::new(r"D:\lib\shell-tunnel.exe");
        if !shipped.exists() {
            eprintln!("skipped: no signed release binary at {}", shipped.display());
            return;
        }
        let out = std::process::Command::new(shipped)
            .arg("--version")
            .output()
            .unwrap();
        let version = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string();
        let archive = pack(shipped);
        let sums = format!("{}  {}\n", hex(&Sha256::digest(&archive)), asset());
        let base = serve(HashMap::from([
            (format!("/download/v{version}/{}", asset()), archive),
            (
                format!("/download/v{version}/SHA256SUMS"),
                sums.into_bytes(),
            ),
        ]));
        let (dir, exe) = exe_dir();

        let staged = stage_with(&version, &exe, &base, true).unwrap();
        assert_eq!(staged.version, version);
        assert_eq!(staged.binary, dir.path().join(STAGED_NAME));
        assert_eq!(leftovers(dir.path()), vec![STAGED_NAME.to_string()]);
        assert_eq!(
            std::fs::read(&staged.binary).unwrap(),
            std::fs::read(shipped).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_release_workflow_refuses_the_publisher_devices_refuse() {
        // A release signed by anyone else would publish and then be refused by
        // every following device; release.yml checks the same name first.
        let workflow = include_str!("../../.github/workflows/release.yml");
        let check = format!(
            "$publisher -ne '{}'",
            super::super::authenticode::EXPECTED_PUBLISHER
        );
        assert_eq!(
            workflow.matches(&check).count(),
            1,
            "release.yml lacks {check:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_validly_signed_binary_from_another_publisher_is_refused() {
        // Proves the publisher comparison discriminates, not only WinVerifyTrust:
        // Git for Windows is validly signed, by someone else. Skipped where absent.
        let other = Path::new(r"C:\Program Files\Git\cmd\git.exe");
        if !other.exists() {
            eprintln!("skipped: no {}", other.display());
            return;
        }
        let err = super::super::authenticode::verify_publisher(other).unwrap_err();
        assert!(
            err.starts_with("signed by"),
            "refused for the wrong reason: {err}"
        );
    }
}
