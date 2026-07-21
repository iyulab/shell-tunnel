//! Auto-update functionality.
//!
//! Checks for updates from GitHub Releases and self-updates the binary.

use std::time::Duration;

use self_update::backends::github::{ReleaseList, Update};
use self_update::cargo_crate_version;

use crate::Result;

/// GitHub repository owner.
const REPO_OWNER: &str = "iyulab";

/// GitHub repository name.
const REPO_NAME: &str = "shell-tunnel";

/// Binary name for the current platform.
#[cfg(windows)]
const BIN_NAME: &str = "shell-tunnel.exe";

#[cfg(not(windows))]
const BIN_NAME: &str = "shell-tunnel";

/// Platform token used in release asset names.
///
/// The release workflow publishes `shell-tunnel-<platform>.<ext>`, and
/// `self_update` locates an asset by substring-matching whatever `target` it is
/// given. Left to its default it looks for the compile-time triple
/// (`x86_64-pc-windows-msvc`), which no asset has ever contained — so every
/// update failed with "No asset found for target". The naming has to be handed
/// to it explicitly, and [`tests::release_targets_match_the_published_assets`]
/// keeps this table and the workflow from drifting apart.
fn release_target() -> Option<&'static str> {
    Some(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "windows-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "x86_64") => "macos-x64",
        ("macos", "aarch64") => "macos-arm64",
        _ => return None,
    })
}

/// Update check result.
#[derive(Debug)]
pub struct UpdateInfo {
    /// Current version.
    pub current: String,
    /// Latest available version.
    pub latest: String,
    /// Whether an update is available.
    pub update_available: bool,
}

/// Check for available updates without applying.
pub fn check_update() -> Result<UpdateInfo> {
    let current = cargo_crate_version!().to_string();

    let releases = ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()
        .map_err(|e| crate::ShellTunnelError::Update(e.to_string()))?
        .fetch()
        .map_err(|e| crate::ShellTunnelError::Update(e.to_string()))?;

    let latest = releases
        .first()
        .map(|r| r.version.clone())
        .unwrap_or_else(|| current.clone());

    let update_available = is_newer_version(&current, &latest);

    Ok(UpdateInfo {
        current,
        latest,
        update_available,
    })
}

/// Perform self-update if a newer version is available.
///
/// Returns `Ok(true)` if updated, `Ok(false)` if already up to date.
pub fn self_update() -> Result<bool> {
    let target = release_target().ok_or_else(|| {
        crate::ShellTunnelError::Update(format!(
            "no release binary is published for {}-{}; build from source instead",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    })?;

    let status = Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .target(target)
        .current_version(cargo_crate_version!())
        .show_download_progress(true)
        .no_confirm(true)
        .build()
        .map_err(|e| crate::ShellTunnelError::Update(e.to_string()))?
        .update()
        .map_err(|e| crate::ShellTunnelError::Update(e.to_string()))?;

    Ok(status.updated())
}

/// Perform silent self-update in background.
///
/// This is non-blocking and logs the result.
pub fn background_update_check() {
    std::thread::spawn(|| {
        // Small delay to let the server start
        std::thread::sleep(Duration::from_secs(2));

        match check_update() {
            Ok(info) => {
                if info.update_available {
                    tracing::info!(
                        "Update available: {} -> {} (run with --update to install)",
                        info.current,
                        info.latest
                    );
                } else {
                    tracing::debug!("Already running latest version: {}", info.current);
                }
            }
            Err(e) => {
                tracing::debug!("Update check failed: {}", e);
            }
        }
    });
}

/// Compare semantic versions.
fn is_newer_version(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> (u32, u32, u32) {
        let v = v.trim_start_matches('v');
        let parts: Vec<&str> = v.split('.').collect();
        let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        (major, minor, patch)
    };

    let (cm, cn, cp) = parse(current);
    let (lm, ln, lp) = parse(latest);

    (lm, ln, lp) > (cm, cn, cp)
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_platform_maps_to_a_published_asset() {
        // Every platform the project builds for must resolve; a `None` here on a
        // supported platform is the bug that broke `--update`.
        let target = release_target();
        if matches!(
            (std::env::consts::OS, std::env::consts::ARCH),
            ("windows", "x86_64")
                | ("linux", "x86_64")
                | ("linux", "aarch64")
                | ("macos", "x86_64")
                | ("macos", "aarch64")
        ) {
            assert!(target.is_some(), "no asset naming for this platform");
        }
    }

    #[test]
    fn release_targets_match_the_published_assets() {
        // Ties the table above to what the workflow actually uploads. Renaming an
        // archive without updating the table would silently break `--update` for
        // that platform, which is exactly how it broke the first time.
        let workflow = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/.github/workflows/release.yml"
        ))
        .expect("release workflow should be readable");

        for platform in [
            "windows-x64",
            "linux-x64",
            "linux-arm64",
            "macos-x64",
            "macos-arm64",
        ] {
            assert!(
                workflow.contains(&format!("shell-tunnel-{platform}.")),
                "the release workflow publishes no asset named shell-tunnel-{platform}.*"
            );
        }
    }

    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("0.1.0", "0.2.0"));
        assert!(is_newer_version("0.1.0", "1.0.0"));
        assert!(is_newer_version("0.1.0", "0.1.1"));
        assert!(!is_newer_version("0.2.0", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(is_newer_version("v0.1.0", "v0.2.0"));
    }
}
