use anyhow::{bail, Context, Result};
use std::cmp::Ordering;
use std::process::Command;

const REPO: &str = "Abzolute1/snag";
const API_URL: &str = "https://api.github.com/repos/Abzolute1/snag/releases/latest";

/// Entry point for `snag update`.
pub async fn run_update(check_only: bool, force: bool) -> Result<()> {
    if cfg!(windows) {
        println!("Self-update is not supported on Windows.");
        println!(
            "Download the latest release from: https://github.com/{}/releases",
            REPO
        );
        return Ok(());
    }

    let current = env!("CARGO_PKG_VERSION");
    println!("Current version: v{}", current);

    let latest = fetch_latest_version().context("Failed to check for updates")?;
    let ord = compare_versions(&latest, current);

    match ord {
        Ordering::Greater => {
            println!("New version available: v{}", latest);
        }
        Ordering::Equal => {
            println!("Already up to date (v{})", current);
            if !force {
                return Ok(());
            }
            println!("--force specified, reinstalling...");
        }
        Ordering::Less => {
            println!(
                "Local version (v{}) is newer than latest release (v{})",
                current, latest
            );
            if !force {
                return Ok(());
            }
            println!("--force specified, reinstalling...");
        }
    }

    if check_only {
        return Ok(());
    }

    let (os, arch) = detect_platform()?;
    download_and_replace(&latest, os, arch)?;

    println!("Updated to v{}", latest);
    Ok(())
}

/// Fetch the latest release version tag from GitHub.
fn fetch_latest_version() -> Result<String> {
    let output = Command::new("curl")
        .args(["-fsSL", API_URL])
        .output()
        .context("Failed to run curl — is it installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("403") {
            bail!("GitHub API rate limit exceeded. Try again in a few minutes.");
        } else if stderr.contains("404") {
            bail!("No releases found. The project may not have published a release yet.");
        }
        bail!("Failed to fetch release info: {}", stderr.trim());
    }

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse GitHub API response")?;

    let tag = body["tag_name"]
        .as_str()
        .context("No tag_name in release response")?;

    // Strip leading 'v' if present
    let version = tag.strip_prefix('v').unwrap_or(tag);
    Ok(version.to_string())
}

/// Simple numeric semver comparison (major.minor.patch).
fn compare_versions(a: &str, b: &str) -> Ordering {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let va = parse(a);
    let vb = parse(b);
    for i in 0..3 {
        let a_part = va.get(i).copied().unwrap_or(0);
        let b_part = vb.get(i).copied().unwrap_or(0);
        match a_part.cmp(&b_part) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// Detect OS and architecture at compile time.
fn detect_platform() -> Result<(&'static str, &'static str)> {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        bail!("Unsupported OS for self-update")
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        bail!("Unsupported architecture for self-update")
    };

    Ok((os, arch))
}

/// Download the release binary, verify it, and swap it into place.
fn download_and_replace(version: &str, os: &str, arch: &str) -> Result<()> {
    let (asset, binary_name) = if os == "windows" {
        (
            format!("snag-{}-{}.exe.zip", os, arch),
            "snag.exe".to_string(),
        )
    } else {
        (format!("snag-{}-{}.tar.gz", os, arch), "snag".to_string())
    };
    let url = format!(
        "https://github.com/{}/releases/download/v{}/{}",
        REPO, version, asset
    );

    // Find our own binary path
    let current_exe = std::env::current_exe().context("Cannot determine path to running binary")?;
    let install_dir = current_exe
        .parent()
        .context("Cannot determine install directory")?;

    // Create temp dir in the same parent (same filesystem for atomic rename)
    let tmp_dir = tempfile::tempdir_in(install_dir).or_else(|_| {
        // Fall back to system temp if same-dir fails (e.g. no write permission yet)
        tempfile::tempdir()
    })?;
    let tmp_path = tmp_dir.path();
    let archive_path = tmp_path.join(&asset);
    let new_binary = tmp_path.join(&binary_name);

    // Download
    println!("Downloading v{}...", version);
    let dl_status = Command::new("curl")
        .args(["-fSL", "-o", archive_path.to_str().unwrap(), &url])
        .status()
        .context("Failed to run curl")?;

    if !dl_status.success() {
        bail!(
            "Download failed. No binary available for {}-{}.\nCheck https://github.com/{}/releases",
            os,
            arch,
            REPO
        );
    }

    // Extract
    if os == "windows" {
        // Use PowerShell to extract zip on Windows
        let ps_status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    archive_path.display(),
                    tmp_path.display()
                ),
            ])
            .status()
            .context("Failed to run PowerShell for extraction")?;

        if !ps_status.success() {
            bail!("Failed to extract archive. The download may be corrupted — try again.");
        }
    } else {
        let tar_status = Command::new("tar")
            .args([
                "-xzf",
                archive_path.to_str().unwrap(),
                "-C",
                tmp_path.to_str().unwrap(),
            ])
            .status()
            .context("Failed to run tar")?;

        if !tar_status.success() {
            bail!("Failed to extract archive. The download may be corrupted — try again.");
        }
    }

    if !new_binary.exists() {
        bail!("Expected '{}' binary not found in archive", binary_name);
    }

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_binary, std::fs::Permissions::from_mode(0o755))?;
    }

    // Verify the new binary runs
    let verify = Command::new(&new_binary)
        .arg("--version")
        .output()
        .context("New binary failed to execute — it may be for a different platform")?;

    if !verify.status.success() {
        bail!("New binary exited with error during verification");
    }

    let version_output = String::from_utf8_lossy(&verify.stdout);
    println!("Verified: {}", version_output.trim());

    // Atomic swap: rename old -> .old, new -> in place
    let backup_path = current_exe.with_extension("old");

    // Check write permission
    if let Err(e) = std::fs::metadata(install_dir).and_then(|m| {
        if m.permissions().readonly() {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "read-only",
            ))
        } else {
            Ok(())
        }
    }) {
        drop(e);
        bail!(
            "No write permission to {}. Try: sudo snag update",
            install_dir.display()
        );
    }

    // Try the rename swap
    if let Err(e) = std::fs::rename(&current_exe, &backup_path) {
        // On some systems, renaming a running binary fails. Try copy instead.
        if std::fs::copy(&new_binary, &current_exe).is_err() {
            bail!("Failed to replace binary ({}). Try: sudo snag update", e);
        }
    } else {
        // Rename new binary into place
        if let Err(e) = std::fs::rename(&new_binary, &current_exe) {
            // Rollback
            let _ = std::fs::rename(&backup_path, &current_exe);
            bail!(
                "Failed to install new binary: {}. Rolled back to previous version.",
                e
            );
        }
        // Clean up backup
        let _ = std::fs::remove_file(&backup_path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.1.0", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.1.0"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("0.1.0", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.2.0", "0.1.0"), Ordering::Greater);
        assert_eq!(compare_versions("0.1.1", "0.1.0"), Ordering::Greater);
    }

    #[test]
    fn test_detect_platform() {
        let result = detect_platform();
        assert!(result.is_ok());
        let (os, arch) = result.unwrap();
        assert!(os == "linux" || os == "macos" || os == "windows");
        assert!(arch == "x86_64" || arch == "aarch64");
    }
}
