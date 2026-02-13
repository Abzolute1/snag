use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// User-facing configuration, persisted as TOML.
/// Separate from runtime state — this holds preferences, not session data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub notifications: NotificationConfig,
    pub appearance: AppearanceConfig,
    pub transfers: TransferConfig,
    pub network: NetworkConfig,
    pub identity: IdentityConfig,
    pub privacy: PrivacyConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationConfig {
    /// Audible terminal bell on transfer completion
    pub bell: bool,
    /// Desktop notification via notify-send
    pub desktop: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppearanceConfig {
    /// Color theme: "orange" or "white"
    pub theme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransferConfig {
    /// Default download directory (~ is expanded)
    pub download_dir: String,
    /// What to do when a file already exists: "skip", "rename", "overwrite"
    pub overwrite: String,
    /// Use zstd compression for chunks
    pub compression: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Listening port (0 = random)
    pub port: u16,
    /// Bind address
    pub bind_address: String,
    /// STUN servers for NAT traversal (host:port format).
    /// Used to discover your public IP. Set to empty list to disable.
    pub stun_servers: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Display name shown to peers (empty = hostname)
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyConfig {
    /// Record transfer history
    pub history: bool,
    /// Max history entries to keep
    pub history_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Number of words in share codes (3-5)
    pub code_words: u8,
}

// -- Defaults --

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            bell: true,
            desktop: true,
        }
    }
}

impl Default for AppearanceConfig {
    fn default() -> Self {
        Self {
            theme: "orange".into(),
        }
    }
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            download_dir: "~/Downloads".into(),
            overwrite: "rename".into(),
            compression: true,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: 0,
            bind_address: "0.0.0.0".into(),
            stun_servers: vec![
                "stun.l.google.com:19302".into(),
                "stun1.l.google.com:19302".into(),
                "stun2.l.google.com:19302".into(),
            ],
        }
    }
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            history: true,
            history_limit: 50,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { code_words: 3 }
    }
}

// -- Paths --

/// Cross-platform home directory detection.
/// Checks HOME (Unix), USERPROFILE (Windows), then falls back to temp dir.
pub fn home_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home);
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        return PathBuf::from(profile);
    }
    // Last resort: temp directory so we never hard-fail
    std::env::temp_dir()
}

fn config_dir() -> PathBuf {
    // Windows: use APPDATA (typically C:\Users\X\AppData\Roaming)
    #[cfg(target_os = "windows")]
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata).join("snag");
    }

    // Unix: XDG_CONFIG_HOME or ~/.config
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join(".config"));
    base.join("snag")
}

fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Expand `~` prefix to home directory (cross-platform).
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        home_dir().join(rest)
    } else if path == "~" {
        home_dir()
    } else {
        PathBuf::from(path)
    }
}

impl Config {
    /// Load config from disk, falling back to defaults for missing fields.
    pub fn load() -> Self {
        let path = config_path();
        Self::load_from(&path)
    }

    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::warn!("Bad config at {}: {}", path.display(), e);
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Save config, creating parent dirs as needed.
    pub fn save(&self) -> Result<()> {
        let path = config_path();
        self.save_to(&path)
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Resolved download directory (tilde expanded, absolute).
    pub fn download_dir(&self) -> PathBuf {
        expand_tilde(&self.transfers.download_dir)
    }

    /// Generate a default config file with comments.
    pub fn dump_default() -> String {
        r#"# Snag configuration
# Place this file at ~/.config/snag/config.toml

[notifications]
bell = true
desktop = true

[appearance]
# "orange" or "white"
theme = "orange"

[transfers]
# Default download directory (~ expands to $HOME)
download_dir = "~/Downloads"
# What to do when a file exists: "skip", "rename", "overwrite"
overwrite = "rename"
compression = true

[network]
# Listening port (0 = random available port)
port = 0
bind_address = "0.0.0.0"
# STUN servers for public IP discovery. Empty list disables STUN.
stun_servers = ["stun.l.google.com:19302", "stun1.l.google.com:19302", "stun2.l.google.com:19302"]

[identity]
# Name shown to peers (empty = auto-detect hostname)
display_name = ""

[privacy]
history = true
history_limit = 50

[security]
# Words in share codes (3-5). More words = harder to guess.
code_words = 3
"#
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_roundtrip() {
        let cfg = Config::default();
        let serialized = toml::to_string_pretty(&cfg).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.notifications.bell, true);
        assert_eq!(deserialized.appearance.theme, "orange");
        assert_eq!(deserialized.transfers.download_dir, "~/Downloads");
        assert_eq!(deserialized.security.code_words, 3);
    }

    #[test]
    fn test_partial_config() {
        let partial = r#"
[notifications]
bell = false
"#;
        let cfg: Config = toml::from_str(partial).unwrap();
        assert_eq!(cfg.notifications.bell, false);
        // Everything else should be defaults
        assert_eq!(cfg.notifications.desktop, true);
        assert_eq!(cfg.appearance.theme, "orange");
        assert_eq!(cfg.transfers.compression, true);
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/Downloads");
        assert!(!expanded.to_string_lossy().starts_with('~'));
    }
}
