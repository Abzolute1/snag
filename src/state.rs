use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const APP_DIR: &str = "snag";
const STATE_FILE: &str = "state.json";

/// A persisted shared file entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedFile {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    /// True when the path doesn't exist on disk (e.g. unmounted drive).
    /// The file stays in the list but is excluded from catalogs.
    #[serde(default)]
    pub missing: bool,
}

/// A transfer history entryy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub file_name: String,
    pub direction: TransferDirection,
    pub peer: String,
    pub timestamp: String,
    pub bytes: u64,
    pub status: TransferResult,
    /// Original path on disk, used for re-adding files from history
    #[serde(default)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferResult {
    Complete,
    Failed,
    Cancelled,
}

/// Persisted app state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedState {
    pub shared_files: Vec<SavedFile>,
    pub history: Vec<HistoryEntry>,
    /// Custom path for the state file (used in tests for isolation).
    /// When `None`, the default XDG / HOME path is used.
    #[serde(skip)]
    pub custom_path: Option<PathBuf>,
}

impl PersistedState {
    /// Load state from disk, or return default if none exists
    pub fn load() -> Self {
        let path = state_file_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(state) => state,
                Err(e) => {
                    tracing::warn!("Failed to parse state file, starting fresh: {}", e);
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Load state using a custom path (for test isolation)
    pub fn load_from(path: PathBuf) -> Self {
        let mut state = match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(state) => state,
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse state file {:?}, starting fresh: {}",
                        path,
                        e
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        };
        state.custom_path = Some(path);
        state
    }

    /// Save state to disk
    pub fn save(&self) -> Result<()> {
        let path = self.custom_path.clone().unwrap_or_else(state_file_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Add a file to the shared list (deduplicates by path)
    pub fn add_file(&mut self, path: &Path) {
        // Don't add duplicates
        if self.shared_files.iter().any(|f| f.path == path) {
            return;
        }

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());

        let is_dir = path.is_dir();
        let size = if is_dir {
            dir_size(path)
        } else {
            path.metadata().map(|m| m.len()).unwrap_or(0)
        };

        self.shared_files.push(SavedFile {
            path: path.to_path_buf(),
            name,
            size,
            is_dir,
            missing: false,
        });
    }

    /// Remove a file by index
    pub fn remove_file(&mut self, index: usize) -> Option<SavedFile> {
        if index < self.shared_files.len() {
            Some(self.shared_files.remove(index))
        } else {
            None
        }
    }

    /// Add a history entry, keeping at most `limit` entries.
    pub fn add_history(&mut self, entry: HistoryEntry, limit: usize) {
        self.history.insert(0, entry);
        self.history.truncate(limit);
    }

    /// Mark files whose paths no longer exist as missing, and clear
    /// the flag for paths that have reappeared (e.g. drive remounted).
    pub fn refresh_missing(&mut self) {
        for f in &mut self.shared_files {
            f.missing = !f.path.exists();
        }
    }
}

fn state_file_path() -> PathBuf {
    // Windows: use LOCALAPPDATA (typically C:\Users\X\AppData\Local)
    #[cfg(target_os = "windows")]
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join(APP_DIR).join(STATE_FILE);
    }

    // Unix: XDG_DATA_HOME or ~/.local/share
    let data_dir = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate::config::home_dir().join(".local").join("share"));
    data_dir.join(APP_DIR).join(STATE_FILE)
}

/// Maximum directory recursion depth to prevent stack overflow from symlink
/// loops or extremely deep directory trees.
const MAX_DIR_DEPTH: u32 = 64;

/// Recursively calculate directory size with bounded depth and symlink skipping.
fn dir_size(path: &Path) -> u64 {
    dir_size_bounded(path, 0)
}

fn dir_size_bounded(path: &Path, depth: u32) -> u64 {
    if depth >= MAX_DIR_DEPTH {
        return 0;
    }
    let mut size = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            // Use symlink_metadata to detect symlinks without following them.
            let metadata = match p.symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                size += dir_size_bounded(&p, depth + 1);
            } else {
                size += metadata.len();
            }
        }
    }
    size
}
