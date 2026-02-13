use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A single entry in the file catalog
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub blake3_hash: Option<Vec<u8>>,
    pub children: Vec<CatalogChild>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogChild {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

/// The shared file catalog
#[derive(Debug, Clone)]
pub struct SharedCatalog {
    pub entries: Vec<CatalogEntry>,
}

impl SharedCatalog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a file or directory to the catalog
    pub fn add_path(&mut self, path: &Path) {
        // Get metadata once upfront to avoid TOCTOU races and skip symlinks.
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return, // path doesn't exist or is inaccessible
        };

        // Skip symlinks to prevent traversal attacks.
        if metadata.file_type().is_symlink() {
            return;
        }

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());

        if metadata.is_dir() {
            let children = collect_children(path);
            let size = dir_size(path, 0);
            self.entries.push(CatalogEntry {
                name,
                path: path.to_path_buf(),
                size,
                is_dir: true,
                blake3_hash: None,
                children,
            });
        } else {
            let size = metadata.len();
            self.entries.push(CatalogEntry {
                name,
                path: path.to_path_buf(),
                size,
                is_dir: false,
                blake3_hash: None,
                children: Vec::new(),
            });
        }
    }

    /// Convert to wire format
    pub fn to_wire(&self) -> crate::protocol::messages::CatalogMessage {
        crate::protocol::messages::CatalogMessage {
            entries: self
                .entries
                .iter()
                .map(|e| crate::protocol::messages::CatalogEntryWire {
                    name: e.name.clone(),
                    size: e.size,
                    is_dir: e.is_dir,
                    blake3_hash: e.blake3_hash.clone(),
                    children: e
                        .children
                        .iter()
                        .map(|c| crate::protocol::messages::CatalogChildWire {
                            name: c.name.clone(),
                            size: c.size,
                            is_dir: c.is_dir,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// Build from wire format
    pub fn from_wire(msg: &crate::protocol::messages::CatalogMessage) -> Self {
        Self {
            entries: msg
                .entries
                .iter()
                .map(|e| CatalogEntry {
                    name: e.name.clone(),
                    path: PathBuf::from(&e.name),
                    size: e.size,
                    is_dir: e.is_dir,
                    blake3_hash: e.blake3_hash.clone(),
                    children: e
                        .children
                        .iter()
                        .map(|c| CatalogChild {
                            name: c.name.clone(),
                            size: c.size,
                            is_dir: c.is_dir,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }
}

/// Collect immediate children of a directory for preview purposes.
fn collect_children(path: &Path) -> Vec<CatalogChild> {
    let mut children = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            let metadata = match p.symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let is_dir = metadata.is_dir();
            let size = if is_dir {
                dir_size(&p, 0)
            } else {
                metadata.len()
            };
            children.push(CatalogChild { name, size, is_dir });
        }
    }
    children.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    children
}

/// Maximum directory recursion depth to prevent stack overflow from symlink
/// loops or extremely deep directory trees.
const MAX_DIR_DEPTH: u32 = 64;

/// Recursively calculate directory size with bounded depth and symlink skipping.
fn dir_size(path: &Path, depth: u32) -> u64 {
    if depth >= MAX_DIR_DEPTH {
        return 0;
    }
    let mut size = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            // Use symlink_metadata to detect symlinks without following them.
            let metadata = match path.symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                size += dir_size(&path, depth + 1);
            } else {
                size += metadata.len();
            }
        }
    }
    size
}
