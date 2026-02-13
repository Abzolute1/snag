use std::collections::HashSet;
use std::time::Instant;

/// Transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Pending,
    Downloading,
    Uploading,
    Complete,
    Failed,
}

/// Information about an active transfer
#[derive(Debug, Clone)]
pub struct TransferInfo {
    pub file_name: String,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub progress: f64,
    pub speed_bytes_per_sec: u64,
    pub eta_seconds: Option<u64>,
    pub status: TransferStatus,
    pub peer_name: Option<String>,
}

/// Track transfer progress with speed and ETA calculation
struct TransferTracker {
    file_name: String,
    total_bytes: u64,
    transferred_bytes: u64,
    status: TransferStatus,
    peer_name: Option<String>,
    started_at: Instant,
    last_update: Instant,
    speed_samples: Vec<(Instant, u64)>,
}

impl TransferTracker {
    fn info(&self) -> TransferInfo {
        let progress = if self.total_bytes > 0 {
            self.transferred_bytes as f64 / self.total_bytes as f64
        } else {
            0.0
        };

        let speed = self.calculate_speed();
        let eta = if speed > 0 && self.total_bytes > self.transferred_bytes {
            Some((self.total_bytes - self.transferred_bytes) / speed)
        } else {
            None
        };

        TransferInfo {
            file_name: self.file_name.clone(),
            total_bytes: self.total_bytes,
            transferred_bytes: self.transferred_bytes,
            progress,
            speed_bytes_per_sec: speed,
            eta_seconds: eta,
            status: self.status,
            peer_name: self.peer_name.clone(),
        }
    }

    fn calculate_speed(&self) -> u64 {
        if self.speed_samples.len() < 2 {
            return 0;
        }

        let window = std::time::Duration::from_secs(3);
        let now = Instant::now();
        let cutoff = now - window;

        let recent: Vec<_> = self
            .speed_samples
            .iter()
            .filter(|(t, _)| *t > cutoff)
            .collect();

        if recent.len() < 2 {
            return 0;
        }

        let first = recent.first().unwrap();
        let last = recent.last().unwrap();
        let bytes_delta = last.1 - first.1;
        let time_delta = last.0.duration_since(first.0);

        if time_delta.is_zero() {
            return 0;
        }

        (bytes_delta as f64 / time_delta.as_secs_f64()) as u64
    }
}

/// Composite key: (peer_name, file_name) for unique transfer tracking.
/// Downloads use peer_name="" since the receiver doesn't track per-peer.
type TransferKey = (String, String);

fn make_key(peer_name: Option<&str>, file_name: &str) -> TransferKey {
    (peer_name.unwrap_or("").to_string(), file_name.to_string())
}

/// Manages all active transfers
pub struct TransferManager {
    transfers: Vec<TransferTracker>,
    pub pending_requests: Vec<String>,
    /// Set of (peer_name, file_name) that have been marked complete.
    /// Used by mark_transfer_complete() to return true only once.
    completed_set: HashSet<TransferKey>,
}

impl TransferManager {
    pub fn new() -> Self {
        Self {
            transfers: Vec::new(),
            pending_requests: Vec::new(),
            completed_set: HashSet::new(),
        }
    }

    /// Start tracking a download
    pub fn start_download(&mut self, file_name: String, total_bytes: u64) {
        self.pending_requests.push(file_name.clone());

        let now = Instant::now();
        self.transfers.push(TransferTracker {
            file_name,
            total_bytes,
            transferred_bytes: 0,
            status: TransferStatus::Downloading,
            peer_name: None,
            started_at: now,
            last_update: now,
            speed_samples: vec![(now, 0)],
        });
    }

    /// Start tracking an upload to a specific peer.
    /// Uses composite (peer_name, file_name) key so two peers downloading
    /// the same file get separate progress trackers.
    pub fn start_upload(&mut self, file_name: String, total_bytes: u64, peer_name: String) {
        let now = Instant::now();
        self.transfers.push(TransferTracker {
            file_name,
            total_bytes,
            transferred_bytes: 0,
            status: TransferStatus::Uploading,
            peer_name: Some(peer_name),
            started_at: now,
            last_update: now,
            speed_samples: vec![(now, 0)],
        });
    }

    /// Update progress when a chunk is received
    pub fn update_chunk_received(
        &mut self,
        file_name: &str,
        _chunk_index: u64,
        _total_chunks: u64,
        chunk_bytes: u64,
    ) {
        if let Some(tracker) = self.transfers.iter_mut().find(|t| t.file_name == file_name) {
            tracker.transferred_bytes += chunk_bytes;
            let now = Instant::now();
            tracker.last_update = now;
            tracker.speed_samples.push((now, tracker.transferred_bytes));

            // Keep only recent samples (last 30 seconds)
            let cutoff = now - std::time::Duration::from_secs(30);
            tracker.speed_samples.retain(|(t, _)| *t > cutoff);
        }
    }

    /// Update progress when a chunk is sent to a specific peer.
    /// Matches on both peer_name AND file_name to avoid collisions.
    pub fn update_chunk_sent(&mut self, peer_name: &str, file_name: &str, chunk_bytes: u64) {
        if let Some(tracker) = self.transfers.iter_mut().find(|t| {
            t.file_name == file_name
                && t.peer_name.as_deref() == Some(peer_name)
                && matches!(t.status, TransferStatus::Uploading)
        }) {
            tracker.transferred_bytes += chunk_bytes;
            let now = Instant::now();
            tracker.last_update = now;
            tracker.speed_samples.push((now, tracker.transferred_bytes));

            let cutoff = now - std::time::Duration::from_secs(30);
            tracker.speed_samples.retain(|(t, _)| *t > cutoff);
        }
    }

    /// Mark a transfer as complete (for downloads — no peer_name)
    pub fn mark_complete(&mut self, file_name: &str) {
        if let Some(tracker) = self.transfers.iter_mut().find(|t| t.file_name == file_name) {
            tracker.status = TransferStatus::Complete;
            tracker.transferred_bytes = tracker.total_bytes;
        }
    }

    /// Mark an upload to a specific peer as complete.
    pub fn mark_upload_complete(&mut self, peer_name: &str, file_name: &str) {
        if let Some(tracker) = self
            .transfers
            .iter_mut()
            .find(|t| t.file_name == file_name && t.peer_name.as_deref() == Some(peer_name))
        {
            tracker.status = TransferStatus::Complete;
            tracker.transferred_bytes = tracker.total_bytes;
        }
    }

    /// Mark a transfer as complete and return true only once per (peer, file).
    /// Used by the listener to correctly count completed downloads.
    pub fn mark_transfer_complete(&mut self, peer_name: &str, file_name: &str) -> bool {
        let key = make_key(Some(peer_name), file_name);
        self.mark_upload_complete(peer_name, file_name);
        self.completed_set.insert(key)
    }

    /// Mark a transfer as failed
    pub fn mark_failed(&mut self, file_name: &str) {
        if let Some(tracker) = self.transfers.iter_mut().find(|t| t.file_name == file_name) {
            tracker.status = TransferStatus::Failed;
        }
    }

    /// Get all transfer info for display
    pub fn get_all_transfers(&self) -> Vec<TransferInfo> {
        self.transfers.iter().map(|t| t.info()).collect()
    }

    /// Get transfers for a specific peer
    pub fn get_peer_transfers(&self, peer_name: &str) -> Vec<TransferInfo> {
        self.transfers
            .iter()
            .filter(|t| t.peer_name.as_deref() == Some(peer_name))
            .map(|t| t.info())
            .collect()
    }

    /// Check if all tracked downloads have finished (complete or failed)
    pub fn all_downloads_done(&self) -> bool {
        let downloads: Vec<_> = self
            .transfers
            .iter()
            .filter(|t| {
                matches!(
                    t.status,
                    TransferStatus::Downloading | TransferStatus::Complete | TransferStatus::Failed
                )
            })
            .collect();
        !downloads.is_empty()
            && downloads
                .iter()
                .all(|t| matches!(t.status, TransferStatus::Complete | TransferStatus::Failed))
    }

    /// Periodic tick to update speed calculations
    pub fn tick(&mut self) {
        // Speed is calculated on-demand, nothing to do here
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composite_key_tracking() {
        let mut mgr = TransferManager::new();

        // Two peers upload the same file
        mgr.start_upload("report.pdf".into(), 1000, "alice".into());
        mgr.start_upload("report.pdf".into(), 1000, "bob".into());

        // Update alice's progress
        mgr.update_chunk_sent("alice", "report.pdf", 500);
        // Update bob's progress
        mgr.update_chunk_sent("bob", "report.pdf", 300);

        let alice_transfers = mgr.get_peer_transfers("alice");
        assert_eq!(alice_transfers.len(), 1);
        assert_eq!(alice_transfers[0].transferred_bytes, 500);

        let bob_transfers = mgr.get_peer_transfers("bob");
        assert_eq!(bob_transfers.len(), 1);
        assert_eq!(bob_transfers[0].transferred_bytes, 300);
    }

    #[test]
    fn test_mark_transfer_complete_returns_true_once() {
        let mut mgr = TransferManager::new();
        mgr.start_upload("file.txt".into(), 100, "peer1".into());

        assert!(mgr.mark_transfer_complete("peer1", "file.txt"));
        assert!(!mgr.mark_transfer_complete("peer1", "file.txt"));

        // Different peer, same file — should return true
        mgr.start_upload("file.txt".into(), 100, "peer2".into());
        assert!(mgr.mark_transfer_complete("peer2", "file.txt"));
    }

    #[test]
    fn test_download_tracking_unchanged() {
        let mut mgr = TransferManager::new();
        mgr.start_download("data.bin".into(), 2000);
        mgr.update_chunk_received("data.bin", 0, 8, 256);

        let transfers = mgr.get_all_transfers();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].transferred_bytes, 256);

        mgr.mark_complete("data.bin");
        let transfers = mgr.get_all_transfers();
        assert_eq!(transfers[0].status, TransferStatus::Complete);
    }
}
