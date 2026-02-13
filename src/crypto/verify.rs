use anyhow::{anyhow, Result};

/// Compute BLAKE3 hash of a data chunk
pub fn hash_chunk(data: &[u8]) -> Vec<u8> {
    blake3::hash(data).as_bytes().to_vec()
}

/// Verify a chunk against its expected BLAKE3 hash
pub fn verify_chunk(data: &[u8], expected_hash: &[u8]) -> Result<()> {
    let actual = hash_chunk(data);
    if actual != expected_hash {
        return Err(anyhow!(
            "Chunk integrity check failed: expected {}, got {}",
            hex_str(expected_hash),
            hex_str(&actual)
        ));
    }
    Ok(())
}

/// Compute BLAKE3 hash of an entire file by reading it in chunks
pub fn hash_file(path: &std::path::Path) -> Result<Vec<u8>> {
    let mut hasher = blake3::Hasher::new();
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::with_capacity(1024 * 1024, file);
    std::io::copy(&mut reader, &mut hasher)?;
    Ok(hasher.finalize().as_bytes().to_vec())
}

/// Simple hex encoding for display
fn hex_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        + "..."
}

/// Reserved for future per-file Merkle proof verification.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root: Vec<u8>,
    pub leaves: Vec<Vec<u8>>,
}

impl MerkleTree {
    /// Build a Merkle tree from chunk hashes
    pub fn from_chunk_hashes(hashes: Vec<Vec<u8>>) -> Self {
        if hashes.is_empty() {
            return Self {
                root: blake3::hash(b"empty").as_bytes().to_vec(),
                leaves: hashes,
            };
        }

        let root = compute_merkle_root(&hashes);
        Self {
            root,
            leaves: hashes,
        }
    }

    /// Verify that a chunk hash is part of this tree
    pub fn verify_leaf(&self, index: usize, hash: &[u8]) -> bool {
        if index >= self.leaves.len() {
            return false;
        }
        self.leaves[index] == hash
    }
}

fn compute_merkle_root(hashes: &[Vec<u8>]) -> Vec<u8> {
    if hashes.len() == 1 {
        return hashes[0].clone();
    }

    let mut next_level = Vec::new();
    for chunk in hashes.chunks(2) {
        if chunk.len() == 2 {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            next_level.push(hasher.finalize().as_bytes().to_vec());
        } else {
            next_level.push(chunk[0].clone());
        }
    }

    compute_merkle_root(&next_level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify_chunk() {
        let data = b"hello world";
        let hash = hash_chunk(data);
        assert!(verify_chunk(data, &hash).is_ok());
        assert!(verify_chunk(b"wrong data", &hash).is_err());
    }

    #[test]
    fn test_merkle_tree() {
        let hashes = vec![
            hash_chunk(b"chunk0"),
            hash_chunk(b"chunk1"),
            hash_chunk(b"chunk2"),
            hash_chunk(b"chunk3"),
        ];
        let tree = MerkleTree::from_chunk_hashes(hashes.clone());

        assert!(tree.verify_leaf(0, &hashes[0]));
        assert!(tree.verify_leaf(1, &hashes[1]));
        assert!(!tree.verify_leaf(0, &hashes[1])); // wrong hash
        assert!(!tree.verify_leaf(10, &hashes[0])); // out of bounds
    }
}
