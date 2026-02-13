use anyhow::Result;
use std::io::Read;
use std::path::Path;

/// Chunk size: 256 KB. File data is encrypted with ChaCha20-Poly1305 directly
/// (bypassing Noise's 65535-byte message limit). Control messages still use Noise.
pub const CHUNK_SIZE: usize = 256 * 1024;

/// A chunk of file data with its hash
pub struct Chunk {
    pub index: u64,
    pub data: Vec<u8>,
    pub blake3_hash: Vec<u8>,
}

/// Read a file and yield chunks
pub struct FileChunker {
    reader: std::io::BufReader<std::fs::File>,
    chunk_index: u64,
    total_chunks: u64,
    file_size: u64,
}

impl FileChunker {
    pub fn new(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let file_size = file.metadata()?.len();
        let total_chunks = file_size.div_ceil(CHUNK_SIZE as u64);
        let reader = std::io::BufReader::with_capacity(CHUNK_SIZE, file);

        Ok(Self {
            reader,
            chunk_index: 0,
            total_chunks,
            file_size,
        })
    }

    pub fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Read the next chunk, returning None when done
    pub fn next_chunk(&mut self) -> Result<Option<Chunk>> {
        let mut buf = vec![0u8; CHUNK_SIZE];
        let n = self.reader.read(&mut buf)?;

        if n == 0 {
            return Ok(None);
        }

        buf.truncate(n);
        let hash = crate::crypto::verify::hash_chunk(&buf);

        let chunk = Chunk {
            index: self.chunk_index,
            data: buf,
            blake3_hash: hash,
        };

        self.chunk_index += 1;
        Ok(Some(chunk))
    }
}

/// Maximum directory recursion depth to prevent stack overflow from symlink
/// loops or extremely deep directory trees.
const MAX_DIR_DEPTH: u32 = 64;

/// Chunk a directory by collecting all files within it
pub fn collect_dir_files(dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    let mut files = Vec::new();
    collect_dir_files_recursive(dir, dir, &mut files, 0)?;
    Ok(files)
}

fn collect_dir_files_recursive(
    base: &Path,
    current: &Path,
    files: &mut Vec<(String, std::path::PathBuf)>,
    depth: u32,
) -> Result<()> {
    if depth >= MAX_DIR_DEPTH {
        return Ok(());
    }
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
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
            collect_dir_files_recursive(base, &path, files, depth + 1)?;
        } else {
            let relative = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string()
                .replace('\\', "/"); // Normalize to forward slashes for wire protocol
            files.push((relative, path));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_chunker_small_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(b"hello world").unwrap();

        let mut chunker = FileChunker::new(&file_path).unwrap();
        assert_eq!(chunker.total_chunks(), 1);

        let chunk = chunker.next_chunk().unwrap().unwrap();
        assert_eq!(chunk.index, 0);
        assert_eq!(chunk.data, b"hello world");
        assert!(!chunk.blake3_hash.is_empty());

        assert!(chunker.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_chunker_exact_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("exact.bin");
        let data = vec![0xAB; CHUNK_SIZE];
        std::fs::write(&file_path, &data).unwrap();

        let mut chunker = FileChunker::new(&file_path).unwrap();
        assert_eq!(chunker.total_chunks(), 1);

        let chunk = chunker.next_chunk().unwrap().unwrap();
        assert_eq!(chunk.data.len(), CHUNK_SIZE);
    }

    #[test]
    fn test_chunker_multi_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("big.bin");
        let data = vec![0xCD; CHUNK_SIZE * 3 + 100];
        std::fs::write(&file_path, &data).unwrap();

        let mut chunker = FileChunker::new(&file_path).unwrap();
        assert_eq!(chunker.total_chunks(), 4);

        let mut total_read = 0;
        while let Some(chunk) = chunker.next_chunk().unwrap() {
            total_read += chunk.data.len();
        }
        assert_eq!(total_read, CHUNK_SIZE * 3 + 100);
    }
}
