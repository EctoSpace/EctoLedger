// Async wrappers for blocking crypto operations.
//
// Sync crypto (SHA-256, Merkle tree building) can block the async executor
// during heavy load. This module spawns CPU-bound work on Tokio's blocking
// thread pool via `tokio::task::spawn_blocking`, ensuring the async runtime
// stays responsive and available for I/O.
//
// All wrappers are async and can be safely called from the tokio runtime.

use ectoledger_core::hash;
use ectoledger_core::merkle::{self, MerkleProof};

/// Error type for blocking task failures.
#[derive(Debug, thiserror::Error)]
pub enum BlockingTaskError {
    /// The spawned blocking task panicked or was cancelled.
    #[error("blocking task panicked: {0}")]
    TaskPanicked(String),
    /// The underlying crypto/merkle operation failed.
    #[error("{0}")]
    Inner(String),
}

/// Async wrapper for SHA-256 hashing.
///
/// Offloads `sha256_hex()` to the blocking thread pool.
/// Returns an error instead of panicking if the blocking task fails.
pub async fn sha256_hex_async(input: Vec<u8>) -> Result<String, BlockingTaskError> {
    tokio::task::spawn_blocking(move || hash::sha256_hex(&input))
        .await
        .map_err(|e| {
            tracing::error!("sha256_hex_async: blocking task failed: {e}");
            BlockingTaskError::TaskPanicked(format!("sha256_hex_async: {e}"))
        })
}

/// Async wrapper for SHA-256 pair hashing (combines two inputs).
///
/// Offloads `sha256_pair()` to the blocking thread pool.
pub async fn sha256_pair_async(a: Vec<u8>, b: Vec<u8>) -> Result<String, BlockingTaskError> {
    tokio::task::spawn_blocking(move || hash::sha256_pair(&a, &b))
        .await
        .map_err(|e| {
            tracing::error!("sha256_pair_async: blocking task failed: {e}");
            BlockingTaskError::TaskPanicked(format!("sha256_pair_async: {e}"))
        })
}

/// Async wrapper for content hash computation.
///
/// Used in the hot path: every event in the ledger loop.
/// Offloads to blocking thread pool to keep executor responsive.
pub async fn compute_content_hash_async(
    previous_hash: String,
    sequence: i64,
    payload_json: String,
    session_id: Option<String>,
) -> Result<String, BlockingTaskError> {
    tokio::task::spawn_blocking(move || {
        hash::compute_content_hash(
            &previous_hash,
            sequence,
            &payload_json,
            session_id.as_deref(),
            None,
        )
    })
    .await
    .map_err(|e| {
        tracing::error!("compute_content_hash_async: blocking task failed: {e}");
        BlockingTaskError::TaskPanicked(format!("compute_content_hash_async: {e}"))
    })
}

/// Async wrapper for Merkle tree building.
///
/// Can take several seconds for large event logs (10k+ events).
/// Must be spawned on the blocking thread pool.
/// Returns the fully-built MerkleTree.
pub async fn build_merkle_tree_async(
    hashes: Vec<String>,
) -> Result<merkle::MerkleTree, merkle::MerkleError> {
    tokio::task::spawn_blocking(move || {
        let hash_refs: Vec<&str> = hashes.iter().map(|s| s.as_str()).collect();
        merkle::build_merkle_tree(&hash_refs)
    })
    .await
    .unwrap_or_else(|_| {
        Err(merkle::MerkleError::InvalidHex(
            "blocking task panicked".to_string(),
        ))
    })
}

/// Async wrapper for Merkle tree root extraction.
///
/// Extracts the root hash from a fully-built MerkleTree.
pub async fn merkle_root_async(tree: merkle::MerkleTree) -> Result<String, BlockingTaskError> {
    tokio::task::spawn_blocking(move || {
        merkle::root(&tree)
            .map_err(|e| BlockingTaskError::Inner(format!("merkle root extraction failed: {e}")))
    })
    .await
    .map_err(|e| {
        tracing::error!("merkle_root_async: blocking task failed: {e}");
        BlockingTaskError::TaskPanicked(format!("merkle_root_async: {e}"))
    })?
}

/// Async wrapper for Merkle proof verification.
///
/// Verifies a leaf hash against a root using the proof path.
pub async fn verify_merkle_proof_async(
    root_hex: String,
    leaf_hash: String,
    proof: MerkleProof,
) -> Result<bool, merkle::MerkleError> {
    tokio::task::spawn_blocking(move || merkle::verify_proof(&root_hex, &leaf_hash, &proof))
        .await
        .unwrap_or_else(|_| {
            Err(merkle::MerkleError::InvalidHex(
                "blocking task panicked".to_string(),
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sha256_async() {
        let result = sha256_hex_async(b"test".to_vec())
            .await
            .expect("sha256 failed");
        // sha256("test") = 9f86d081...
        assert!(result.len() == 64);
        assert_eq!(
            result,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[tokio::test]
    async fn test_sha256_pair_async() {
        let a = b"hello".to_vec();
        let b = b"world".to_vec();
        let result = sha256_pair_async(a, b).await.expect("sha256_pair failed");
        assert!(result.len() == 64);
    }

    #[tokio::test]
    async fn test_compute_content_hash_async() {
        let genesis_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let result = compute_content_hash_async(genesis_hash, 0, r#"{"test":1}"#.to_string(), None)
            .await
            .expect("content hash failed");
        assert!(result.len() == 64);
    }

    #[tokio::test]
    async fn test_merkle_tree_async() {
        let hashes = vec![
            "aaa".to_string(),
            "bbb".to_string(),
            "ccc".to_string(),
            "ddd".to_string(),
        ];
        let tree = build_merkle_tree_async(hashes).await.expect("merkle build");

        let root = merkle_root_async(tree).await.expect("merkle root failed");
        assert_eq!(root.len(), 64);
    }
}
