// Binary Merkle tree over SHA-256 content hashes.
//
// Tree construction (RFC 6962 domain separation):
//   - Leaves: sha256(0x00 || content_hash_hex_bytes)
//   - Internal nodes: sha256(0x01 || left_child_bytes || right_child_bytes)
//   - Odd number of leaves: last leaf is duplicated.
//
// The 0x00/0x01 domain-separation prefixes prevent second-preimage attacks
// where an attacker crafts an internal node that collides with a leaf hash
// (or vice versa).
//
// All hashes are stored and exposed as lowercase hex strings.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Errors that can occur during Merkle tree operations.
#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    /// A node hash string was not valid lowercase hex.
    #[error("invalid hex in Merkle node: {0:?}")]
    InvalidHex(String),
    /// The tree has no layers (was built from an empty leaf set).
    #[error("cannot generate proof on empty tree")]
    EmptyTree,
    /// The requested leaf index is beyond the number of leaves.
    #[error("leaf_idx {leaf_idx} out of range (tree has {leaf_count} leaves)")]
    IndexOutOfRange { leaf_idx: usize, leaf_count: usize },
}

/// A single sibling entry in a Merkle inclusion proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofNode {
    /// "left" or "right" — which side this sibling is on.
    pub side: String,
    /// SHA-256 hash of the sibling node as lowercase hex.
    pub hash: String,
}

/// Inclusion proof for one leaf in the tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// Zero-based index of the proven leaf.
    pub leaf_index: usize,
    /// Sibling path from leaf up to (but not including) the root.
    pub path: Vec<ProofNode>,
}

/// A fully-built binary Merkle tree stored as layers.
/// `layers[0]` = leaf layer, `layers[last]` = root (single element).
pub struct MerkleTree {
    /// Each layer is a list of hex-encoded SHA-256 hashes.
    layers: Vec<Vec<String>>,
}

/// Domain-separation prefix for Merkle leaf hashes (RFC 6962).
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for Merkle internal node hashes (RFC 6962).
const NODE_PREFIX: u8 = 0x01;

/// Hash a leaf value with domain separation: SHA-256(0x00 || data).
fn hash_leaf(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Combines two Merkle sibling hashes (both lowercase hex) into a parent hash
/// with domain separation: SHA-256(0x01 || left_bytes || right_bytes).
///
/// Returns `Err(MerkleError::InvalidHex)` if either input is not valid hex.
/// Previously this used `unwrap_or_default()`, which silently produced a hash
/// over empty bytes when given malformed input — a correctness and security bug.
fn combine(left: &str, right: &str) -> Result<String, MerkleError> {
    let l = hex::decode(left).map_err(|_| MerkleError::InvalidHex(left.to_string()))?;
    let r = hex::decode(right).map_err(|_| MerkleError::InvalidHex(right.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(&l);
    hasher.update(&r);
    Ok(hex::encode(hasher.finalize()))
}

/// Build a Merkle tree from a slice of content-hash hex strings.
/// Returns an empty tree (no root) if `hashes` is empty.
///
/// Returns `Err(MerkleError::InvalidHex)` if any internal node hash is malformed.
pub fn build_merkle_tree(hashes: &[&str]) -> Result<MerkleTree, MerkleError> {
    if hashes.is_empty() {
        return Ok(MerkleTree { layers: vec![] });
    }

    // Leaf layer: hash_leaf(content_hash_bytes) with domain-separation prefix.
    let leaves: Vec<String> = hashes.iter().map(|h| hash_leaf(h.as_bytes())).collect();

    let mut layers: Vec<Vec<String>> = vec![leaves];

    while layers.last().map_or(0, |l| l.len()) > 1 {
        let current = layers.last().unwrap();
        let mut next: Vec<String> = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            let left = &current[i];
            let right = if i + 1 < current.len() {
                &current[i + 1]
            } else {
                // Duplicate the last leaf for odd-length layers.
                left
            };
            next.push(combine(left, right)?);
            i += 2;
        }
        layers.push(next);
    }

    Ok(MerkleTree { layers })
}

/// Returns the Merkle root as a lowercase hex string.
///
/// Returns `Err(MerkleError::EmptyTree)` if the tree has no leaves,
/// consistent with `proof()` behaviour.
pub fn root(tree: &MerkleTree) -> Result<String, MerkleError> {
    tree.layers
        .last()
        .and_then(|l| l.first())
        .cloned()
        .ok_or(MerkleError::EmptyTree)
}

/// Generates an inclusion proof for the leaf at `leaf_idx`.
///
/// Returns `Err(MerkleError::EmptyTree)` if the tree has no layers, or
/// `Err(MerkleError::IndexOutOfRange)` if `leaf_idx >= leaf_count`.
pub fn proof(tree: &MerkleTree, leaf_idx: usize) -> Result<MerkleProof, MerkleError> {
    if tree.layers.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    let leaf_count = tree.layers[0].len();
    if leaf_idx >= leaf_count {
        return Err(MerkleError::IndexOutOfRange {
            leaf_idx,
            leaf_count,
        });
    }

    let mut path: Vec<ProofNode> = Vec::new();
    let mut idx = leaf_idx;

    // Walk up from the leaf layer to the root layer (exclusive — root has no sibling).
    for layer in &tree.layers[..tree.layers.len().saturating_sub(1)] {
        let sibling_idx = if idx.is_multiple_of(2) {
            // idx is left child; sibling is to the right (or duplicate of idx if it doesn't exist)
            (idx + 1).min(layer.len() - 1)
        } else {
            // idx is right child; sibling is to the left
            idx - 1
        };
        let side = if idx.is_multiple_of(2) {
            "right"
        } else {
            "left"
        };
        path.push(ProofNode {
            side: side.to_string(),
            hash: layer[sibling_idx].clone(),
        });
        idx /= 2;
    }

    Ok(MerkleProof {
        leaf_index: leaf_idx,
        path,
    })
}

/// Verifies that `leaf_content_hash` (a raw content_hash string, not yet SHA-256'd) is
/// included in the Merkle tree whose root is `root_hex`.
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if the proof is structurally
/// valid but does not match the root, and `Err(MerkleError::InvalidHex)` if any
/// proof node contains a malformed hex string (previously silently hashed empty bytes).
pub fn verify_proof(
    root_hex: &str,
    leaf_content_hash: &str,
    merkle_proof: &MerkleProof,
) -> Result<bool, MerkleError> {
    // Re-derive the leaf hash the same way the builder did (with domain separation).
    let mut current = hash_leaf(leaf_content_hash.as_bytes());

    for node in &merkle_proof.path {
        current = match node.side.as_str() {
            "left" => combine(&node.hash, &current)?,
            "right" => combine(&current, &node.hash)?,
            _ => return Ok(false),
        };
    }

    // Constant-time comparison to prevent timing side-channels (TM-4).
    let current_bytes = hex::decode(&current).map_err(|_| MerkleError::InvalidHex(current))?;
    let root_bytes =
        hex::decode(root_hex).map_err(|_| MerkleError::InvalidHex(root_hex.to_string()))?;
    Ok(current_bytes.ct_eq(&root_bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let tree = build_merkle_tree(&["abc123"]).unwrap();
        let r = root(&tree).unwrap();
        assert!(!r.is_empty());
        let p = proof(&tree, 0).unwrap();
        assert!(verify_proof(&r, "abc123", &p).unwrap());
    }

    #[test]
    fn test_even_leaves() {
        let hashes = ["a", "b", "c", "d"];
        let tree = build_merkle_tree(&hashes).unwrap();
        let r = root(&tree).unwrap();
        for (i, h) in hashes.iter().enumerate() {
            let p = proof(&tree, i).unwrap();
            assert!(
                verify_proof(&r, h, &p).unwrap(),
                "proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_odd_leaves() {
        let hashes = ["a", "b", "c"];
        let tree = build_merkle_tree(&hashes).unwrap();
        let r = root(&tree).unwrap();
        for (i, h) in hashes.iter().enumerate() {
            let p = proof(&tree, i).unwrap();
            assert!(
                verify_proof(&r, h, &p).unwrap(),
                "proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_invalid_proof() {
        let tree = build_merkle_tree(&["real_hash"]).unwrap();
        let r = root(&tree).unwrap();
        let p = proof(&tree, 0).unwrap();
        assert!(!verify_proof(&r, "wrong_hash", &p).unwrap());
    }

    #[test]
    fn test_empty_tree() {
        let tree = build_merkle_tree(&[]).unwrap();
        assert!(matches!(root(&tree), Err(MerkleError::EmptyTree)));
    }

    #[test]
    fn test_malformed_proof_node_returns_err() {
        let tree = build_merkle_tree(&["hash1", "hash2"]).unwrap();
        let r = root(&tree).unwrap();
        let mut p = proof(&tree, 0).unwrap();
        // Corrupt the proof path with an invalid hex string.
        p.path[0].hash = "not-valid-hex!!!".to_string();
        assert!(
            matches!(
                verify_proof(&r, "hash1", &p),
                Err(MerkleError::InvalidHex(_))
            ),
            "expected InvalidHex error for malformed proof node"
        );
    }
}
