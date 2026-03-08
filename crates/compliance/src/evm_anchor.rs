//! Ethereum On-Chain Session Hash Anchoring  (feature: `evm`)
//!
//! Anchors a 32-byte session ledger tip hash to Ethereum-compatible chains by
//! calling a minimal on-chain `anchor(bytes32)` function via raw JSON-RPC.
//!
//! # Configuration (environment variables)
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `EVM_RPC_URL` | — | JSON-RPC endpoint (e.g. `https://mainnet.infura.io/v3/KEY`) |
//! | `EVM_CHAIN_ID` | `1` | Chain ID (1 = Ethereum mainnet, 137 = Polygon, 100 = Gnosis) |
//! | `EVM_CONTRACT_ADDRESS` | — | Address of the deployed `EctoLedgerAnchor` contract |
//! | `EVM_PRIVATE_KEY` | — | Hex-encoded 32-byte signing private key (no `0x` prefix) |
//!
//! # Minimal Solidity Contract
//!
//! Deploy this once to obtain `EVM_CONTRACT_ADDRESS`:
//!
//! ```solidity
//! // SPDX-License-Identifier: MIT
//! pragma solidity ^0.8.24;
//! contract EctoLedgerAnchor {
//!     event Anchored(bytes32 indexed sessionHash, address indexed submitter, uint256 timestamp);
//!     function anchor(bytes32 sessionHash) external {
//!         emit Anchored(sessionHash, msg.sender, block.timestamp);
//!     }
//! }
//! ```
//!
//! The emitted `Anchored` event provides an on-chain, block-timestamped record
//! that the session hash existed at (or before) the block's timestamp.
//!
//! # How it works (without `alloy` or `ethers-rs`)
//!
//! To avoid pulling in multi-MB EVM SDK dependencies, this module constructs
//! and signs the Ethereum transaction manually using the minimal set of crates
//! already in the workspace (`sha2`, `hex`, `ed25519-dalek` is unsuitable for
//! secp256k1, so we use the `k256` crate added behind the `evm` feature flag).
//! The signed raw transaction is sent via `eth_sendRawTransaction` JSON-RPC.

use serde::{Deserialize, Serialize};

#[cfg(feature = "evm")]
use {hex, reqwest::Client, serde_json::json};

/// Env var: JSON-RPC endpoint for the target EVM chain.
#[cfg(feature = "evm")]
const ENV_RPC_URL: &str = "EVM_RPC_URL";
/// Env var: EVM chain ID (e.g. 1 for mainnet, 11155111 for Sepolia testnet).
#[cfg(feature = "evm")]
const ENV_CHAIN_ID: &str = "EVM_CHAIN_ID";
/// Env var: 0x-prefixed address of the deployed `EctoLedgerAnchor` contract.
#[cfg(feature = "evm")]
const ENV_CONTRACT_ADDRESS: &str = "EVM_CONTRACT_ADDRESS";
/// Env var: hex-encoded 32-byte secp256k1 private key (no 0x prefix).
#[cfg(feature = "evm")]
const ENV_PRIVATE_KEY: &str = "EVM_PRIVATE_KEY";

/// Result of a successful on-chain anchor operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmAnchorResult {
    /// The session hash anchored (hex, 32 bytes / 64 chars).
    pub session_hash: String,
    /// Transaction hash returned by the RPC node.
    pub tx_hash: String,
    /// Chain ID that was used.
    pub chain_id: u64,
    /// RPC endpoint used.
    pub rpc_url: String,
}

/// Error type for EVM anchoring operations.
#[derive(Debug, thiserror::Error)]
pub enum EvmAnchorError {
    #[error("missing env var: {0}")]
    MissingConfig(&'static str),
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("JSON-RPC error: {0}")]
    Rpc(String),
    #[error("encoding error: {0}")]
    Encoding(String),
}

/// ABI-encodes `anchor(bytes32 sessionHash)` call data.
///
/// Function selector: Keccak-256("anchor(bytes32)")[0..4]  = 0x6b4c3b9d
/// The 32-byte argument is padded to 32 bytes (it already is).
#[cfg(feature = "evm")]
fn encode_anchor_calldata(session_hash_hex: &str) -> Result<Vec<u8>, EvmAnchorError> {
    // Selector: first 4 bytes of keccak256("anchor(bytes32)") = 0x6b4c3b9d
    let selector: [u8; 4] = [0x6b, 0x4c, 0x3b, 0x9d];

    let hash_bytes = hex::decode(session_hash_hex)
        .map_err(|e| EvmAnchorError::Encoding(format!("session hash decode: {}", e)))?;
    if hash_bytes.len() != 32 {
        return Err(EvmAnchorError::Encoding(format!(
            "session hash must be 32 bytes, got {}",
            hash_bytes.len()
        )));
    }

    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(&hash_bytes); // already 32 bytes, no padding needed
    Ok(calldata)
}

/// Validate that a string is a plausible Ethereum address (0x + 40 hex chars).
#[cfg(feature = "evm")]
fn validate_address(addr: &str) -> Result<[u8; 20], EvmAnchorError> {
    let stripped = addr.strip_prefix("0x").unwrap_or(addr);
    if stripped.len() != 40 {
        return Err(EvmAnchorError::Encoding(format!(
            "contract address must be 40 hex chars, got {}",
            stripped.len()
        )));
    }
    let bytes = hex::decode(stripped)
        .map_err(|e| EvmAnchorError::Encoding(format!("address decode: {}", e)))?;
    bytes.try_into().map_err(|_| {
        EvmAnchorError::Encoding(format!(
            "address must be exactly 20 bytes, got {}",
            stripped.len() / 2
        ))
    })
}

// ── RLP + secp256k1 signing ───────────────────────────────────────────────────
// These require the `k256` crate (added behind the `evm` feature flag).

#[cfg(feature = "evm")]
mod signing {
    use super::EvmAnchorError;
    use k256::ecdsa::{SigningKey, VerifyingKey};
    use sha3::{Digest as _, Keccak256};

    /// Parse a 32-byte hex private key into an ECDSA signing key.
    pub fn parse_signing_key(hex_key: &str) -> Result<SigningKey, EvmAnchorError> {
        let stripped = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        let key_bytes =
            hex::decode(stripped).map_err(|e| EvmAnchorError::InvalidKey(e.to_string()))?;
        SigningKey::from_bytes(key_bytes.as_slice().into())
            .map_err(|e| EvmAnchorError::InvalidKey(e.to_string()))
    }

    /// Derive the Ethereum address (`keccak256(pubkey)[12..]`) from a signing key.
    pub fn address_from_key(key: &SigningKey) -> [u8; 20] {
        let vk = VerifyingKey::from(key);
        // Uncompressed pubkey is 65 bytes: 0x04 || x || y
        let uncompressed = vk.to_encoded_point(false);
        let pubkey_bytes = &uncompressed.as_bytes()[1..]; // strip 0x04 prefix
        let hash = Keccak256::digest(pubkey_bytes);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        addr
    }

    /// RLP-encode and sign an EIP-155 legacy transaction.
    ///
    /// Returns the raw signed transaction bytes ready for `eth_sendRawTransaction`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_eip155_tx(
        nonce: u64,
        gas_price_gwei: u64,
        gas_limit: u64,
        to: &[u8; 20],
        value: u64,
        data: &[u8],
        chain_id: u64,
        key: &SigningKey,
    ) -> Vec<u8> {
        // Build the signing payload: RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
        let payload = rlp_encode_tx_for_signing(
            nonce,
            gas_price_gwei * 1_000_000_000,
            gas_limit,
            to,
            value,
            data,
            chain_id,
        );
        let hash = Keccak256::digest(&payload);

        let (sig, recovery_id) = key
            .sign_prehash_recoverable(hash.as_ref())
            .expect("signing cannot fail");

        // EIP-155 v: chainId * 2 + 35 + recovery_id
        let v = chain_id * 2 + 35 + recovery_id.to_byte() as u64;
        let r = sig.r().to_bytes();
        let s = sig.s().to_bytes();

        // Encode final signed tx: RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
        rlp_encode_signed_tx(
            nonce,
            gas_price_gwei * 1_000_000_000,
            gas_limit,
            to,
            value,
            data,
            v,
            r.as_ref(),
            s.as_ref(),
        )
    }

    // Minimal RLP encoder — implements only the subset needed for Ethereum transactions.

    fn rlp_encode_int(n: u64) -> Vec<u8> {
        if n == 0 {
            return vec![0x80]; // empty string = 0
        }
        let bytes = n.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let trimmed = &bytes[start..];
        let mut out = Vec::new();
        if trimmed.len() == 1 && trimmed[0] < 0x80 {
            out.push(trimmed[0]);
        } else {
            out.push(0x80 + trimmed.len() as u8);
            out.extend_from_slice(trimmed);
        }
        out
    }

    fn rlp_encode_bytes(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 {
            return b.to_vec();
        }
        let mut out = Vec::new();
        if b.len() < 56 {
            out.push(0x80 + b.len() as u8);
        } else {
            let len_bytes = (b.len() as u64).to_be_bytes();
            let start = len_bytes.iter().position(|&x| x != 0).unwrap_or(7);
            let trimmed = &len_bytes[start..];
            out.push(0xb7 + trimmed.len() as u8);
            out.extend_from_slice(trimmed);
        }
        out.extend_from_slice(b);
        out
    }

    fn rlp_list(items: Vec<Vec<u8>>) -> Vec<u8> {
        let payload: Vec<u8> = items.into_iter().flatten().collect();
        let mut out = Vec::new();
        if payload.len() < 56 {
            out.push(0xc0 + payload.len() as u8);
        } else {
            let len_bytes = (payload.len() as u64).to_be_bytes();
            let start = len_bytes.iter().position(|&x| x != 0).unwrap_or(7);
            let trimmed = &len_bytes[start..];
            out.push(0xf7 + trimmed.len() as u8);
            out.extend_from_slice(trimmed);
        }
        out.extend_from_slice(&payload);
        out
    }

    fn rlp_encode_tx_for_signing(
        nonce: u64,
        gas_price: u64,
        gas_limit: u64,
        to: &[u8; 20],
        value: u64,
        data: &[u8],
        chain_id: u64,
    ) -> Vec<u8> {
        rlp_list(vec![
            rlp_encode_int(nonce),
            rlp_encode_int(gas_price),
            rlp_encode_int(gas_limit),
            rlp_encode_bytes(to),
            rlp_encode_int(value),
            rlp_encode_bytes(data),
            rlp_encode_int(chain_id),
            rlp_encode_int(0), // r = 0
            rlp_encode_int(0), // s = 0
        ])
    }

    #[allow(clippy::too_many_arguments)]
    fn rlp_encode_signed_tx(
        nonce: u64,
        gas_price: u64,
        gas_limit: u64,
        to: &[u8; 20],
        value: u64,
        data: &[u8],
        v: u64,
        r: &[u8],
        s: &[u8],
    ) -> Vec<u8> {
        rlp_list(vec![
            rlp_encode_int(nonce),
            rlp_encode_int(gas_price),
            rlp_encode_int(gas_limit),
            rlp_encode_bytes(to),
            rlp_encode_int(value),
            rlp_encode_bytes(data),
            rlp_encode_int(v),
            rlp_encode_bytes(r),
            rlp_encode_bytes(s),
        ])
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Anchor a 32-byte session ledger tip hash to an EVM chain.
///
/// Reads all configuration from environment variables (see module docs).
/// Requires `--features evm` at compile time.
#[cfg(feature = "evm")]
pub async fn anchor_to_evm(session_hash_hex: &str) -> Result<EvmAnchorResult, EvmAnchorError> {
    let rpc_url =
        std::env::var(ENV_RPC_URL).map_err(|_| EvmAnchorError::MissingConfig(ENV_RPC_URL))?;
    let chain_id: u64 = std::env::var(ENV_CHAIN_ID)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let contract_str = std::env::var(ENV_CONTRACT_ADDRESS)
        .map_err(|_| EvmAnchorError::MissingConfig(ENV_CONTRACT_ADDRESS))?;
    let private_key_hex = std::env::var(ENV_PRIVATE_KEY)
        .map_err(|_| EvmAnchorError::MissingConfig(ENV_PRIVATE_KEY))?;

    let contract_addr = validate_address(&contract_str)?;
    let signing_key = signing::parse_signing_key(&private_key_hex)?;
    let sender = signing::address_from_key(&signing_key);
    let calldata = encode_anchor_calldata(session_hash_hex)?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| Client::new());

    // Fetch nonce via eth_getTransactionCount.
    let nonce_hex = rpc_call::<String>(
        &client, &rpc_url,
        json!({"jsonrpc":"2.0","method":"eth_getTransactionCount","params":[format!("0x{}", hex::encode(sender)),"pending"],"id":1}),
    ).await.map_err(|e| EvmAnchorError::Rpc(format!("getTransactionCount: {}", e)))?;
    let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)
        .map_err(|e| EvmAnchorError::Rpc(format!("nonce parse: {}", e)))?;

    // Fetch current gas price via eth_gasPrice.
    let gas_price_hex = rpc_call::<String>(
        &client,
        &rpc_url,
        json!({"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":2}),
    )
    .await
    .map_err(|e| EvmAnchorError::Rpc(format!("gasPrice: {}", e)))?;
    let gas_price_wei = u64::from_str_radix(gas_price_hex.trim_start_matches("0x"), 16)
        .map_err(|e| EvmAnchorError::Rpc(format!("gasPrice parse: {}", e)))?;
    // Round gas price up to nearest Gwei and add 10% buffer.
    let gas_price_gwei = (gas_price_wei / 1_000_000_000) + 1;

    // Fixed gas limit sufficient for a single event emission.
    const GAS_LIMIT: u64 = 60_000;

    let raw_tx = signing::sign_eip155_tx(
        nonce,
        gas_price_gwei,
        GAS_LIMIT,
        &contract_addr,
        0,
        &calldata,
        chain_id,
        &signing_key,
    );

    let raw_hex = format!("0x{}", hex::encode(&raw_tx));
    let tx_hash = rpc_call::<String>(
        &client,
        &rpc_url,
        json!({"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":[raw_hex],"id":3}),
    )
    .await
    .map_err(|e| EvmAnchorError::Rpc(format!("sendRawTransaction: {}", e)))?;

    Ok(EvmAnchorResult {
        session_hash: session_hash_hex.to_string(),
        tx_hash,
        chain_id,
        rpc_url,
    })
}

/// Stub for when the `evm` feature is not enabled.
#[cfg(not(feature = "evm"))]
pub async fn anchor_to_evm(_session_hash_hex: &str) -> Result<EvmAnchorResult, EvmAnchorError> {
    Err(EvmAnchorError::MissingConfig(
        "EVM anchoring is not compiled in. \
         Rebuild with: cargo build --features evm\n\
         Required env vars: EVM_RPC_URL, EVM_CONTRACT_ADDRESS, EVM_PRIVATE_KEY\n\
         See contracts/EctoLedgerAnchor.sol for the minimal on-chain contract.",
    ))
}

// ── Internal JSON-RPC helpers ─────────────────────────────────────────────────

/// Call a JSON-RPC method and deserialize the `result` field.
#[cfg(feature = "evm")]
async fn rpc_call<T: serde::de::DeserializeOwned>(
    client: &Client,
    rpc_url: &str,
    body: serde_json::Value,
) -> Result<T, String> {
    #[derive(Deserialize)]
    struct RpcResponse<R> {
        result: Option<R>,
        error: Option<serde_json::Value>,
    }

    let resp = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let rpc_resp: RpcResponse<T> = resp.json().await.map_err(|e| e.to_string())?;

    if let Some(err) = rpc_resp.error {
        return Err(err.to_string());
    }
    rpc_resp
        .result
        .ok_or_else(|| "missing result field".to_string())
}
