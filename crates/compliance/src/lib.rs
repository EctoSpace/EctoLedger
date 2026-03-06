//! Compliance artefact modules for EctoLedger.
//!
//! This crate bundles the self-contained compliance primitives:
//! - **ots** — OpenTimestamps integration (submit SHA-256 digests to calendar pools)
//! - **evm_anchor** — Ethereum on-chain session hash anchoring
//! - **verifiable_credential** — W3C VC-JWT issuance and verification (EdDSA / ECDSA)
//!
//! The host crate re-exports these modules so existing `crate::ots::*`,
//! `crate::evm_anchor::*`, and `crate::verifiable_credential::*` paths
//! continue to resolve.

pub mod evm_anchor;
pub mod ots;
pub mod verifiable_credential;
