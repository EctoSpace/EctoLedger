//! OS-level sandboxing and canonical output formatting for EctoLedger.
//!
//! This crate isolates all platform-specific sandbox code (Landlock, Seatbelt,
//! Windows Job Objects, seccomp-BPF) and container orchestration (Docker,
//! Firecracker) behind a single public interface.  The host crate re-exports
//! this module so existing `crate::sandbox::*` paths continue to resolve.

pub mod output;
pub mod sandbox;

// Re-export the most common types at crate root for convenience.
pub use output::{CMD_MAX_OUTPUT_BYTES, format_sandbox_output, trim_to_max};
pub use sandbox::*;
