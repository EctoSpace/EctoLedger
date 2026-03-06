pub mod remote;
pub mod router;
pub mod runtime;
pub mod software;

#[cfg(feature = "enclave")]
pub mod ipc;

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub mod apple_hv;

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub use apple_hv::test_enclave_boot;

#[cfg(not(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
)))]
pub fn test_enclave_boot() -> Result<(), String> {
    Err("sandbox-apple-enclave is only available on macOS arm64".to_string())
}
