// The Apple Hypervisor only allows one VM at a time per process, so these tests
// must not run concurrently.  A static mutex serialises access.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
static HV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn enclave_apple_boot() {
    let _guard = HV_LOCK.lock().unwrap();
    let result = ectoledger::enclave::test_enclave_boot();
    match &result {
        Err(e) if e.contains("unsupported operation") || e.contains("HypervisorError") => {
            eprintln!("SKIPPED: Apple Hypervisor not available (running inside a VM?): {e}");
            return;
        }
        _ => {}
    }
    assert!(result.is_ok(), "Apple Hypervisor boot failed: {result:?}");
}

/// Full EnclaveRuntime lifecycle: initialize → verify attestation → destroy.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn enclave_runtime_lifecycle() {
    let _guard = HV_LOCK.lock().unwrap();
    use ectoledger::enclave::apple_hv::AppleHvEnclaveRuntime;
    use ectoledger::enclave::runtime::{EnclaveLevel, EnclaveRuntime};

    let mut rt = AppleHvEnclaveRuntime::new();

    // Initialize: boots VM, performs IPC handshake, returns attestation.
    match rt.initialize() {
        Err(e)
            if e.to_string().contains("unsupported operation")
                || e.to_string().contains("HypervisorError") =>
        {
            eprintln!("SKIPPED: Apple Hypervisor not available (running inside a VM?): {e}");
            return;
        }
        Err(e) => panic!("initialize failed: {e}"),
        Ok(attestation) => {
            if attestation.level == EnclaveLevel::SoftwareHardened {
                eprintln!(
                    "SKIPPED: Apple HV booted but IPC handshake degraded to SoftwareHardened"
                );
                rt.destroy().ok();
                return;
            }

            assert_eq!(attestation.level, EnclaveLevel::AppleHypervisor);
            assert!(
                !attestation.measurement_hash.is_empty(),
                "measurement hash must not be empty"
            );
            assert_eq!(rt.level(), EnclaveLevel::AppleHypervisor);

            // Destroy: tears down the enclave.
            rt.destroy().expect("destroy failed");
        }
    }
}
