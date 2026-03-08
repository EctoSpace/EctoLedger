use crate::enclave::remote::RemoteEnclaveRuntime;
use crate::enclave::runtime::EnclaveRuntime;
use crate::enclave::software::SoftwareEnclaveRuntime;

/// Which enclave tier to select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveRoute {
    /// Automatically pick the best available tier.
    Auto,
    /// Level 1: software-hardened (mlock + zeroize).
    Software,
    /// Level 2: Apple Hypervisor bare-metal unikernel.
    Apple,
    /// Level 3: remote hardware enclave (Nitro / SEV-SNP).
    Remote,
}

/// Configuration for enclave tier selection.
pub struct EnclaveConfig {
    pub route: EnclaveRoute,
    pub remote_url: Option<String>,
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self {
            route: EnclaveRoute::Auto,
            remote_url: std::env::var("ECTO_ENCLAVE_REMOTE_URL").ok(),
        }
    }
}

/// Select and return a boxed `EnclaveRuntime` based on the configuration and
/// compile-time feature flags.
pub fn select_enclave(config: &EnclaveConfig) -> Box<dyn EnclaveRuntime> {
    match config.route {
        EnclaveRoute::Software => Box::new(SoftwareEnclaveRuntime::new()),

        EnclaveRoute::Apple => {
            #[cfg(all(
                feature = "sandbox-apple-enclave",
                target_os = "macos",
                target_arch = "aarch64"
            ))]
            {
                Box::new(crate::enclave::apple_hv::AppleHvEnclaveRuntime::new())
            }
            #[cfg(not(all(
                feature = "sandbox-apple-enclave",
                target_os = "macos",
                target_arch = "aarch64"
            )))]
            {
                eprintln!(
                    "[enclave/router] Apple HV requested but not available; falling back to Software"
                );
                Box::new(SoftwareEnclaveRuntime::new())
            }
        }

        EnclaveRoute::Remote => {
            if let Some(ref url) = config.remote_url {
                Box::new(RemoteEnclaveRuntime::new_with_url(url.clone()))
            } else {
                eprintln!(
                    "[enclave/router] Remote requested but no URL configured; falling back to Software"
                );
                Box::new(SoftwareEnclaveRuntime::new())
            }
        }

        EnclaveRoute::Auto => {
            // Priority: Remote > Apple HV > Software.
            if let Some(ref url) = config.remote_url {
                return Box::new(RemoteEnclaveRuntime::new_with_url(url.clone()));
            }

            #[cfg(all(
                feature = "sandbox-apple-enclave",
                target_os = "macos",
                target_arch = "aarch64"
            ))]
            {
                return Box::new(crate::enclave::apple_hv::AppleHvEnclaveRuntime::new());
            }

            #[cfg(not(all(
                feature = "sandbox-apple-enclave",
                target_os = "macos",
                target_arch = "aarch64"
            )))]
            {
                Box::new(SoftwareEnclaveRuntime::new())
            }
        }
    }
}
