use serde::{Deserialize, Serialize};

/// Confidentiality tier for the enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclaveLevel {
    /// Level 1 – mlock'd host memory, zeroized on drop.
    SoftwareHardened,
    /// Level 2 – Apple Hypervisor Framework (aarch64 bare-metal unikernel).
    AppleHypervisor,
    /// Level 3 – Remote hardware enclave (AWS Nitro / AMD SEV-SNP).
    RemoteHardwareEnclave,
}

impl std::fmt::Display for EnclaveLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SoftwareHardened => write!(f, "software_hardened"),
            Self::AppleHypervisor => write!(f, "apple_hypervisor"),
            Self::RemoteHardwareEnclave => write!(f, "remote_hardware_enclave"),
        }
    }
}

/// Attestation evidence produced by an enclave after initialization or execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveAttestation {
    pub level: EnclaveLevel,
    /// SHA-256 hash of the enclave measurement (binary payload or remote report).
    pub measurement_hash: String,
    /// Raw attestation blob (e.g. COSE-Sign1 for Nitro, vCPU register dump for Apple HV).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_attestation: Option<Vec<u8>>,
}

/// Request sent into the enclave for inference.
#[derive(Debug, Clone)]
pub struct EnclaveRequest {
    pub prompt: Vec<u8>,
    pub model_id: String,
}

/// Response returned from the enclave.
#[derive(Debug, Clone)]
pub struct EnclaveResponse {
    pub output: Vec<u8>,
    pub attestation: EnclaveAttestation,
}

/// Core trait for all enclave tiers.
///
/// Implementations must be `Send + Sync` so they can be stored in `AgentLoopConfig` and shared
/// across await points inside `tokio::spawn`.  The methods are synchronous because vCPU
/// execution is inherently blocking (the host thread parks until the guest triggers an exit).
pub trait EnclaveRuntime: Send + Sync {
    /// Boot / attest the enclave.  Returns attestation evidence on success.
    fn initialize(&mut self) -> Result<EnclaveAttestation, String>;
    /// Send a prompt into the enclave and receive an encrypted response.
    fn execute(&self, req: EnclaveRequest) -> Result<EnclaveResponse, String>;
    /// Which tier this runtime represents.
    fn level(&self) -> EnclaveLevel;
    /// Tear down the enclave, zeroize secrets.
    fn destroy(&mut self) -> Result<(), String>;
}
