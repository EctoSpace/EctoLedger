//! Unified error type for the EctoLedger host crate.
//!
//! `EctoLedgerError` wraps every module-level error behind a single enum so
//! that public API surfaces (commands, server, SDK bindings) can propagate
//! typed errors instead of `Box<dyn Error>`.
//!
//! Adopting this type at call-sites is **incremental**: existing functions that
//! return `Box<dyn Error + Send + Sync>` can use `EctoLedgerError` via its
//! blanket `From` impl into `Box<dyn Error>`, or switch their return type at
//! their own pace.

/// Unified error type covering all host-crate subsystems.
///
/// Variants map 1-to-1 to the concrete error enums defined in each module.
/// All conversions are derived with `#[from]`, so `?` works transparently
/// when the calling function returns `Result<T, EctoLedgerError>`.
#[derive(Debug, thiserror::Error)]
pub enum EctoLedgerError {
    // ── Infrastructure ────────────────────────────────────────────────────────
    /// I/O error (file system, network, process).
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Database query or connection error.
    #[error(transparent)]
    Database(#[from] sqlx::Error),

    /// Database migration error.
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// Database setup / polling error.
    #[error(transparent)]
    DbSetup(#[from] crate::db_setup::DbSetupError),

    // ── Core agent operations ─────────────────────────────────────────────────
    /// Agent cognitive-loop error.
    #[error(transparent)]
    Agent(#[from] crate::agent::AgentError),

    /// Ledger append error.
    #[error(transparent)]
    LedgerAppend(#[from] crate::ledger::AppendError),

    /// Cryptographic signing error.
    #[error(transparent)]
    Signing(#[from] crate::signing::SigningError),

    /// Policy parsing / loading error.
    #[error(transparent)]
    Policy(#[from] crate::policy::PolicyLoadError),

    // ── Execution & sandboxing ────────────────────────────────────────────────
    /// Command / tool execution error.
    #[error(transparent)]
    Executor(#[from] crate::executor::ExecuteError),

    /// OS-level sandbox error.
    #[error(transparent)]
    Sandbox(#[from] crate::sandbox::SandboxError),

    /// Guard micro-VM process error.
    #[error(transparent)]
    Guard(#[from] crate::guard_process::GuardProcessError),

    /// Blocking-task spawn error.
    #[error(transparent)]
    Blocking(#[from] crate::blocking::BlockingTaskError),

    // ── AI / LLM ──────────────────────────────────────────────────────────────
    /// LLM backend error.
    #[error(transparent)]
    Llm(#[from] crate::llm::LlmError),

    /// Ollama setup / health-check error.
    #[error(transparent)]
    OllamaSetup(#[from] crate::ollama::OllamaSetupError),

    // ── Reporting & verification ──────────────────────────────────────────────
    /// Report generation error.
    #[error(transparent)]
    Report(#[from] crate::report::ReportError),

    /// Certificate generation / verification error.
    #[error(transparent)]
    Certificate(#[from] crate::certificate::CertificateError),

    /// Verifiable Credential error.
    #[error(transparent)]
    VcVerify(#[from] crate::verifiable_credential::VcVerifyError),

    /// Snapshot error.
    #[error(transparent)]
    Snapshot(#[from] crate::snapshot::SnapshotError),

    // ── External anchoring ────────────────────────────────────────────────────
    /// OpenTimestamps error.
    #[error(transparent)]
    Ots(#[from] crate::ots::OtsError),

    /// EVM on-chain anchor error.
    #[error(transparent)]
    EvmAnchor(#[from] crate::evm_anchor::EvmAnchorError),

    // ── Multi-agent ───────────────────────────────────────────────────────────
    /// Orchestrator error.
    #[error(transparent)]
    Orchestrator(#[from] crate::orchestrator::OrchestratorError),

    /// Red-team error.
    #[error(transparent)]
    RedTeam(#[from] crate::red_team::RedTeamError),

    /// Tripwire / safety-rail violation.
    #[error(transparent)]
    Tripwire(#[from] crate::tripwire::TripwireError),

    /// Session wake-up recovery error.
    #[error(transparent)]
    WakeUp(#[from] crate::wakeup::WakeUpError),

    // ── Catch-all ─────────────────────────────────────────────────────────────
    /// Unstructured / ad-hoc error (replaces `format!("...").into()` patterns).
    #[error("{0}")]
    Other(String),
}

impl From<String> for EctoLedgerError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl From<&str> for EctoLedgerError {
    fn from(s: &str) -> Self {
        Self::Other(s.to_owned())
    }
}
