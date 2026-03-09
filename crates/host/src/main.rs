use clap::{Parser, Subcommand};
use ectoledger::commands;
use ectoledger::config;
use ectoledger::db_setup;
use ectoledger::ledger;
#[cfg(any(all(target_os = "linux", feature = "sandbox"), windows))]
use ectoledger::sandbox;
use ectoledger::secrets;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "ectoledger")]
#[command(
    about = "Cryptographically verified, state-driven agent framework for automated security auditing"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the database, migrations, and Observer dashboard on port 3000 (no agent).
    Serve {
        /// Verify full chain from genesis; otherwise only last 1000 events.
        #[arg(long, default_value_t = false)]
        verify_full: bool,
    },

    /// Run a security audit: start the Observer and execute the cognitive loop with the given prompt.
    Audit {
        /// Audit instruction for the agent (e.g. "Read server_config.txt").
        #[arg(required = true)]
        prompt: String,
        /// Verify full chain from genesis; otherwise only last 1000 events.
        #[arg(long, default_value_t = false)]
        verify_full: bool,
        /// Path to audit_policy.toml (policy hash stored in session and genesis).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// Disable the Guard (not recommended). Requires --no-guard-confirmed to proceed.
        #[arg(long)]
        no_guard: bool,
        /// Explicitly acknowledge running without the Guard. Must be used with --no-guard.
        #[arg(long)]
        no_guard_confirmed: bool,
        /// Prompt for approval gate decisions interactively on stdin instead of the dashboard.
        #[arg(long, default_value_t = false)]
        interactive: bool,
        /// Read the key-encryption password from the given file descriptor
        /// instead of the interactive prompt or ECTO_KEY_PASSWORD env var.
        /// More secure than env vars (not visible via /proc, ps, docker inspect).
        /// Unix only.  Example: `ectoledger audit "..." --key-password-fd 3  3< <(pass show ectoledger)`
        #[arg(long)]
        key_password_fd: Option<i32>,
        /// Automatically anchor the ledger tip to the target chain at this
        /// interval (in seconds) during the audit.  0 = disabled (default).
        /// Requires EVM env vars for `ethereum`, or OTS for `bitcoin`.
        /// This is defense-in-depth: periodic anchoring limits the window
        /// in which a compromised system could rewrite unanchored history (TM-1e).
        #[arg(long, default_value_t = 0)]
        auto_anchor_interval: u64,
        /// Target chain for auto-anchoring: `bitcoin` or `ethereum`.
        #[arg(long, default_value = "bitcoin", value_parser = ["bitcoin", "ethereum"])]
        auto_anchor_chain: String,
    },

    /// Replay events for a session (colored output).
    Replay {
        /// Session UUID to replay.
        session: Uuid,
        /// Stop after this many steps (default: all).
        #[arg(long)]
        to_step: Option<u32>,
        /// Inject adversarial observation at sequence (e.g. "seq=3:EVIL PAYLOAD"). Can be repeated.
        #[arg(long)]
        inject_observation: Vec<String>,
    },

    /// Verify event signatures for a session (ed25519).
    VerifySession {
        /// Session UUID.
        session: Uuid,
    },

    /// Export audit report for a session.
    Report {
        /// Session UUID.
        session: Uuid,
        /// Output format: sarif, json, html, or certificate (.elc).
        #[arg(long, default_value = "json")]
        format: String,
        /// Write to file (default: stdout). Required for --format certificate.
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Skip OpenTimestamps submission when generating a certificate.
        #[arg(long, default_value_t = false)]
        no_ots: bool,
    },

    /// Multi-agent orchestration: runs recon / analysis / verify sub-agents with independent ledgers.
    Orchestrate {
        /// Audit goal for the orchestrated run.
        #[arg(required = true)]
        goal: String,
        /// Shared policy file applied to all sub-agents (optional).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// Maximum steps per sub-agent (default: role-specific policy max_steps).
        #[arg(long)]
        max_steps: Option<u32>,
    },

    /// Compare two audit sessions (baseline vs current). Outputs remediation evidence.
    DiffAudit {
        /// Baseline session UUID.
        #[arg(long)]
        baseline: Uuid,
        /// Current session UUID.
        #[arg(long)]
        current: Uuid,
        /// Output path (default: stdout).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Red-team mode: adversarial agent to test defenses.
    RedTeam {
        /// UUID of the completed audit session to attack.
        #[arg(long)]
        target_session: Uuid,
        /// Maximum number of injection candidates to generate.
        #[arg(long, default_value = "50")]
        attack_budget: u32,
        /// Optional path to write the report as JSON.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },

    /// Generate a cryptographic SP1 ZK proof of an audit session and embed it in the certificate.
    /// Compile with `--features zk` to enable proof generation.
    ProveAudit {
        /// Session UUID to prove.
        session: Uuid,
        /// Path to the audit policy TOML file (used to extract policy patterns for the proof).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// Output path for the .elc certificate file (default: audit-<session>.elc).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Skip OpenTimestamps submission in the generated certificate.
        #[arg(long, default_value_t = false)]
        no_ots: bool,
    },

    /// Anchor a session's ledger tip to the Bitcoin timechain via OpenTimestamps,
    /// or to an EVM-compatible chain via a smart contract call.
    AnchorSession {
        /// Session UUID whose ledger tip to anchor.
        session: Uuid,
        /// Target chain: `bitcoin` (default, via OpenTimestamps) or `ethereum`
        /// (EVM-compatible — requires EVM_RPC_URL, EVM_CHAIN_ID, EVM_CONTRACT_ADDRESS,
        /// EVM_PRIVATE_KEY env vars and `--features evm` build flag).
        #[arg(long, default_value = "bitcoin", value_parser = ["bitcoin", "ethereum"])]
        chain: String,
    },

    /// Verify an EctoLedger Audit Certificate (.elc) file.
    VerifyCertificate {
        /// Path to the .elc certificate file.
        file: std::path::PathBuf,
    },

    /// Decode and verify a W3C VC-JWT issued by EctoLedger.
    ///
    /// Checks structure, expiry, and (when --issuer-hex is provided) the Ed25519 signature
    /// over the VC payload.  Prints the decoded credential subject to stdout.
    ///
    /// # Examples
    ///
    ///   ectoledger verify-vc "eyJhbGci..."
    ///   ectoledger verify-vc "eyJhbGci..." --issuer-hex <hex-encoded verifying key>
    VerifyVc {
        /// The VC-JWT string (three base64url parts separated by `.`).
        jwt: String,
        /// Optional hex-encoded Ed25519 verifying key (32 bytes / 64 hex chars).
        /// When provided, the JWT signature is verified against this key.
        #[arg(long)]
        issuer_hex: Option<String>,
    },
}

/// Returns true when the configured DATABASE_URL uses a SQLite scheme.
fn is_sqlite_url(url: &str) -> bool {
    url.starts_with("sqlite:") || url.starts_with("sqlite://")
}

/// Extract a filesystem path from a SQLite DATABASE_URL.
///
/// Handles the common variants:
///   sqlite:ledger.db      → ledger.db
///   sqlite://ledger.db    → ledger.db
///   sqlite:///tmp/l.db    → /tmp/l.db
///   sqlite::memory:       → None  (in-memory, no file)
fn sqlite_path_from_url(url: &str) -> Option<std::path::PathBuf> {
    let path_str = if let Some(rest) = url.strip_prefix("sqlite:///") {
        // sqlite:///tmp/l.db → /tmp/l.db  (absolute path — restore leading slash)
        format!("/{rest}")
    } else if let Some(rest) = url.strip_prefix("sqlite://") {
        rest.to_string()
    } else if let Some(rest) = url.strip_prefix("sqlite:") {
        rest.to_string()
    } else {
        url.to_string()
    };
    if path_str == ":memory:" || path_str.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(path_str))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    dotenvy::dotenv().ok();

    // Windows: apply Job Object sandbox to the current process.
    // All child processes inherit KILL_ON_JOB_CLOSE + UI restrictions.
    // This is done at startup (not per-child) because Windows lacks Unix pre_exec.
    #[cfg(target_os = "windows")]
    {
        let ws = std::env::current_dir().unwrap_or_default();
        if let Err(e) = sandbox::apply_child_sandbox(&ws) {
            tracing::error!("Windows Job Object sandbox could not be applied: {}", e);
            return Err("Aborting: Windows Job Object sandbox could not be applied.".into());
        }
    }

    let cli = Cli::parse();

    // ── Offline commands: no database required ─────────────────────────────
    // Handle commands that are purely local (no DB, no ledger) before
    // attempting any database connection or migration.
    match &cli.command {
        Commands::VerifyCertificate { file } => {
            commands::report::run_verify_certificate(file)?;
            return Ok(());
        }
        Commands::VerifyVc { jwt, issuer_hex } => {
            commands::report::run_verify_vc(jwt, issuer_hex.as_deref())?;
            return Ok(());
        }
        _ => {} // fall through to DB setup
    }

    let configured_url = config::database_url()?;

    // ── Database setup: dispatch by URL scheme ────────────────────────────
    //
    // The CLI supports both PostgreSQL and SQLite.  A single `DatabasePool`
    // is constructed below (one branch per backend) and all subsequent logic
    // — chain verification, genesis, shutdown wiring, and command dispatch —
    // runs exactly once against that pool, eliminating the previous fork.
    //
    //   postgres://...  → PgPool + Postgres migrations + full command set
    //   sqlite:...      → SqlitePool (zero infrastructure, limited commands)

    let is_sqlite = is_sqlite_url(&configured_url);

    // ── Guard: reject commands that require PostgreSQL when using SQLite ───
    if is_sqlite {
        match &cli.command {
            Commands::Orchestrate { .. }
            | Commands::DiffAudit { .. }
            | Commands::RedTeam { .. }
            | Commands::Audit { .. }
            | Commands::ProveAudit { .. }
            | Commands::AnchorSession { .. } => {
                return Err("This command requires PostgreSQL. \
                     SQLite mode does not support this command yet. \
                     Set DATABASE_URL to a postgres:// URL and try again."
                    .into());
            }
            _ => {}
        }
    }

    // ── Backend construction ──────────────────────────────────────────────
    //
    // For PostgreSQL: spin up embedded PG if needed, run migrations, seed
    // the OBSERVER_TOKEN, then wrap in DatabasePool::Postgres.
    // For SQLite: open (or create) the on-disk file, run SQLite migrations,
    // then wrap in DatabasePool::Sqlite.
    let _embedded_pg: Option<db_setup::EmbeddedDb>;
    let backend: ectoledger::pool::DatabasePool;

    if is_sqlite {
        _embedded_pg = None;
        let db_path = sqlite_path_from_url(&configured_url);
        backend = ectoledger::pool::create_sqlite_pool(&db_path.unwrap_or_else(|| {
            db_setup::app_data_dir()
                .join("ectoledger")
                .join("ledger.db")
        }))
        .await?;

        // Seed the current session's OBSERVER_TOKEN as an admin entry in api_tokens
        // so that Bearer-token auth works out of the box with SQLite (including the
        // in-memory database used by integration tests).
        {
            use sha2::{Digest, Sha256 as Sha2};
            let legacy_token = config::observer_token();
            let token_hash = hex::encode(Sha2::digest(legacy_token.as_bytes()));
            match backend
                .insert_token(
                    &token_hash,
                    "admin",
                    Some("observer_token (bootstrapped)"),
                    None,
                )
                .await
            {
                Ok(_) => {
                    tracing::info!("OBSERVER_TOKEN registered as admin in api_tokens (SQLite).")
                }
                Err(e) => tracing::warn!("Failed to seed OBSERVER_TOKEN into api_tokens: {e}"),
            }
        }
    } else {
        let result = db_setup::ensure_postgres_ready(&configured_url).await?;
        let database_url = result.0;
        _embedded_pg = Some(result.1);

        // Tune pool size to prevent connection exhaustion during multi-agent runs.
        // Defaults to 2×CPU (min 5, max 50); override with DATABASE_POOL_SIZE env var.
        let pool_size: u32 = config::database_pool_size();
        let pg = PgPoolOptions::new()
            .max_connections(pool_size)
            .min_connections(1)
            .idle_timeout(std::time::Duration::from_secs(600))
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(&database_url)
            .await?;

        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&pg)
            .await?;
        tracing::info!("Database connected (PostgreSQL).");

        sqlx::migrate!("./migrations").run(&pg).await?;

        // Seed the current session's OBSERVER_TOKEN as an admin entry in api_tokens.
        // Uses ON CONFLICT so the insert is idempotent: re-using the same token
        // across restarts is a no-op.
        {
            use sha2::{Digest, Sha256 as Sha2};
            let legacy_token = config::observer_token();
            let token_hash = hex::encode(Sha2::digest(legacy_token.as_bytes()));
            match sqlx::query(
                "INSERT INTO api_tokens (token_hash, role, label) \
                 VALUES ($1, 'admin', 'observer_token (bootstrapped)') \
                 ON CONFLICT (token_hash) DO NOTHING",
            )
            .bind(&token_hash)
            .execute(&pg)
            .await
            {
                Ok(_) => tracing::info!("OBSERVER_TOKEN registered as admin in api_tokens."),
                Err(e) => tracing::warn!("Failed to seed OBSERVER_TOKEN into api_tokens: {e}"),
            }
        }

        // ISSUE-19: Load EVM_PRIVATE_KEY into secure memory and scrub from environment.
        // On Linux the full process environment is readable via /proc/<pid>/environ by any
        // process with the same UID, and is logged by some container runtimes.
        if let Some(_evm_key) = secrets::load_env_secret("EVM_PRIVATE_KEY") {
            tracing::info!(
                "EVM_PRIVATE_KEY loaded into secure memory and removed from process environment. \
                 The key will be zeroized when no longer needed."
            );
        }

        backend = ectoledger::pool::DatabasePool::Postgres(pg);
    }

    // ── Shared startup: chain verification ───────────────────────────────
    let verify_full = match &cli.command {
        Commands::Serve { verify_full, .. } | Commands::Audit { verify_full, .. } => *verify_full,
        _ => false,
    };
    if let Some((latest_seq, _)) = backend.get_latest().await? {
        let from = if verify_full {
            0
        } else {
            (latest_seq - 999).max(0)
        };
        let to = latest_seq;
        let chain_ok = match &backend {
            ectoledger::pool::DatabasePool::Postgres(p) => {
                ledger::verify_chain(p, from, to).await?
            }
            ectoledger::pool::DatabasePool::Sqlite(p) => {
                ledger::sqlite::verify_chain_sqlite(p, from, to).await?
            }
        };
        if !chain_ok {
            return Err("Ledger chain verification failed: tampering detected.".into());
        }
    }

    // ── Shared startup: genesis ───────────────────────────────────────────
    let appended = backend.ensure_genesis().await?;
    if appended.sequence == 0 {
        tracing::info!("Genesis block created.");
    } else {
        tracing::info!(
            "Genesis already present; latest sequence = {}.",
            appended.sequence
        );
    }

    let metrics = std::sync::Arc::new(ectoledger::metrics::Metrics::default());

    // ── Platform sandbox: apply seccomp-BPF AFTER database setup ───────────
    //
    // The Linux seccomp filter is installed here (after DB setup) rather than
    // at process start, because embedded PostgreSQL (pg_embed) spawns child
    // processes via fork()+exec() that inherit the filter via PR_SET_NO_NEW_PRIVS.
    // PostgreSQL requires System V IPC (shmget, semget, etc.) which are NOT in
    // the allowlist.  Deferring the filter until after DB setup avoids this.
    //
    // The filter still protects all command execution (serve, audit, agent loop)
    // which is where untrusted input is processed.
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        if let Err(e) = sandbox::apply_main_process_seccomp() {
            tracing::error!("Linux seccomp filter failed to apply: {}", e);
            return Err("Aborting: main-process seccomp sandbox could not be applied.".into());
        }
    }

    // ── Graceful shutdown: wire Ctrl-C to the cancellation token ─────────
    let cancel = CancellationToken::new();
    {
        let shutdown_cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("SIGINT received — initiating graceful shutdown");
                shutdown_cancel.cancel();
            }
        });
    }

    // ── Command dispatch (single block for both backends) ─────────────────
    match cli.command {
        Commands::Serve { .. } => match backend {
            ectoledger::pool::DatabasePool::Postgres(pg) => {
                commands::serve::run(pg, metrics, cancel).await?;
            }
            other => {
                commands::serve::run_with_pool(other, metrics, cancel).await?;
            }
        },
        Commands::Audit {
            prompt,
            policy,
            no_guard,
            no_guard_confirmed,
            interactive,
            key_password_fd,
            auto_anchor_interval,
            auto_anchor_chain,
            ..
        } => {
            // SQLite is guarded above; safe to unwrap the Postgres pool.
            let pg = backend.as_pg().expect("Audit requires PostgreSQL").clone();
            commands::audit::run(
                pg,
                metrics,
                commands::audit::AuditArgs {
                    prompt,
                    policy,
                    no_guard,
                    no_guard_confirmed,
                    interactive,
                    key_password_fd,
                    auto_anchor_interval,
                    auto_anchor_chain,
                },
            )
            .await?;
        }
        Commands::Replay {
            session,
            to_step,
            inject_observation,
        } => match &backend {
            ectoledger::pool::DatabasePool::Postgres(pg) => {
                commands::report::run_replay(pg, session, to_step, inject_observation).await?;
            }
            ectoledger::pool::DatabasePool::Sqlite(sq) => {
                commands::report::run_replay_sqlite(sq, session, to_step, inject_observation)
                    .await?;
            }
        },
        Commands::VerifySession { session } => match &backend {
            ectoledger::pool::DatabasePool::Postgres(pg) => {
                commands::report::run_verify_session(pg, session).await?;
            }
            ectoledger::pool::DatabasePool::Sqlite(sq) => {
                commands::report::run_verify_session_sqlite(sq, session).await?;
            }
        },
        Commands::Orchestrate {
            goal,
            policy,
            max_steps,
        } => {
            // SQLite is guarded above; safe to unwrap the Postgres pool.
            let pg = backend
                .as_pg()
                .expect("Orchestrate requires PostgreSQL")
                .clone();
            commands::orchestrate::run_orchestrate(
                &ectoledger::pool::DatabasePool::Postgres(pg),
                goal,
                policy,
                max_steps,
            )
            .await?;
        }
        Commands::DiffAudit {
            baseline,
            current,
            output,
        } => {
            let pg = backend
                .as_pg()
                .expect("DiffAudit requires PostgreSQL")
                .clone();
            commands::orchestrate::run_diff_audit(&pg, baseline, current, output).await?;
        }
        Commands::RedTeam {
            target_session,
            attack_budget,
            output,
        } => {
            let pg = backend
                .as_pg()
                .expect("RedTeam requires PostgreSQL")
                .clone();
            commands::orchestrate::run_red_team(&pg, target_session, attack_budget, output).await?;
        }
        Commands::ProveAudit {
            session,
            policy,
            output,
            no_ots,
        } => {
            let pg = backend
                .as_pg()
                .expect("ProveAudit requires PostgreSQL")
                .clone();
            commands::prove::run(&pg, session, policy, output, no_ots).await?;
        }
        Commands::AnchorSession { session, chain } => {
            let pg = backend
                .as_pg()
                .expect("AnchorSession requires PostgreSQL")
                .clone();
            commands::anchor::run(&pg, session, chain).await?;
        }
        Commands::Report {
            session,
            format,
            output,
            no_ots,
        } => match &backend {
            ectoledger::pool::DatabasePool::Postgres(pg) => {
                commands::report::run_report(pg, session, format, output, no_ots).await?;
            }
            ectoledger::pool::DatabasePool::Sqlite(sq) => {
                commands::report::run_report_sqlite(sq, session, format, output, no_ots).await?;
            }
        },
        // VerifyCertificate and VerifyVc are handled above (early return, no DB).
        Commands::VerifyCertificate { .. } | Commands::VerifyVc { .. } => unreachable!(),
    }

    Ok(())
}
