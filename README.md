
> **Your AI agent made 47 decisions. Can you prove what it did? To a regulator? To a court?**
>
> **EctoLedger makes that proof automatic.**

# EctoLedger

[![CI](https://github.com/EctoSpace/EctoLedger/actions/workflows/ci.yml/badge.svg)](https://github.com/EctoSpace/EctoLedger/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.6.4-orange.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-1.94%2B%20%7C%20edition%202024-orange.svg)](https://www.rust-lang.org)
[![GitHub issues](https://img.shields.io/github/issues/EctoSpace/EctoLedger.svg)](https://github.com/EctoSpace/EctoLedger/issues)
[![Last commit](https://img.shields.io/github/last-commit/EctoSpace/EctoLedger.svg)](https://github.com/EctoSpace/EctoLedger/commits/main)


<p align="center">
  <img src="assets/ectoLedger-Logo.webp" alt="EctoLedger Logo" width="250" />
</p>

<p align="center">
  <strong>Cryptographically verified AI agent execution - tamper-evident, policy-enforced, compliance-ready.</strong>
</p>

<p align="center">
  <a href="docs/quickstart.md">Quickstart</a> •
  <a href="#what-ectoledger-is-and-is-not">What It Is</a> •
  <a href="#common-use-cases">Use Cases</a> •
  <a href="#choose-your-starting-mode">Choose Mode</a> •
  <a href="#prerequisites">Prerequisites</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#management-gui">Management GUI</a> •
  <a href="#sdks">SDKs</a> •
  <a href="#cli-reference">CLI Reference</a> •
  <a href="#configuration-reference">Configuration</a> •
  <a href="#decentralized-identity-and-w3c-verifiable-credentials">Verifiable Credentials</a> •
  <a href="#compliance-iso-420012023">Compliance</a> •
  <a href="#project-layout">Project Layout</a>
</p>

---

## What is EctoLedger?

**EctoLedger is the dashcam + emergency brake for autonomous AI agents.**

Your AI agent just made 47 decisions.  
Can you prove exactly what it did — to a regulator, an auditor, or a court?  
EctoLedger makes that proof automatic… while physically blocking dangerous actions before they happen.

### What EctoLedger is (and is not)

**What it is**
- A **security proxy** in front of autonomous AI actions.
- A **prevention layer** that can block unsafe commands before execution.
- A **cryptographic evidence layer** that produces tamper-evident audit trails and verifiable certificates.
- An **optional isolation layer** with sandbox tiers (including Firecracker on Linux and Apple Hypervisor guard isolation on supported Apple Silicon builds).

**What it is not**
- Not a crypto trading product.
- Not a replacement for SIEM, ticketing, or full GRC suites.
- Not a legal guarantee by itself; it provides verifiable evidence to support legal/compliance processes.

### Features by platform

| Feature                                    | Linux                      | macOS         | Windows       |
|-------------------------------------------|----------------------------|---------------|---------------|
| Firecracker microVM isolation (optional)   | Yes (when configured)      | Not available | Not available |
| OS-level sandbox (Landlock/Seatbelt/Jobs)  | Yes                        | Yes           | Yes           |
| Real-time GUI dashboard                   | Yes                        | Yes           | Yes           |
| .elc certificate export                  | Yes                        | Yes           | Yes           |
| 4-layer guardrails + tripwire             | Yes                        | Yes           | Yes           |

### Two core capabilities

**1. Constant monitoring + prevention (the emergency brake)**  
Real-time desktop GUI dashboard shows every thought and action live.  
4-layer guardrails (policy engine → dual-LLM checker → schema validation → tripwire) stop risky API calls, data leaks, or unauthorized transactions *before* they execute.

**2. State-of-the-art cryptographic audit (the tamper-proof flight recorder)**  
Every decision is signed, hash-chained, and stored in an immutable ledger.  
Export self-contained `.elc` certificates that any regulator or court can verify offline — no trust in you required.

### Who this is for?
- Teams running AI agents that call APIs, run commands, or touch sensitive data  
- Security & platform engineers who need enforceable guardrails  
- Compliance officers preparing for the EU AI Act (2026) and other AI governance rules  
- Anyone who never wants to say “the AI did it” in front of a judge

### Common use cases

- **AI operations guardrail**: block risky LLM-proposed commands before they hit production systems.
- **Compliance evidence generation**: produce tamper-evident records for SOC 2, PCI-DSS, OWASP, ISO 42001, and internal audits.
- **Enterprise due diligence**: show customers and security teams independently verifiable proof of what the agent did.
- **Incident investigation**: replay what happened during an AI-assisted workflow with signed, hash-chained evidence.

### Choose your starting mode

| Mode | Best for | What you can do |
|---|---|---|
| **Demo (`--demo`)** | Fast product evaluation | Guided local experience with embedded components and seeded data |
| **SQLite (`DATABASE_URL=sqlite://...`)** | Local/dev/CI workflows | Serve dashboard, replay, report, certificate and VC verification |
| **PostgreSQL** | Production and advanced workflows | Full `audit`, `orchestrate`, `diff-audit`, `red-team`, `prove-audit`, `anchor-session` |

### Why now?
The EU AI Act becomes fully enforceable for high-risk AI systems in August 2026.  
Article 12 explicitly requires tamper-evident, automatically recorded logs that normal logging cannot provide.  
Every company deploying autonomous agents will need exactly this infrastructure.  
You built it before the market even knew it was required.

![EctoLedger demo](site/marketing_assets/videos/gui_demo.gif)

### How it works (technical)

EctoLedger gives every AI agent a cryptographically sealed audit trail. Each action is hash-chained, signature-verified, and policy-gated before execution. The result is an immutable ledger that regulators, auditors, and security teams can inspect, replay, and independently verify - with no trust in the issuer.

**Highlights of version 0.6.4:**

| Capability | What it provides |
|---|---|
| **Pluggable ledger backends** | Swap PostgreSQL for SQLite (dev/CI) — or any future store — through the `LedgerBackend` trait; [SQLite does not support](#sqlite-limitations) `audit`, `orchestrate`, `diff-audit`, `red-team`, `prove-audit`, or `anchor-session` |
| **Tauri 2 management GUI** | Glassmorphic desktop app: live dashboard, Prometheus metrics, session browser, policy editor, Tripwire config, settings, certificate export |
| **Python & TypeScript SDKs** | Typed REST clients; LangChain `LedgerTool` and AutoGen `LedgerHook` included |
| **Extended webhooks with HMAC signing** | GuardDenial and TripwireRejection events delivered to any SIEM in JSON, CEF, or LEEF; `X-EctoLedger-Signature: sha256=<hex>` header secures each delivery |
| **W3C Verifiable Credentials** | VC-JWT issued on session completion; Ed25519-signed, `did:key:` anchored; resolvable via `GET /api/sessions/{id}/vc/verify` |
| **ISO 42001:2023** | Machine-readable policy pack (14 controls) and compliance whitepaper |
| **4-layer semantic guard** | Policy engine → dual-LLM guard process → strict schema JSON validation → structural tripwire before every commit |
| **Hardware microVM sandbox (Linux only)** | Firecracker-based execution isolation for `run_command` intents; quick setup via `scripts/setup-firecracker.sh`; enterprise provisioning (custom prefix, `/opt/ectoledger` paths) via `scripts/provision-firecracker.sh` |
| **EVM chain anchoring** | Publish the ledger tip hash to any EVM-compatible chain via `anchor-session --chain ethereum`; built-in and enabled by default |
| **SP1 ZK proofs** | Provable policy compliance without exposing raw event payloads |
| **`.elc` audit certificates** | Self-contained, five-pillar verifiable records; standalone `verify-cert` binary |
| **Automatic signing-key rotation** | Rotate session Ed25519 keys every N steps; `KeyRotation` events record each rollover. Configurable with `AGENT_KEY_ROTATION_STEPS`. |
| **Dynamic orchestrator policy injection** | Per-role policy overrides via `ECTO_RECON_POLICY`, `ECTO_ANALYSIS_POLICY`, `ECTO_VERIFY_POLICY` env vars or a shared `--policy` file |
| **Configurable network binding** | Observer dashboard bind address and port are fully configurable via `ECTO_BIND_HOST` / `ECTO_BIND_PORT` - no port conflicts in container environments |
| **Hardware-aware connection pooling** | Database pool scales to 2×CPU by default (5–50); override with `DATABASE_POOL_SIZE` |

---

## Prerequisites

| Dependency | Required for | Notes |
|---|---|---|
| Rust 1.94+ | All builds | `rustup` recommended (edition 2024) |
| Docker | Docker demo (`docker-compose.demo.yml`) | Not required for `--demo` launcher mode or SQLite mode |
| Ollama / OpenAI / Anthropic | `audit`, `orchestrate`, `red-team` | At least one LLM backend must be reachable |
| Node.js 20+ and npm | Tauri 2 GUI (`gui/`) | Only needed if building or running the desktop app |

---

## The Philosophy

**The agent is the database.** The Rust process is a transient worker. All durable state - the event log and snapshots - lives in the configured ledger backend (PostgreSQL or SQLite). The process has no long-term memory; it restores state from the ledger on each run.

**Verify then commit.** Actions proposed by the LLM pass through a strict four-layer pipeline before they are committed or executed:

1. **Ledger goal anchoring.** The session goal is hashed at creation (`goal_hash`) and re-verified on every `append_event`. Events are SHA-256-chained: any insertion, deletion, or mutation anywhere in the chain is detectable on startup without replaying execution.

2. **Guard process (dual-LLM).** A secondary LLM (`GUARD_LLM_BACKEND` / `GUARD_LLM_MODEL`) runs in a separate process (`guard-worker`) communicating over `stdin`/`stdout` JSON. It evaluates each proposed intent against the stated goal and returns `ALLOW` or `DENY: <reason>`. Configure `GUARD_REQUIRED=true` in production.

3. **Output content scanning (hybrid).** Execution observations are scanned by two passes before being appended to the ledger:
   - **Regex pass:** NFKC normalization followed by tuned patterns - injection phrases, Unicode homoglyphs, zero-width characters, LLM template tags, embedded action JSON, data/javascript URIs, role-injection, base64-encoded blobs, and prompt continuation markers.
   - **Strict schema pass:** Every JSON object containing an `"action"` key is validated against the sealed `StrictAgentOutput` schema with `#[serde(deny_unknown_fields)]`. Any object that carries fields outside the four allowed keys (`action`, `params`, `justification`, `reasoning`) is immediately flagged as a `strict_schema_violation` - catching hijack insertions like `override_goal` or `system_prompt` that exploit structural overlap with valid agent outputs.
   - **Structural JSON/AST pass:** bracket-depth extraction plus `serde_json` parse of every `{...}` candidate, detecting action-shaped objects and goal-hijacking keys that regex alone would miss.
   - **Base64 pass:** decodes `eyJ...` base64 candidates and re-runs the structural check on the decoded payload.

**Tripwire (structural rules):**
- **Paths** - component-level `..` rejection, normalization without `canonicalize()`, symlink-escape detection; only directories under the configured workspace are permitted.
- **Networks** - allowlisted domains only; HTTPS enforced by default (configurable).
- **Commands** - blocklist of dangerous shell constructs (`sudo`, `rm -rf`, etc.).
- **Justification** - every non-complete action requires a minimum length of justification (default 5 characters); empty or missing justifications are rejected immediately.

Tripwire rules (min justification length, require HTTPS, allowed paths/domains, banned command patterns) are configurable via the GUI **Tripwire** menu or `~/.ectoledger/tripwire.json`. See the "Hardware microVM sandbox" and "Automatic signing-key rotation" sections below for additional environment-driven options.

Together these layers raise the bar for prompt injection without claiming unconditional immunity - no software defence is absolute. Intents that pass all checks are appended to the hash-chained ledger and executed; nothing is ever updated or deleted.

---

## Configuration Reference

All configuration is loaded from environment variables (with optional `.env` file support via `dotenvy`). Values marked **[required]** have no sensible default and must be set for the described feature to be active.

### Core Agent

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgres://ectoledger:ectoledger@localhost:5432/ectoledger` | Ledger backend. Use `sqlite://ledger.db` for SQLite. |
| `DATABASE_POOL_SIZE` | `2×CPU` (min 5, max 50) | DB connection pool size. Scales automatically to available CPU cores. |
| `LLM_BACKEND` | `ollama` | Primary LLM backend: `ollama`, `openai`, `anthropic`. |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL. |
| `OLLAMA_MODEL` | `mistral` | Model to pull and use for agent inference. |
| `OPENAI_API_KEY` | - | **[required for openai]** OpenAI API key. |
| `ANTHROPIC_API_KEY` | - | **[required for anthropic]** Anthropic API key. |
| `AGENT_MAX_STEPS` | `20` | Maximum cognitive loop steps per session. |
| `AGENT_SNAPSHOT_INTERVAL` | `50` | Steps between automatic state snapshots. |
| `AGENT_LLM_ERROR_LIMIT` | `5` | Consecutive LLM errors before aborting the session. |
| `AGENT_GUARD_DENIAL_LIMIT` | `3` | Consecutive guard denials before aborting. |
| `AGENT_JUSTIFICATION_FAILURE_LIMIT` | `3` | Consecutive schema failures before aborting. |
| `AGENT_TOKEN_BUDGET_MAX` | unlimited | Maximum approximate token budget per session. |
| `AGENT_KEY_ROTATION_STEPS` | disabled | Steps between Ed25519 signing-key rotations. |
| `AGENT_ALLOWED_DOMAINS` | `[]` | Comma-separated list of allowed `http_get` domains. |

### Guard Process

| Variable | Default | Description |
|---|---|---|
| `GUARD_REQUIRED` | `true` | Abort startup if guard LLM config is missing. Set `false` only for development. |
| `GUARD_LLM_BACKEND` | - | **[required when `GUARD_REQUIRED=true`]** Guard LLM backend: `ollama`, `openai`, `anthropic`. |
| `GUARD_LLM_MODEL` | - | **[required when `GUARD_REQUIRED=true`]** Guard LLM model name. |

### Observer Dashboard & API

| Variable | Default | Description |
|---|---|---|
| `OBSERVER_TOKEN` | auto-generated | Bearer token for the dashboard API. Printed to stdout on first run if unset. |
| `ECTO_BIND_HOST` | `0.0.0.0` | Network interface to bind the dashboard listener. Use `127.0.0.1` for loopback-only. |
| `ECTO_BIND_PORT` | `3000` | TCP port for the dashboard listener. Override to avoid conflicts in multi-instance deployments. |
| `SCANNER_SENSITIVITY` | `medium` | Output scanner level: `low` (structural only), `medium` (default), `high` (broadest). |

### Webhook / SIEM Egress

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | disabled | Target URL for security event POSTs. Required to enable egress. |
| `WEBHOOK_BEARER_TOKEN` | - | `Authorization: Bearer <token>` header added to every POST. |
| `WEBHOOK_HMAC_SECRET` | disabled | When set, each POST includes `X-EctoLedger-Signature: sha256=<hex>` for receiver-side verification. |
| `WEBHOOK_RATE_LIMIT_PER_SECOND` | `10` | Maximum outbound webhook deliveries per second per URL. |
| `WEBHOOK_INCLUDE_GUARD` | `true` | Include `GuardDenial` events in egress. |
| `WEBHOOK_INCLUDE_TRIPWIRE` | `true` | Include `TripwireRejection` events in egress. |
| `SIEM_FORMAT` | `json` | Output format: `json`, `cef` (ArcSight), `leef` (IBM LEEF 2.0). |

### EVM Chain Anchoring

| Variable | Default | Description |
|---|---|---|
| `EVM_RPC_URL` | - | **[required for EVM anchoring]** JSON-RPC endpoint (e.g. `https://mainnet.infura.io/v3/<key>`). |
| `EVM_CHAIN_ID` | - | **[required]** EIP-155 chain ID (1 = Ethereum mainnet, 137 = Polygon, etc.). |
| `EVM_CONTRACT_ADDRESS` | - | **[required]** Deployed `EctoLedgerAnchor` contract address (checksummed). |
| `EVM_PRIVATE_KEY` | - | **[required]** Hex-encoded private key for signing anchor transactions. |

### Firecracker microVM Sandbox

| Variable | Default | Description |
|---|---|---|
| `ECTO_FC_BINARY` | `/usr/local/bin/firecracker` | Path to Firecracker binary. Setting this opts in to sandbox mode. |
| `ECTO_FC_KERNEL` | `/opt/ectoledger/vmlinux` | Path to Linux kernel image (ELF or Image format). |
| `ECTO_FC_ROOTFS` | `/opt/ectoledger/rootfs.ext4` | Path to root filesystem ext4 image. |
| `ECTO_FC_VCPUS` | `1` | Number of vCPUs per microVM. |
| `ECTO_FC_MEM_MIB` | `128` | Memory (MiB) per microVM. |
| `ECTO_FC_TIMEOUT_SECS` | `30` | Hard execution timeout (seconds). |

### Orchestrator Policy Injection

| Variable | Default | Description |
|---|---|---|
| `ECTO_RECON_POLICY` | built-in | Path to a TOML policy file that overrides the built-in Recon sub-agent policy. |
| `ECTO_ANALYSIS_POLICY` | built-in | Path to a TOML policy file that overrides the built-in Analysis sub-agent policy. |
| `ECTO_VERIFY_POLICY` | built-in | Path to a TOML policy file that overrides the built-in Verify sub-agent policy. |

---

## Architecture

The cognitive loop is a strict pipeline: **Perceive → Propose → Verify → Commit → Execute.**

```mermaid
flowchart LR
  Perceive[Perceive State]
  Propose[Propose Intent]
  Policy[Policy Engine]
  Guard[Guard Process]
  Tripwire[Tripwire]
  Commit[Commit to Ledger]
  Execute[Execute Side Effect]
  LLM[Primary LLM]
  DB[(Ledger Backend\nPostgres · SQLite)]
  Host[Host]
  Perceive -->|restore from backend| Propose
  Propose -->|LLM JSON| LLM
  LLM --> Propose
  Propose --> Policy
  Policy --> Guard
  Guard --> Tripwire
  Tripwire -->|allowed only| Commit
  Commit -->|hash-chain + Ed25519| DB
  Commit --> Execute
  Execute -->|run / read / http| Host
  Execute -->|observation scanned| DB
```

1. **Perceive** - Restore agent state from the ledger (latest snapshot + replayed events).
2. **Propose** - Send state to the primary LLM; receive a single JSON intent (`run_command`, `read_file`, `http_get`, `complete`).
3. **Verify** - Policy engine (if `--policy` is set), then Guard process (separate binary), then Tripwire; reject or accept.
4. **Commit** - Verify goal hash, append the action to the ledger (hash-chained, Ed25519-signed), then run the side effect.
5. **Execute** - Run the command, read the file, or perform the HTTP GET; scan observation; append to the ledger. Loop until `complete` or `max_steps` is reached.

---

## Pluggable Ledger Backends

The `LedgerBackend` trait (`crates/ledger-api`) decouples the agent runtime from any specific storage engine. EctoLedger ships two production-ready implementations:

| Backend | Connection string | Best for |
|---|---|---|
| **PostgreSQL** (`PostgresLedger`) | `postgres://user:pass@host/db` | Production, multi-agent, high-throughput |
| **SQLite** (`SqliteLedger`) | `sqlite://ledger.db` | Local development, CI, single-machine audits |

#### SQLite limitations

> **⚠️ Not all commands are available in SQLite mode.** The following commands require PostgreSQL and will exit with an error if `DATABASE_URL` points to a SQLite file:
>
> | Unsupported command | Why PostgreSQL is required |
> |---|---|
> | `audit` | Full cognitive loop requires PG-backed session locking and migrations |
> | `orchestrate` | Multi-agent coordination relies on PG advisory locks |
> | `diff-audit` | Session diffing uses PG-specific window functions |
> | `red-team` | Attack simulation requires full event streaming over PG |
> | `prove-audit` | ZK proof generation reads from PG-only tables |
> | `anchor-session` | On-chain anchoring reads the PG event schema |
>
> SQLite mode fully supports: `serve`, `replay`, `verify-session`, `report`, `verify-certificate`, and `verify-vc`.

Switch backends at runtime via `DATABASE_URL`:

```bash
# PostgreSQL (default)
DATABASE_URL=postgres://ectoledger:ectoledger@localhost:5432/ectoledger cargo run -- serve

# SQLite - zero infrastructure, zero configuration
DATABASE_URL=sqlite://ledger.db cargo run -- serve
```

The `LedgerBackend` trait provides a minimal, cursor-style interface (simplified — see [`crates/ledger-api/src/lib.rs`](crates/ledger-api/src/lib.rs) for the full production trait with signing keys, sequence ranges, and admin operations):

```rust
pub trait LedgerBackend: Send + Sync {
    async fn create_session(&self, new: NewSession) -> Result<(Session, Vec<u8>), LedgerError>;
    async fn append_event(&self, session_id: Uuid, payload: RawPayload,
                          signing_key: &SigningKey, seq: i64) -> Result<AppendResult, LedgerError>;
    async fn seal_session(&self, session_id: Uuid) -> Result<(), LedgerError>;
    async fn get_events_by_session(&self, session_id: Uuid) -> Result<Vec<LedgerEvent>, LedgerError>;
    async fn list_sessions(&self, limit: i64) -> Result<Vec<Session>, LedgerError>;
    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, LedgerError>;
    async fn prove_compliance(&self, session_id: Uuid) -> Result<RawPayload, LedgerError>;
}
```

Third parties can implement this trait to add custom backends (DynamoDB, FoundationDB, etc.) without modifying EctoLedger itself.

### Scaling Considerations

> **SQLite is a single-instance backend.** Do not run multiple EctoLedger processes against the same SQLite file — use PostgreSQL for multi-instance deployments.

PostgreSQL supports horizontal scaling with the following caveats:

- **SSE fanout** uses PostgreSQL `LISTEN/NOTIFY` to wake subscribers across instances (see `pg_notify` module).
- **Approval state** can be persisted to the `pending_approvals` table for cross-instance visibility.
- **Session ownership** uses per-session advisory locks to prevent duplicate cognitive loops.

See [`docs/SCALING.md`](docs/SCALING.md) for the full horizontal-scaling guide.

---

## Zero-Friction Setup

### Additional Environment Variables

- `ECTO_FC_BINARY`, `ECTO_FC_KERNEL`, `ECTO_FC_ROOTFS` – paths required to enable the Firecracker sandbox.  Set at least `ECTO_FC_BINARY` to opt in; the agent will warn if the files are missing or on non-Linux platforms.
- `ECTO_FC_VCPUS`, `ECTO_FC_MEM_MIB`, `ECTO_FC_TIMEOUT_SECS` – optional tuning parameters for microVM size and execution timeout.
- `AGENT_KEY_ROTATION_STEPS` – positive integer number of cognitive-loop steps between automatic session signing-key rotations. If unset or zero, rotation is disabled. A `KeyRotation` ledger event is appended each time a new key is generated.

### Firecracker microVM - Automated Provisioning

Two provisioning scripts are provided:

| Script | Use case |
|---|---|
| `scripts/setup-firecracker.sh` | Quick setup for dev/CI - installs to `~/.local` (no root) or `/usr/local` |
| `scripts/provision-firecracker.sh` | Enterprise setup - installs to `/opt/ectoledger`, custom FC version, systemd-ready |

The `scripts/setup-firecracker.sh` script automates the entire Firecracker setup on any KVM-capable Linux host (x86\_64 and aarch64). It downloads the Firecracker binary, a minimal Linux kernel image, and a compatible rootfs, then prints the exact environment variable exports needed:

```bash
# One-time setup (run as root for system-wide paths, or as a normal user for ~/.local)
sudo bash scripts/setup-firecracker.sh

# Export the variables printed by the script, then:
cargo build --release --features sandbox-firecracker

# Or with the pre-built Linux binary:
ECTO_FC_BINARY=/usr/local/bin/firecracker \
ECTO_FC_KERNEL=/opt/ectoledger/vmlinux \
ECTO_FC_ROOTFS=/opt/ectoledger/rootfs.ext4 \
    ./ectoledger-linux audit "<your goal>"
```

When running as a non-root user, assets are installed to `~/.local/bin` and `~/.local/opt/ectoledger` without requiring `sudo`. The script validates architecture, checks for KVM availability, verifies binary checksums, and prints a ready-to-source export block on completion.

EctoLedger is **self-deploying** - no manual database creation, migration tools, or configuration files required.

**PostgreSQL mode** (default): if `DATABASE_URL` is unset, the binary defaults to `postgres://ectoledger:ectoledger@localhost:5432/ectoledger`. It checks for a Docker container named `ectoledger-postgres`, starts one if absent, polls until ready, then runs migrations and creates the genesis block automatically.

**SQLite mode**: set `DATABASE_URL=sqlite://ledger.db`. No Docker, no external process, no migration tool. The database file is created on first run.

If `OBSERVER_TOKEN` is unset, a random token is generated and printed at startup with the dashboard URL - use it as `?token=…` or in the `Authorization` header.

---

## Quick Start

**macOS:**
```bash
git clone https://github.com/EctoSpace/EctoLedger.git
cd EctoLedger
./ectoledger-mac
```

**Linux:**
```bash
git clone https://github.com/EctoSpace/EctoLedger.git
cd EctoLedger
./ectoledger-linux
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/EctoSpace/EctoLedger.git
cd EctoLedger
.\ectoledger-win.ps1
```

That's it. The launcher script:

1. Checks prerequisites (`cargo`, `node`, `npm`; warns if Ollama isn't running)
2. Creates a `.env` with safe dev defaults on first run
3. Builds the Rust binary (skipped on subsequent runs - fast restart)
4. Installs npm packages for the GUI (`gui/node_modules`)
5. Starts the backend server on `http://127.0.0.1:3000`
6. Opens the Tauri desktop GUI with hot-reload

Press **Ctrl+C** to stop everything cleanly.

### 🚀 Try the Zero-Config Demo

Want to see EctoLedger in action without configuring databases or API keys? Run the launcher with the `--demo` flag:

```bash
# macOS
./ectoledger-mac --demo

# Linux
./ectoledger-linux --demo

# Windows (PowerShell)
.\ectoledger-win.ps1 -demo
```

**What happens?** The launcher starts an isolated embedded PostgreSQL instance on a separate port, auto-detects your LLM, and sets `ECTO_DEMO_MODE=true` so the backend uses a completely separate database from your normal data. Read the full [Demo Architecture Guide](docs/demo-README.md) for details.

**LLM selection (automatic, in priority order):**

| Condition | Result |
|---|---|
| `OPENAI_API_KEY` in environment | Uses OpenAI — no local model needed |
| `ANTHROPIC_API_KEY` in environment | Uses Anthropic — no local model needed |
| Neither key set | Checks for Ollama; auto-installs it if missing, starts daemon, pulls `qwen2.5:0.5b` (~500 MB, one-time download) |

**Data isolation:** Demo PostgreSQL runs on port 5433 with database `ectoledger_demo`, stored separately from your normal data (`~/.local/share/ectoledger/postgres-demo` on Linux, `~/Library/Application Support/ectoledger/postgres-demo` on macOS). Use `--reset-db --demo` together to wipe it.

> **First run only:** pg-embed Postgres binaries download once (~30 MB). If using Ollama, `qwen2.5:0.5b` downloads once (~500 MB). Subsequent demo starts take seconds.

### 🐳 Docker Demo

No Rust toolchain, no Node.js, no Ollama — just Docker. One command pulls a pre-built image from GitHub Container Registry and starts the full backend stack:

```bash
docker compose -f docker-compose.demo.yml up
```

Then open **http://localhost:3000** in your browser.

| Component | Image | Notes |
|---|---|---|
| PostgreSQL 17 | `postgres:17-alpine` | Isolated DB, data persisted in a named Docker volume |
| Ollama | `ollama/ollama:latest` | Pulls `qwen2.5:0.5b` automatically on first start |
| EctoLedger | `ghcr.io/ectospace/ectoledger:latest` | Pre-built release binary, pulls in seconds |

To stop and remove all data:
```bash
docker compose -f docker-compose.demo.yml down -v
```

**Build from source** (optional — only if you want to test local code changes):
```bash
docker compose -f docker-compose.demo.yml -f docker-compose.build.yml up --build
```

> The Docker demo exposes only the REST API and Observer dashboard — there is no Tauri desktop GUI. Use the `--demo` flag with the native launcher (above) for the full desktop experience.

---

## How-To: First Production Audit

Use this path when you need strong guardrails and verifiable evidence (not just a demo run):

1. Use PostgreSQL backend (`DATABASE_URL=postgres://...`) for full command support.
2. Configure guard settings and keep `GUARD_REQUIRED=true`.
3. Run:

```bash
cargo run -- audit "Audit production deployment configuration" \
  --policy crates/host/policies/iso42001.toml
```

4. Export and verify evidence:

```bash
cargo run -- report <session_id> --format certificate --output audit.elc
./target/release/verify-cert audit.elc
```

5. Optional: anchor the session hash for timestamp non-repudiation.

```bash
cargo run -- anchor-session <session_id>
```

## Troubleshooting

### `audit` command fails immediately

- Confirm backend mode: SQLite does not support `audit`, `orchestrate`, `red-team`, `diff-audit`, `prove-audit`, or `anchor-session`.
- Verify LLM connectivity and API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or Ollama availability).
- If running production settings, check guard variables (`GUARD_REQUIRED`, `GUARD_LLM_BACKEND`, `GUARD_LLM_MODEL`).

### Demo works but production behaves differently

- Demo mode is tuned for fast evaluation and isolated data; production requires explicit guard/policy/backend configuration.
- Re-check `.env` and backend selection before comparing results.
- Validate policy and tripwire settings from the GUI or config files.

### Verification confusion (`verify-session` vs `verify-certificate` vs VC verify)

- `verify-session` validates signed event chain integrity for a session.
- `verify-certificate` / `verify-cert` validates exported `.elc` artifacts offline.
- VC verify endpoints perform structural/expiry checks; for full signature assurances use the documented cryptographic verification API path.

**Shorthand via `make`** (macOS/Linux):

| Command | Description |
|---|---|
| `make start` / `make` | Build + launch backend + GUI (default) |
| `make setup` | First-time build & install only, no servers |
| `make rebuild` | Force rebuild then launch |
| `make backend` | Backend only (no GUI) |
| `make reset-db` | Wipe embedded Postgres data dir (fixes auth failures after partial first run) |
| `make test` | Run Rust unit tests |
| `make test-integration` | Integration tests against ephemeral Postgres (requires Docker) |
| `make check` | Type-check the Svelte/TypeScript GUI |
| `make clean` | Remove all build artifacts |

**Customise your setup** - edit `.env` (created automatically on first launch):

```bash
# Use OpenAI instead of Ollama
LLM_BACKEND=openai
OPENAI_API_KEY=sk-...

# Enable production guard
GUARD_REQUIRED=true
GUARD_LLM_BACKEND=ollama
GUARD_LLM_MODEL=llama3

# Enable SIEM webhook egress
WEBHOOK_URL=https://your-siem.example.com/events
```

---

## Management GUI

`gui/` contains a **Tauri 2 + Svelte 5** desktop application - a native binary for macOS, Windows, and Linux that communicates with the local Axum server over HTTP.

**Design:** Apple-glass glassmorphism - frosted translucent panels, `backdrop-filter: blur`, vibrant purple accents on a deep dark gradient background. On macOS, `vibrancy: "under-window"` is used for native frosted glass.

**Screens:**

| Screen | Content |
|---|---|
| **Dashboard** | Full-width "Test Prompt" textarea + Run button; live metrics panel with real-time refresh |
| **Live Dashboard** | Real-time streaming view of agent cognitive loop activity |
| **Prometheus metrics** | Raw Prometheus metrics endpoint output (under Dashboard) |
| **Sessions** | Session list with status badges; per-session event timeline; one-click `.elc` certificate export |
| **Policies** | TOML policy editor with live syntax validation; save changes to the server in one click |
| **Tripwire** | Configurable structural rules: min justification length, require HTTPS, allowed paths/domains, banned command patterns |
| **Tokens** | RBAC API token management — create, revoke, and list bearer tokens with role-based access control |
| **Webhooks** | Webhook endpoint configuration — add, edit, and test SIEM egress targets |
| **Observer** | Embedded Observer dashboard panel for real-time event monitoring |
| **Testing** | Built-in adversarial testing interface for validating guard and scanner defenses |
| **DevHub** | Developer reference panel with API docs, SDK examples, and integration guides |
| **Setup Wizard** | First-run onboarding wizard for LLM backend, database, and guard configuration |
| **Settings** | LLM backend (Ollama/OpenAI/Anthropic), model selection, and other preferences |

The GUI solves a common operational pain point: the Observer dashboard is embedded inside the application and never closes or requires a browser.

<details>
<summary>Manual GUI commands (advanced)</summary>

```bash
# Development (hot-reload, requires backend running)
cd gui && npm install && npm run tauri dev

# Production bundle
cd gui && npm run tauri build
# Installer at: target/release/bundle/  (the workspace root, not inside gui)
```
</details>

<details>
<summary>Building production GUI installers</summary>

Tauri bundles platform-native installers automatically. Ensure prerequisites are
installed for your target OS, then build from the `gui/` directory:

```bash
cd gui
npm install
npm run tauri build
```

**Output locations** (`target/release/bundle/`):

| Platform | Installer format | Path |
|----------|-----------------|------|
| macOS    | `.dmg` / `.app` | `bundle/dmg/EctoLedger_<version>_aarch64.dmg` |
| Windows  | `.msi` / `.nsis` | `bundle/msi/EctoLedger_<version>_x64_en-US.msi` |
| Linux    | `.deb` / `.AppImage` | `bundle/deb/ectoledger_<version>_amd64.deb` |

**Platform-specific prerequisites:**

- **macOS:** Xcode Command Line Tools (`xcode-select --install`)
- **Windows:** Visual Studio Build Tools with C++ workload, WebView2 (pre-installed on Windows 10+)
- **Linux:** `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev` (or `libappindicator3-dev` on older distros), `librsvg2-dev`
  ```bash
  # Debian/Ubuntu 22.04+
  sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
  ```

**Code-signing (recommended for distribution):**

- macOS: Set `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, and `APPLE_SIGNING_IDENTITY` environment variables, or configure in `gui/src-tauri/tauri.conf.json` under `bundle > macOS`.
- Windows: Use `signtool.exe` on the `.msi` output, or configure Tauri's built-in signing via `TAURI_SIGNING_PRIVATE_KEY`.

For CI-driven builds, configure a `release.yml` GitHub Actions workflow to automate
cross-platform compilation and artifact upload on tag pushes.
</details>

---

## SDKs

### Python SDK

```bash
# Core client only
pip install ectoledger-sdk

# With LangChain support
pip install 'ectoledger-sdk[langchain]'

# With AutoGen support
pip install 'ectoledger-sdk[autogen]'
```

```python
import asyncio
from ectoledger_sdk import LedgerClient

async def main():
    async with LedgerClient("http://localhost:3000") as client:
        session = await client.create_session(goal="Audit Cargo.toml dependencies")
        await client.append_event(session.session_id, {"step": "read", "file": "Cargo.toml"})
        ok = await client.verify_chain(session.session_id)
        print("Chain intact:", ok)
        await client.seal_session(session.session_id)

asyncio.run(main())
```

**LangChain integration** - appends every agent reasoning step to the ledger:

```python
from ectoledger_sdk.langchain import LedgerTool

ledger_tool = LedgerTool(
    session_id="<uuid>",
    base_url="http://localhost:3000",
)
agent_executor = AgentExecutor(agent=agent, tools=[search_tool, ledger_tool])
```

**AutoGen integration** - hooks into reply processing on any `ConversableAgent`:

```python
from ectoledger_sdk.autogen import LedgerHook

hook = LedgerHook(session_id="<uuid>")
hook.attach(my_conversable_agent)
```

See [`sdk/python/README.md`](sdk/python/README.md) for the full API reference.

### TypeScript SDK

```bash
npm install ectoledger-sdk
```

```typescript
import { EctoLedgerClient } from "ectoledger-sdk";

const client = new EctoLedgerClient({ baseUrl: "http://localhost:3000" });

const session = await client.createSession("Summarise quarterly report");
await client.appendEvent(session.id, { step: "retrieved_docs", count: 42 });
const ok = await client.verifyChain(session.id);
await client.sealSession(session.id);

// Export audit certificate as a Blob
const cert = await client.exportCertificate(session.id);
```

Zero external dependencies — uses the native `fetch` API (Node 18+, browsers, Deno, Bun). Fully typed with TypeScript generics. Non-2xx responses throw `EctoLedgerApiError` with `.status` and `.body` properties.

See [`sdk/typescript/README.md`](sdk/typescript/README.md) for the full API reference.

---

## CLI Reference

### `serve` - start the Observer dashboard

```bash
cargo run -- serve
# Observer: http://localhost:3000 (use printed token as ?token=… or Authorization header)
```

| Endpoint | Description |
|---|---|
| `GET /` | Observer dashboard (real-time SSE, content redacted) |
| `GET /metrics` | Prometheus metrics |
| `GET /api/metrics/security` | Security events JSON (injection attempts, denials, aborts, chain failures) |
| `GET /api/approvals/<session_id>` | Pending approval gate state |
| `POST /api/approvals/<session_id>` | Submit an approval decision |

### `audit` - run an AI agent audit

```bash
# Basic audit
cargo run -- audit "Read server_config.txt"

# With a compliance policy
cargo run -- audit "Audit Cargo.toml dependencies" \
    --policy crates/host/policies/soc2-audit.toml

# SQLite backend - no infrastructure required
DATABASE_URL=sqlite://ledger.db \
    cargo run -- audit "Quick local audit"

# Cloud credential injection
AGENT_CLOUD_CREDS_FILE=~/.ectoledger/aws-audit.json \
    cargo run -- audit "Audit S3 bucket policy for public exposure" \
    --policy crates/host/policies/soc2-audit.toml

# Interactive approval gates (stdin - no dashboard required)
cargo run -- audit "Run nmap scan" --policy gate_policy.toml --interactive

# Development only - disable guard (requires explicit confirmation flag)
cargo run -- audit "Quick read" --no-guard --no-guard-confirmed
```

### `report` - export session reports

```bash
# Supported formats: json (default), sarif, html, certificate (.elc),
#                   github_actions, gitlab_codequality
cargo run -- report <session_id> --format sarif    --output report.sarif
cargo run -- report <session_id> --format html     --output report.html
cargo run -- report <session_id> --format certificate --output audit.elc
cargo run -- report <session_id> --format github_actions
cargo run -- report <session_id> --format gitlab_codequality --output codequality.json
```

Exits with code `1` when any finding is `high` or `critical` severity - suitable as a CI gate.

### `verify-session` - verify Ed25519 event signatures

```bash
cargo run -- verify-session <session_id>
```

### `verify-certificate` - offline certificate verification

```bash
cargo run -- verify-certificate audit.elc

# Standalone binary (no Rust, PostgreSQL, or Ollama required - ship to auditors)
./target/release/verify-cert audit.elc
```

### `replay` - replay a session

```bash
cargo run -- replay <session_id>
cargo run -- replay <session_id> --inject-observation "seq=3:injected content"
```

Useful for debugging and adversarial testing.

### `diff-audit` - compare two sessions

```bash
cargo run -- diff-audit \
    --baseline <session_id> \
    --current  <session_id> \
    [--output  diff.json]
```

### `orchestrate` - multi-agent security audit

Runs three sequential sub-agents - **Recon → Analysis → Verify** - each in an independent ledger session. On completion, a `CrossLedgerSeal` event with a length-prefixed SHA-256 commitment is appended to every session, cryptographically binding them together without merging their event chains.

> **Security note:** The cross-ledger seal hash uses length-prefixed encoding (`len(tip) || tip`) for each input to prevent boundary-collision attacks where `sha256("AB" || "C")` would equal `sha256("A" || "BC")` without prefixes.

```bash
cargo run -- orchestrate "Audit the Rust dependency tree for known vulnerabilities"
cargo run -- orchestrate "Audit Nginx config" \
    --policy shared_policy.toml --max-steps 25

# Per-role policy overrides via environment variables:
ECTO_RECON_POLICY=/etc/ectoledger/strict-recon.toml \
ECTO_VERIFY_POLICY=/etc/ectoledger/strict-verify.toml \
    cargo run -- orchestrate "Audit production Kubernetes configuration"
```

**Policy resolution order (highest priority first):**
1. Role-specific env var (`ECTO_RECON_POLICY`, `ECTO_ANALYSIS_POLICY`, `ECTO_VERIFY_POLICY`)
2. Shared `--policy` file (applies to all roles if role-specific var is not set)
3. Built-in hardcoded defaults

| Sub-agent | Allowed actions | Notes |
|---|---|---|
| **Recon** | `read_file`, `run_command` | `http_get` is forbidden |
| **Analysis** | `read_file` | Receives Recon observations as goal context; produces findings |
| **Verify** | `read_file` | Independently confirms each Analysis finding before completing |

### `anchor-session` - Bitcoin or EVM timestamp

```bash
# Bitcoin via OpenTimestamps (default)
cargo run -- anchor-session <session_id>

# EVM chain (Ethereum, Polygon, or any EVM-compatible network)
EVM_RPC_URL=https://mainnet.infura.io/v3/<key> \
EVM_CHAIN_ID=1 \
EVM_CONTRACT_ADDRESS=0x... \
EVM_PRIVATE_KEY=0x... \
    cargo run -- anchor-session <session_id> --chain ethereum
```

Submits the ledger tip hash to the OTS aggregator pool (Bitcoin path) or calls `anchor(bytes32)` on the deployed `EctoLedgerAnchor` smart contract (EVM path). An `Anchor` event is appended to the session in both cases, embedding the proof and transaction hash for independent verification.

EVM anchoring is enabled in all pre-built binaries by default (`evm` feature is on). No `--features evm` flag is required.

### `red-team` - adversarial defense testing

```bash
cargo run -- red-team --target-session <session_id>
cargo run -- red-team --target-session <session_id> \
    --attack-budget 100 --output red-team-report.json
```

Generates injection payloads via LLM and tests each against the output scanner and tripwire in isolation. Exit code `1` when any payload passes all checks - integrate directly into CI. For single-payload manual testing, use `replay --inject-observation` instead.

### `prove-audit` - SP1 zero-knowledge proof

```bash
cargo build --features zk
cargo run --features zk -- prove-audit <session_id>
cargo run --features zk -- prove-audit <session_id> \
    --policy crates/host/policies/soc2-audit.toml --output audit.elc
```

Generates an SP1 ZK validity proof over the full event hash chain and policy commitment. A verifier can confirm policy compliance without access to raw event payloads - the right tool for regulated industries (healthcare, finance) where audited data cannot leave the client's perimeter. For all other use cases, the standard `.elc` certificate (five-pillar verification) provides sufficient cryptographic provenance without proof generation overhead.

---

## Audit Certificates (`.elc`)

Every completed session can be exported as a self-contained `.elc` file that is verifiable completely offline against five independent guarantees:

| Pillar | Guarantee |
|---|---|
| **Ed25519 signature** | Tamper-resistance - entire payload signed with session keypair; public key embedded in certificate; no trusted third party required |
| **SHA-256 hash chain** | Gap and mutation detection - any insertion, deletion, or modification anywhere in the chain is detected without replaying execution |
| **Merkle inclusion proofs** | Efficient finding spot-checks - each finding carries a sibling-hash path to the Merkle root built over all event `content_hash` values; O(log n) verification |
| **OpenTimestamps / Bitcoin anchor** | Temporal non-repudiation - proves the audit completed before block N, verifiable by anyone without trust in the issuer |
| **Goal hash integrity** | Session integrity - `sha256(goal)` stored at creation; re-verified on every event; agent goal cannot be redirected mid-session |

A sixth proof (SP1 ZK validity proof) is available when built with `--features zk`.

The `verify-cert` binary is a static, dependency-free binary (< 5 MB) designed to be shipped to customers, auditors, or regulators. It requires no Rust toolchain, PostgreSQL, or Ollama.

---

## Decentralized Identity and W3C Verifiable Credentials

Sessions and `.elc` certificates carry an optional `session_did` field. When present, it contains a `did:key:` URI derived from the session Ed25519 keypair - providing a W3C-compatible, self-sovereign identity anchor for each audit session that can be verified by any standards-compliant DID resolver without calling back to the EctoLedger instance.

### Verifiable Credential issuance

When an agent session completes, EctoLedger automatically issues a W3C VC-JWT that encodes the session identity, goal, policy hash, and completion status in a tamper-evident, portable credential:

```json
{
  "iss": "did:key:z...",
  "sub": "did:key:z...",
  "jti": "urn:uuid:<session-id>",
  "iat": 1740000000,
  "exp": 1747776000,
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://ectoledger.security/2026/credentials/v1"],
    "type": ["VerifiableCredential", "EctoLedgerSessionCredential"],
    "credentialSubject": {
      "id": "did:key:z...",
      "sessionId": "<uuid>",
      "goal": "Audit S3 bucket policies",
      "policyHash": "sha256:<hex>",
      "status": "completed",
      "issuedAt": "2026-02-22T03:00:00Z"
    }
  }
}
```

### REST endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/sessions/{id}/vc` | `GET` | Retrieve the VC-JWT and decoded payload for a completed session |
| `/api/sessions/{id}/vc/verify` | `GET` | Resolve and verify the VC-JWT (structural integrity + expiry check) |

**Retrieve a session credential:**

```bash
curl -H "Authorization: Bearer $OBSERVER_TOKEN" \
    http://localhost:3000/api/sessions/<session-id>/vc | jq .
```

**Verify (resolve) a session credential:**

```bash
curl -H "Authorization: Bearer $OBSERVER_TOKEN" \
    http://localhost:3000/api/sessions/<session-id>/vc/verify | jq .
# → { "valid": true, "vc_payload": { ... } }
```

The verify endpoint performs:
1. **Structural validation** - checks that the JWT has the required `header.payload.signature` format.
2. **Expiry check** - rejects credentials whose `exp` claim is in the past (default lifetime: 90 days).
3. **Signature verification** - **not performed by this REST endpoint**; for full Ed25519 signature verification, use the `verify_vc_jwt` Rust API in `crates/host/src/verifiable_credential.rs`.

### Programmatic verification (Rust)

```rust
use ectoledger::verifiable_credential::{build_vc_jwt, verify_vc_jwt, VcVerifyError};

// Verify a VC-JWT with the session signing key
let vk = signing_key.verifying_key();
match verify_vc_jwt(&vc_jwt, Some(&vk)) {
    Ok(payload) => println!("Valid credential: {}", payload),
    Err(VcVerifyError::Expired) => eprintln!("Credential has expired"),
    Err(VcVerifyError::InvalidSignature) => eprintln!("Signature mismatch"),
    Err(e) => eprintln!("Verification error: {}", e),
}
```

---

## Webhooks and SIEM Integration

EctoLedger emits structured events to any HTTP endpoint - configure once and receive real-time notifications for all security-relevant agent decisions.

**Event kinds:**

| Kind | Trigger |
|---|---|
| `Observation` | Agent produces a flagged or aborted observation |
| `GuardDenial` | Guard process returns `DENY` for a proposed intent |
| `TripwireRejection` | Tripwire rejects an action (path escape, blocked domain, dangerous command, missing justification) |

**Configuration:**

```bash
WEBHOOK_URL=https://siem.corp.example/ingest
WEBHOOK_BEARER_TOKEN=<token>
SIEM_FORMAT=json                    # json (default) | cef | leef
WEBHOOK_INCLUDE_GUARD=true          # default true - include GuardDenial events
WEBHOOK_INCLUDE_TRIPWIRE=true       # default true - include TripwireRejection events
```

CEF and LEEF payloads include `event_kind`, `session_id`, `payload_hash`, and timestamp. These formats are directly ingested by Splunk, IBM QRadar, and ArcSight.

---

## Policy System

### Industry policy packs

| File | Standard | Focus |
|---|---|---|
| `crates/host/policies/soc2-audit.toml` | SOC 2 Type II | Access management, logging, encryption at rest |
| `crates/host/policies/pci-dss-audit.toml` | PCI-DSS v4.0 | Cardholder data scope, network segmentation |
| `crates/host/policies/owasp-top10.toml` | OWASP Top 10 2021 | Injection, broken auth, crypto failures, SSRF, misconfiguration |
| `crates/host/policies/iso42001.toml` | ISO 42001:2023 | AI management system - 14 controls across 7 clauses |

```bash
cargo run -- audit "Audit SOC2 controls" \
    --policy crates/host/policies/soc2-audit.toml

cargo run -- audit "Audit cardholder data environment" \
    --policy crates/host/policies/pci-dss-audit.toml

cargo run -- audit "Audit web application for OWASP Top 10" \
    --policy crates/host/policies/owasp-top10.toml

cargo run -- audit "ISO 42001 AI system audit" \
    --policy crates/host/policies/iso42001.toml
```

### Policy DSL

The TOML policy file supports four rule categories. All sections are optional.

```toml
name = "example-policy"
max_steps = 30

# 1. Allowed / forbidden action lists
[[allowed_actions]]
action = "read_file"

[[forbidden_actions]]
action = "http_get"

# 2. Conditional command rules - evaluated in order; first match wins
[[command_rules]]
program = "curl"
arg_pattern = "^https://(internal\\.corp|api\\.example)\\.com"
decision = "allow"

[[command_rules]]
program = "curl"
arg_pattern = ".*"
decision = "deny"
reason = "curl permitted only to approved internal domains"

# 3. Observation content rules - applied after each execution
[[observation_rules]]
pattern = "(?i)(password|secret|api.key)\\s*[:=]\\s*\\S+"
action = "redact"       # redact | flag | abort
label = "credential_leak"

# 4. Approval gate triggers - policy-driven human-in-the-loop
[[approval_gates]]
trigger = "action == 'run_command' && command_contains('nmap')"
require_approval = true
timeout_seconds = 300
on_timeout = "deny"
```

**Rule types:**

- **`command_rules`** - Applied to `run_command` actions only. `program` matches the first token; `arg_pattern` is a regex over remaining arguments. Decisions: `allow`, `deny`, `require_approval`.
- **`observation_rules`** - Applied to raw observation text after every tool execution. `redact` replaces matches with `[REDACTED:<label>]`; `flag` logs a warning and continues; `abort` terminates the session.
- **`approval_gates`** - Boolean trigger expressions (`action == 'x'`, `command_contains('y')`, joined by `&&`). When triggered, an `ApprovalRequired` event is appended and the agent waits for a human decision via the REST API or `--interactive` `stdin`.

**Additional trigger predicates:**

| Predicate | Example |
|---|---|
| `path_extension_matches(ext)` | `path_extension_matches('.key')` |
| `url_host_in_cidr(cidr)` | `url_host_in_cidr('10.0.0.0/8')` |
| `command_matches_regex(pattern)` | `command_matches_regex('^nmap\\s')` |

### Plugin system - third-party security tools

```toml
[[plugins]]
name = "trivy"
binary = "trivy"
description = "Container and filesystem vulnerability scanner"
arg_patterns = ["^image\\s+\\S+", "^fs\\s+\\."]
env_passthrough = ["TRIVY_USERNAME", "TRIVY_PASSWORD"]

[[plugins]]
name = "semgrep"
binary = "semgrep"
description = "Static analysis"
arg_patterns = ["^--config\\s+\\S+\\s+\\."]
env_passthrough = []
```

Plugin binaries are added to the executor allowlist only when declared in the policy file. `env_passthrough` injects named host environment variables into the plugin child process exclusively - the parent environment is never modified.

---

## Compliance: ISO 42001:2023

`crates/host/policies/iso42001.toml` provides 14 machine-readable controls mapped to ISO 42001:2023 clauses (4.1 through 10.1), loadable directly as a policy pack.

`docs/iso42001.md` provides the full compliance whitepaper: clause-by-clause mapping table, cryptographic controls reference (hash chain formula, Ed25519 signing, DID, Merkle), governance architecture diagram, and deployment checklist.

---

## Cloud Credential Injection

Safely audit AWS, GCP, Azure, or Kubernetes environments with ephemeral credentials. Credentials are injected only into matching cloud CLI child processes and never appear in the parent environment or audit logs.

**Credential file format (`~/.ectoledger/aws-audit.json`):**

```json
{
  "name": "aws-audit-role",
  "provider": "aws",
  "env_vars": {
    "AWS_ACCESS_KEY_ID": "ASIA...",
    "AWS_SECRET_ACCESS_KEY": "...",
    "AWS_SESSION_TOKEN": "..."
  }
}
```

```bash
AGENT_CLOUD_CREDS_FILE=~/.ectoledger/aws-audit.json \
    cargo run -- audit "Audit S3 bucket policy for public exposure"
```

Supported providers (added to executor allowlist only when credentials are present): `aws`, `gcloud`, `az`, `kubectl`, `terraform`, `eksctl`, `helm`. The credential `name` and `provider` are recorded as an auditable `Thought` event at session start; credential values are never logged.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgres://ectoledger:ectoledger@localhost:5432/ectoledger` | Connection string - `postgres://…` or `sqlite://…` |
| `OBSERVER_TOKEN` | *(random, printed at startup)* | Bearer token for Observer dashboard access |
| `LLM_BACKEND` | `ollama` | Primary LLM: `ollama`, `openai`, `anthropic` |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `mistral` | Ollama model name |
| `GUARD_LLM_BACKEND` | - | Guard process LLM backend (use a different model from primary) |
| `GUARD_LLM_MODEL` | - | Guard process model name |
| `GUARD_REQUIRED` | `true` | Set `true` in production - startup fails if Guard env is missing |
| `AGENT_ALLOWED_DOMAINS` | - | Comma-separated domains permitted by Tripwire `http_get` |
| `AGENT_MAX_STEPS` | `20` | Maximum agent loop iterations |
| `AGENT_LLM_ERROR_LIMIT` | `5` | Circuit-breaker threshold for consecutive LLM errors |
| `AGENT_GUARD_DENIAL_LIMIT` | `3` | Circuit-breaker threshold for consecutive Guard denials |
| `ECTO_DATA_DIR` | `.ectoledger/keys/` | Directory for encrypted session key files |
| `ECTO_KEY_PASSWORD` | - | Session key password (skips interactive password prompt) |
| `AGENT_CLOUD_CREDS_FILE` | - | Path to JSON cloud credential file |
| `WEBHOOK_URL` | - | HTTP endpoint for async SIEM/webhook egress |
| `WEBHOOK_BEARER_TOKEN` | - | Bearer token appended to webhook requests |
| `SIEM_FORMAT` | `json` | Webhook egress format: `json`, `cef`, `leef` |
| `WEBHOOK_INCLUDE_GUARD` | `true` | Emit `GuardDenial` events to the configured webhook |
| `WEBHOOK_INCLUDE_TRIPWIRE` | `true` | Emit `TripwireRejection` events to the configured webhook |

---

## Running Tests

**Unit tests (no database required):**

```bash
cargo test
```

**Integration tests - PostgreSQL:**

```bash
# Ephemeral Docker container (recommended)
./scripts/test-integration.sh

# Against an existing instance
DATABASE_URL=postgres://... cargo test --features integration
```

**Integration tests - SQLite:**

```bash
DATABASE_URL=sqlite://test.db cargo test --features integration
```

### Adversarial Prompt Injection Tests

`crates/host/tests/adversarial_guards.rs` is a native Rust test module with **93 adversarial payloads** that exercise the output scanner and tripwire layers directly — no running server, no database, no network, no external dependencies.

```bash
# Run all adversarial tests:
cargo test -p ectoledger --test adversarial_guards

# Run a single category:
cargo test -p ectoledger --test adversarial_guards goal_injection
cargo test -p ectoledger --test adversarial_guards tripwire_bypass
cargo test -p ectoledger --test adversarial_guards output_scanner_evasion
cargo test -p ectoledger --test adversarial_guards semantic_guard
cargo test -p ectoledger --test adversarial_guards ancillary
```

#### Cross-platform OS targeting

OS-specific payloads (e.g. `/etc/shadow` on Linux, `SAM` on Windows, Keychain on macOS) are gated with `#[cfg(target_os = "...")]` so they compile and run only on the relevant platform — zero runtime overhead, no OS detection needed.

| Platform | Tests compiled | OS-gated tests |
|---|---|---|
| **macOS** | 88 | 1 mac-only + 83 agnostic |
| **Linux** | 91 | 3 linux-only + 83 agnostic |
| **Windows** | 91 | 3 windows-only + 83 agnostic |
| **All platforms** | 93 | All of the above |

#### Payload categories

| # | Category | Count | Target Guard Layer |
|---|---|---|---|
| 1 | `goal_injection` | 30 | Output scanner (regex + structural JSON + base64 decode) |
| 2 | `tripwire_bypass` | 23 | Tripwire (shlex tokenization, metacharacter ban, banned commands, path traversal, executable allowlist) |
| 3 | `output_scanner_evasion` | 17 | Output scanner (all passes: regex, structural JSON/AST, strict schema, base64) |
| 4 | `semantic_guard` | 12 | Output scanner + tripwire (role injection, continuation markers, hijack keys) |
| 5 | `ancillary` | 10 | Tripwire (URL validation, domain allowlist, HTTPS enforcement, unknown actions, justification) |

#### How it works

Each test calls `scan_observation()` or `Tripwire::validate()` directly as pure functions — no I/O, no async runtime. This means the adversarial test suite:

- Runs in **< 0.1 seconds** (no server startup)
- Requires **zero external dependencies** (no Python, npm, or Docker)
- Works **offline** on any platform with a Rust toolchain
- Integrates naturally with `cargo test` and CI pipelines

---

## Security Warnings

### macOS - Missing Network Isolation

Apple's Seatbelt sandbox does **not** provide per-process network isolation.  Child processes spawned by the executor inherit full outbound network access.  This is an architectural limitation of macOS, not a bug in EctoLedger.

**For production macOS deployments**, apply edge network filtering to restrict outbound traffic from the EctoLedger process:

- Deploy a host-level firewall (pfctl, Little Snitch, Lulu) or corporate forward proxy.
- Configure `AGENT_ALLOWED_DOMAINS` to restrict `http_get` destinations.
- Use Docker Desktop for Mac (`ECTO_DOCKER_IMAGE=alpine:3.19`) to gain `--network=none` isolation for `run_command` actions.
- Use a local DNS sinkhole (dnsmasq / Unbound) to block DNS-tunnelling exfiltration.

See [`SANDBOX_CROSS_PLATFORM.md`](SANDBOX_CROSS_PLATFORM.md) for the full cross-platform security comparison.

---

## Optional Cargo Features

Beyond the defaults (`sandbox` + `evm`), the following optional features are available:

| Feature | Flag | Description |
|---|---|---|
| **ECDSA VC signing** | `--features vc-ecdsa` | P-256 (ECDSA) VC signing alongside the default Ed25519 (EdDSA) scheme |
| **SQLCipher encryption** | `--features sqlcipher` | At-rest encryption for the SQLite backend; set `ECTOLEDGER_SQLCIPHER_KEY` |
| **BLAKE3 hashing** | `--features hash-blake3` | Use BLAKE3 instead of SHA-256 for new events (falls back to SHA-256 for older events) |
| **OS keychain** | `--features keychain` | Store signing keys in the platform keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| **Enclave IPC** | `--features enclave` | X25519 + ChaCha20-Poly1305 IPC for the guard unikernel |
| **Remote attestation** | `--features enclave-remote` | COSE-based remote attestation for enclave guard (includes `enclave`) |
| **Apple Hypervisor** | `--features sandbox-apple-enclave` | Boot the guard unikernel on Apple Hypervisor (macOS Silicon; includes `enclave`) |
| **Firecracker microVM** | `--features sandbox-firecracker` | Firecracker-based execution isolation (Linux + KVM required) |
| **ZK proofs** | `--features zk` | SP1 RISC-V zero-knowledge proof generation for provable policy compliance |
| **Windows icon** | `--features embed-resource` | Embed Windows icon / version-info resource into binaries |

> **Note:** The `sandbox` feature activates Linux-specific Landlock LSM + seccomp-BPF. On macOS and Windows, OS-level sandboxing (Seatbelt / Job Objects) is compiled unconditionally — the `sandbox` flag is a no-op on those platforms.

---

## Project Layout

```
EctoLedger/
├── ectoledger-mac           # macOS launcher (bash)
├── ectoledger-linux         # Linux launcher (bash)
├── ectoledger-win.ps1       # Windows launcher (PowerShell)
├── crates/
│   ├── core/               # Pure logic - no I/O; shared with the SP1 zkVM guest
│   │   └── src/
│   │       ├── hash.rs         # SHA-256 helpers (sha256_hex, compute_content_hash)
│   │       ├── merkle.rs       # Binary Merkle tree, inclusion proofs
│   │       ├── intent.rs       # ProposedIntent, ValidatedIntent
│   │       ├── policy.rs       # PolicyEngine, all policy structs, policy_hash_bytes
│   │       └── schema.rs       # SP1 zkVM protocol types: ChainEvent, GuestInput, GuestOutput
│   ├── guest/              # SP1 RISC-V zkVM guest (compiled separately with --features zk)
│   │   └── src/main.rs     # Verifies genesis, hash chain, Merkle root, policy patterns
│   ├── guard_unikernel/    # Bare-metal guard unikernel (aarch64-unknown-none)
│   │   └── src/main.rs     # Standalone guard binary for hardware enclaves
│   ├── ledger-api/         # Pluggable LedgerBackend trait - standalone, no host dependency
│   │   └── src/lib.rs      # LedgerBackend, LedgerError, LedgerEvent, Session, AppendResult
│   └── host/               # Main application: ectoledger, guard-worker, verify-cert
│       ├── src/
│       │   ├── main.rs             # CLI entry point
│       │   ├── agent.rs            # Cognitive loop
│       │   ├── ledger.rs           # Module root - re-exports postgres free functions
│       │   ├── ledger/
│       │   │   ├── postgres.rs     # PostgresLedger implementing LedgerBackend
│       │   │   └── sqlite.rs       # SqliteLedger implementing LedgerBackend
│       │   ├── server.rs           # Axum server (Observer, SSE, metrics, approvals API)
│       │   ├── orchestrator.rs     # Multi-agent: Recon → Analysis → Verify + CrossLedgerSeal
│       │   ├── guard.rs            # Guard trait; in-process fallback
│       │   ├── guard_process.rs    # Spawns guard-worker, communicates via stdin/stdout JSON
│       │   ├── tripwire.rs         # Structural intent validation
│       │   ├── output_scanner.rs   # Hybrid scanner (13 regex + 8 exfil patterns + structural JSON/AST)
│       │   ├── policy.rs           # Host-side policy loader
│       │   ├── certificate.rs      # .elc: Merkle, OTS, Ed25519, optional SP1 ZK proof
│       │   ├── report.rs           # SARIF 2.1, HTML, GitHub Actions, GitLab CQ, certificate
│       │   ├── webhook.rs          # Async SIEM egress (JSON/CEF/LEEF); EgressKind enum
│       │   ├── signing.rs          # Ed25519 session keypair and per-event signing
│       │   ├── cloud_creds.rs      # Ephemeral cloud credential injection
│       │   ├── sandbox.rs          # Linux Landlock/seccomp, macOS Seatbelt, Windows Job Object
│       │   ├── approvals.rs        # Approval gate state, session pause/resume
│       │   ├── ots.rs              # OpenTimestamps integration
│       │   ├── red_team.rs         # Adversarial payload generation and defense testing
│       │   ├── snapshot.rs         # Agent state snapshots
│       │   ├── executor.rs         # run_command / read_file / http_get
│       │   ├── config.rs           # Environment variable loading, settings persistence
│       │   ├── metrics.rs          # Prometheus metrics and counters
│       │   ├── compensation.rs     # Compensating-action planner for rollback
│       │   ├── schema.rs           # Event types: Genesis, Thought, Action, Observation, …
│       │   ├── diff_audit.rs       # Cross-session diff comparisons
│       │   ├── verifiable_credential.rs  # W3C VC-JWT issuance and verification (Ed25519 / did:key)
│       │   ├── evm_anchor.rs       # Ethereum on-chain session hash anchoring (feature: evm)
│       │   ├── llm/                # LLM backends: Ollama, OpenAI, Anthropic
│       │   └── bin/                # guard_worker.rs, verify_cert.rs
│       ├── migrations/         # PostgreSQL migrations (sqlx)
│       │   └── sqlite/         # SQLite migrations (001–005)
│       ├── tests/
│       │   ├── adversarial_guards.rs           # 93 adversarial prompt injection tests (pure Rust, no I/O)
│       │   └── cross_platform_cmd_guards.rs    # Windows CMD + Linux host injection guard tests
│       └── policies/           # Policy packs: soc2, pci-dss, owasp-top10, iso42001
├── assets/
│   ├── ectoLedger-Logo.webp # README logo
│   └── el-logo.webp          # Icon source (icons generated via npm run icon:generate)
├── scripts/
│   ├── test-integration.sh         # Integration test harness (Docker Postgres)
│   ├── setup-firecracker.sh        # Firecracker microVM setup (Linux/KVM)
│   └── provision-firecracker.sh    # Firecracker provisioning with custom prefix
├── gui/                    # Tauri 2 + Svelte 5 management GUI
│   ├── scripts/
│   │   └── generate-icons.mjs   # Generates Tauri icons from assets/el-logo.webp
│   ├── src/
│   │   ├── App.svelte              # Root layout - three-tab glassmorphic shell
│   │   └── lib/
│   │       ├── Sidebar.svelte      # Navigation sidebar
│   │       ├── Dashboard.svelte    # Test Prompt panel + live metrics
│   │       ├── LiveDashboard.svelte # Real-time streaming agent activity view
│   │       ├── MetricsView.svelte  # Prometheus metrics tab
│   │       ├── Sessions.svelte     # Session browser, event viewer, certificate export
│   │       ├── PolicyEditor.svelte # TOML policy editor with live validation
│   │       ├── TripwireView.svelte # Tripwire config (paths, domains, commands, justification)
│   │       ├── TokensView.svelte   # RBAC API token management
│   │       ├── WebhooksView.svelte # Webhook/SIEM egress configuration
│   │       ├── ObserverPanel.svelte # Embedded Observer dashboard panel
│   │       ├── TestingView.svelte  # Adversarial testing interface
│   │       ├── DevHub.svelte       # Developer reference and integration guides
│   │       ├── SetupWizard.svelte  # First-run onboarding wizard
│   │       └── Settings.svelte     # LLM backend and model settings
│   └── src-tauri/          # Tauri 2 Rust backend (9 HTTP-proxy Tauri commands)
├── sdk/
│   ├── python/             # Python SDK - pip install ectoledger-sdk
│   │   └── ectoledger_sdk/
│   │       ├── client.py       # LedgerClient (httpx + pydantic)
│   │       ├── models.py       # Session, LedgerEvent, AppendResult, MetricsSummary
│   │       ├── langchain/      # LedgerTool (langchain_core BaseTool)
│   │       └── autogen/        # LedgerHook (ConversableAgent reply hook)
│   └── typescript/         # TypeScript SDK - npm install ectoledger-sdk
│       └── src/
│           ├── client.ts       # EctoLedgerClient (native fetch, zero dependencies)
│           ├── models.ts       # Typed interfaces
│           └── index.ts        # Barrel export
├── contracts/
│   └── EctoLedgerAnchor.sol  # EVM smart contract for on-chain session hash anchoring
├── docs/
│   ├── schema.md           # Event schema reference
│   ├── iso42001.md         # ISO 42001:2023 compliance whitepaper
│   ├── sandbox-parity.md   # Sandbox feature parity matrix
│   └── sandbox-verification-report.md  # Sandbox verification test results
├── SANDBOX_CROSS_PLATFORM.md  # Cross-platform sandbox comparison + macOS security warning
└── audit_policy.example.toml   # Annotated example policy file
```

---

## Licensing

Apache 2.0 — use it freely for personal, internal, commercial, research, and open-source purposes. See [LICENSE](LICENSE) for the full text.

For enterprise consulting, custom integrations, or support SLAs, contact [ectoledger@pm.me](mailto:ectoledger@pm.me).
