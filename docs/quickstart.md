# EctoLedger — Quickstart

Get from zero to your first cryptographically sealed AI audit in under 3 minutes.

---

## 1. Prerequisites

| Tool | Install | Required? |
|---|---|---|
| **Rust 1.94+** | [rustup.rs](https://rustup.rs/) | Yes — all builds |
| **Docker Desktop** | [docker.com](https://www.docker.com/products/docker-desktop/) | Docker demo, PostgreSQL backend, integration tests — not required for `--demo` launcher mode or SQLite mode |
| **Node.js 20+** | [nodejs.org](https://nodejs.org/) | Only for the desktop GUI |
| **An LLM** | [Ollama](https://ollama.com/) (local) or an OpenAI / Anthropic API key | Yes — powers the agent |

---

## 2. Clone & Launch

### One-command start (recommended)

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

The launcher script:
1. Checks prerequisites (`cargo`, `node`, `npm`; warns if Ollama isn't running)
2. Creates a `.env` with safe dev defaults on first run
3. Builds the Rust binary (skipped on subsequent runs)
4. Installs npm packages for the GUI
5. Starts the backend server on `http://127.0.0.1:3000`
6. Opens the Tauri desktop GUI with hot-reload

Press **Ctrl+C** to stop everything.

### Zero-config demo

Want to see it in action without any setup?

```bash
./ectoledger-mac --demo      # macOS
./ectoledger-linux --demo    # Linux
.\ectoledger-win.ps1 -demo   # Windows
```

This auto-provisions an embedded PostgreSQL, installs Ollama + a lightweight model if needed, and seeds a mock audit session so you can watch the cognitive loop live.

### Make shortcuts (macOS/Linux)

| Command | What it does |
|---|---|
| `make` or `make start` | Build + launch backend + GUI |
| `make setup` | First-time build only, no servers |
| `make backend` | Backend server only (no GUI) |
| `make test` | Run all Rust unit tests |
| `make clean` | Remove build artifacts |

---

## 3. Choose Your Backend

| Backend | Setup | Connection string |
|---|---|---|
| **SQLite** (simplest) | Nothing — zero infrastructure | `DATABASE_URL=sqlite://ledger.db` |
| **PostgreSQL** (default) | Docker auto-provisions a container | `DATABASE_URL=postgres://ectoledger:ectoledger@localhost:5432/ectoledger` |

SQLite is perfect for getting started fast. PostgreSQL is needed for `audit`, `orchestrate`, `diff-audit`, `red-team`, `prove-audit`, and `anchor-session`.

Switch at any time by changing `DATABASE_URL` in your `.env` file.

---

## 4. Configure an LLM

Edit the `.env` file (auto-created on first launch):

**Option A — Ollama (local, free):**
```bash
LLM_BACKEND=ollama
OLLAMA_MODEL=mistral
# Start Ollama: ollama serve
# Pull model:   ollama pull mistral
```

**Option B — OpenAI:**
```bash
LLM_BACKEND=openai
OPENAI_API_KEY=sk-...
```

**Option C — Anthropic:**
```bash
LLM_BACKEND=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

---

## 5. Your First Audit

### Run the audit

```bash
# With PostgreSQL (default)
cargo run -- audit "Read server_config.txt"

# With SQLite — zero infrastructure
DATABASE_URL=sqlite://ledger.db cargo run -- serve
# (then use the GUI or SDK to create sessions)
```

### View the dashboard

The server prints an `OBSERVER_TOKEN` on startup. Open:

```
http://localhost:3000?token=<printed-token>
```

Or use the Tauri desktop GUI which connects automatically.

### Export a certificate

```bash
cargo run -- report <session_id> --format certificate --output audit.elc
```

### Verify offline

```bash
# With cargo
cargo run -- verify-certificate audit.elc

# Or use the standalone binary (ship to auditors — no Rust/Postgres/Ollama needed)
./target/release/verify-cert audit.elc
```

---

## 6. Your First Orchestration

Run a multi-agent security audit (Recon → Analysis → Verify):

```bash
cargo run -- orchestrate "Audit the Rust dependency tree for known vulnerabilities"
```

Each sub-agent runs in its own ledger session. On completion, a `CrossLedgerSeal` cryptographically binds all sessions together.

---

## 7. Apply a Compliance Policy

```bash
# SOC 2
cargo run -- audit "Audit access controls" \
    --policy crates/host/policies/soc2-audit.toml

# OWASP Top 10
cargo run -- audit "Audit web app security" \
    --policy crates/host/policies/owasp-top10.toml

# ISO 42001 (AI management)
cargo run -- audit "ISO 42001 AI system audit" \
    --policy crates/host/policies/iso42001.toml

# PCI-DSS
cargo run -- audit "Audit cardholder data environment" \
    --policy crates/host/policies/pci-dss-audit.toml
```

---

## 8. SDK Integration

### Python

```bash
pip install -e ./sdk/python
```

```python
import asyncio
from ectoledger_sdk import LedgerClient

async def main():
    async with LedgerClient("http://localhost:3000") as client:
        session = await client.create_session(goal="Audit Cargo.toml")
        await client.append_event(session.session_id, {"step": "read", "file": "Cargo.toml"})
        ok = await client.verify_chain(session.session_id)
        print("Chain intact:", ok)
        await client.seal_session(session.session_id)

asyncio.run(main())
```

LangChain and AutoGen integrations are also available — see [sdk/python/README.md](../sdk/python/README.md).

### TypeScript

```bash
npm install ectoledger-sdk
```

```typescript
import { EctoLedgerClient } from "ectoledger-sdk";

const client = new EctoLedgerClient({ baseUrl: "http://localhost:3000" });
const session = await client.createSession("Summarise report");
await client.appendEvent(session.id, { step: "retrieved_docs" });
const ok = await client.verifyChain(session.id);
await client.sealSession(session.id);
```

Zero external dependencies — uses native `fetch` (Node 18+, browsers, Deno, Bun). See [sdk/typescript/README.md](../sdk/typescript/README.md).

---

## 9. Production Checklist

Before deploying to production, review these settings in `.env`:

- [ ] **`GUARD_REQUIRED=true`** — enforce dual-LLM guard on every intent
- [ ] **`GUARD_LLM_BACKEND` / `GUARD_LLM_MODEL`** — configure the guard LLM (use a different model from primary)
- [ ] **`OBSERVER_TOKEN`** — set explicitly (don't rely on auto-generated)
- [ ] **`WEBHOOK_URL`** — point to your SIEM for real-time security event egress
- [ ] **`WEBHOOK_HMAC_SECRET`** — enable HMAC signing for webhook integrity
- [ ] **`AGENT_ALLOWED_DOMAINS`** — restrict `http_get` to known-good domains
- [ ] **`DATABASE_URL`** — use PostgreSQL for multi-instance deployments
- [ ] Review [SANDBOX_CROSS_PLATFORM.md](../SANDBOX_CROSS_PLATFORM.md) for platform-specific isolation

---

## 10. Running Tests

```bash
# Unit tests (no database required)
cargo test --workspace

# Adversarial prompt injection tests (93 payloads, pure Rust, < 0.1s)
cargo test -p ectoledger --test adversarial_guards

# Integration tests (Docker Postgres)
./scripts/test-integration.sh

# Integration tests (SQLite)
DATABASE_URL=sqlite://test.db cargo test --features integration
```

---

## Next Steps

| Resource | Description |
|---|---|
| [README.md](../README.md) | Full documentation — architecture, CLI reference, configuration, policy DSL |
| [docs/schema.md](schema.md) | Database schema and migration history |
| [docs/iso42001.md](iso42001.md) | ISO 42001:2023 compliance whitepaper |
| [docs/SCALING.md](SCALING.md) | Horizontal scaling guide (PostgreSQL) |
| [SANDBOX_CROSS_PLATFORM.md](../SANDBOX_CROSS_PLATFORM.md) | Cross-platform sandbox comparison |
| [audit_policy.example.toml](../audit_policy.example.toml) | Annotated example policy file |
| [sdk/python/README.md](../sdk/python/README.md) | Python SDK full API reference |
| [sdk/typescript/README.md](../sdk/typescript/README.md) | TypeScript SDK full API reference |
