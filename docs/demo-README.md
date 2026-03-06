# Ecto Ledger Demo Mode

Evaluating enterprise security tools shouldn't require an afternoon of DevOps. Ecto Ledger's `--demo` flag is designed to get you from `git clone` to a cryptographically verified AI audit in under 3 minutes, with zero configuration.

## What Demo Mode Does

When you append `--demo` to your platform's launcher script, Ecto Ledger autonomously creates an isolated, safe sandbox environment on your machine:

1. **Zero-Pollution Storage:** Unsets `DATABASE_URL` so the backend automatically starts an isolated embedded PostgreSQL instance via pg-embed on **port 5433** with a separate data directory (`~/Library/Application Support/ectoledger/postgres-demo` on macOS, `~/.local/share/ectoledger/postgres-demo` on Linux, `%LOCALAPPDATA%\ectoledger\postgres-demo` on Windows). This is completely isolated from your normal-mode database. Run with `--reset-db --demo` to wipe it.
2. **Autonomous LLM Provisioning:** If you do not have cloud API keys configured, the script checks for a local [Ollama](https://ollama.com) installation. If missing, it gives you a 5-second warning and safely auto-installs it.
3. **Speed-Optimized Model:** It automatically pulls the lightweight `qwen2.5:0.5b` model. At ~400MB, it is highly capable for standard CLI reasoning and downloads in seconds.
4. **Guard Disabled:** The semantic guard (`GUARD_REQUIRED`) is disabled in demo mode to avoid requiring a separate guard LLM configuration. In production, always enable the guard.
5. **Auto-Seeded Audit:** The Rust backend detects the demo environment (`ECTO_DEMO_MODE=true`) and can automatically initiate a mock audit session.

## How to Use It

**macOS:**
```bash
./ectoledger-mac --demo
```

**Linux:**
```bash
./ectoledger-linux --demo
```

**Windows (PowerShell):**
```powershell
.\ectoledger-win.ps1 -demo
```

## LLM Detection Priority

The demo launcher checks for LLM backends in this order:

1. **Cloud API key** — If `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is already set in your environment, that provider is used automatically. No local model is downloaded.
2. **Existing Ollama installation** — If Ollama is already installed and running, it is reused. The `qwen2.5:0.5b` model is pulled if not already present.
3. **Auto-install Ollama** — If no LLM is available at all, the script warns you and provides a 5-second countdown before installing Ollama:
   - **macOS:** `brew install ollama`
   - **Linux:** `curl -fsSL https://ollama.com/install.sh | sh`
   - **Windows:** `winget install Ollama.Ollama` (falls back to direct `.exe` download if winget is unavailable)

Press **Ctrl+C** during the countdown to cancel the auto-install.

## Environment Variables Set by Demo Mode

| Variable | Value | Purpose |
|---|---|---|
| `DATABASE_URL` | *(unset)* | Cleared so the backend uses embedded PostgreSQL (pg-embed) for full isolation |
| `ECTO_DEMO_MODE` | `true` | Triggers isolated demo database (port 5433, `postgres-demo` data dir) |
| `ECTO_DEV_MODE` | `true` | Allows default database URL when `DATABASE_URL` is unset |
| `GUARD_REQUIRED` | `false` | Disables the semantic guard (no separate guard LLM needed in demo) |
| `LLM_BACKEND` | `ollama` / `openai` / `anthropic` | Auto-detected LLM provider |
| `OLLAMA_MODEL` | `qwen2.5:0.5b` | Lightweight model for fast local inference (only when using Ollama) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API endpoint (only when using Ollama) |
| `RUST_LOG` | `info` | Log level (preserved if already set) |

## Cleaning Up

To remove all demo artifacts:

```bash
# macOS: delete the demo Postgres data
rm -rf "$HOME/Library/Application Support/ectoledger/postgres-demo"
# Or use the launcher flag:
./ectoledger-mac --demo --reset-db

# Linux:
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/ectoledger/postgres-demo"
# Or:
./ectoledger-linux --demo --reset-db

# Optionally remove the pulled model
ollama rm qwen2.5:0.5b
```

Demo mode never modifies your `.env` file — all overrides are process-scoped environment variables only.

## Idempotency

Running `--demo` multiple times is safe:
- Ollama is not re-installed if already present
- The `qwen2.5:0.5b` model is not re-downloaded if already pulled
- The embedded Postgres data persists between runs (use `--reset-db` to start fresh)
