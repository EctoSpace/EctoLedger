# =============================================================================
#  EctoLedger - One-Click Launcher (Windows)
#  Usage:  .\ectoledger-win.ps1 [FLAGS]
#
#  FLAGS:
#    --demo           Zero-config demo: SQLite DB, auto-detect/install LLM, seed demo session
#    --setup          Build and install deps only, then exit
#    --rebuild        Force cargo build even if binary already exists
#    --backend-only   Start backend server without the GUI
#    --reset-db       Wipe embedded Postgres data and start fresh
#    --help           Show this message
# =============================================================================

param(
    [switch]$demo,
    [switch]$setup,
    [switch]$rebuild,
    [switch]$backendOnly,
    [switch]$resetDb,
    [switch]$help
)

$ErrorActionPreference = "Stop"
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$BINARY = Join-Path $SCRIPT_DIR "target\release\ectoledger.exe"
$GUI_DIR = Join-Path $SCRIPT_DIR "gui"
$LOG_FILE = Join-Path $SCRIPT_DIR "ectoledger.log"

function Write-Info { param($msg) Write-Host "  " -NoNewline; Write-Host ">" -ForegroundColor Cyan -NoNewline; Write-Host " $msg" }
function Write-Success { param($msg) Write-Host "  " -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host " $msg" }
function Write-Warn { param($msg) Write-Host "  " -NoNewline; Write-Host "!" -ForegroundColor Yellow -NoNewline; Write-Host "  $msg" }
function Write-Err { param($msg) Write-Host "  " -NoNewline; Write-Host "X" -ForegroundColor Red -NoNewline; Write-Host "  $msg" -ForegroundColor Red }
function Write-Step { param($msg) Write-Host ""; Write-Host "-- $msg --" -ForegroundColor Cyan }

if ($help) {
    Write-Host "Usage: .\ectoledger-win.ps1 [-demo] [-setup] [-rebuild] [-backendOnly] [-resetDb] [-help]"
    Write-Host ""
    Write-Host "  -demo          Zero-config demo: SQLite DB, auto-detect/install LLM, seed session"
    Write-Host "  -setup          Build and install deps only (no servers started)"
    Write-Host "  -rebuild       Force Rust rebuild even if binary exists"
    Write-Host "  -backendOnly   Start backend without the GUI"
    Write-Host "  -resetDb       Wipe embedded Postgres data and start fresh"
    Write-Host "  -help          Show this message"
    exit 0
}

Write-Host ""
Write-Host "  EctoLedger 2026" -ForegroundColor Cyan
Write-Host ""

# -- 1. Check prerequisites --
# If tools are missing the script offers to install them interactively.
Write-Step "Checking prerequisites"

# Helper: prompt the user yes/no.  Returns $true for yes, $false for no.
# In non-interactive mode always returns $false.
function Ask-Install {
    param([string]$ToolName)
    if (-not [Environment]::UserInteractive) { return $false }
    $reply = Read-Host "  ?  $ToolName is not installed. Install it now? [y/N]"
    return ($reply -match '^[Yy]')
}

# Refresh PATH from registry so newly installed tools are found in this session.
function Refresh-Path {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    # Also add cargo's default location if it exists.
    $cargoPath = Join-Path $env:USERPROFILE ".cargo\bin"
    if ((Test-Path $cargoPath) -and ($env:Path -notlike "*$cargoPath*")) {
        $env:Path = "$cargoPath;$env:Path"
    }
}

$hasWinget = $false
try { $null = Get-Command winget -ErrorAction Stop; $hasWinget = $true } catch {}

$unresolved = @()

# -- Cargo / Rust --
$cargoFound = $false
try { $null = Get-Command cargo -ErrorAction Stop; $cargoFound = $true } catch {}

if (-not $cargoFound) {
    if ($hasWinget) {
        if (Ask-Install "Rust/Cargo (via winget)") {
            Write-Info "Installing Rust via winget ..."
            winget install --id Rustlang.Rustup -e --accept-source-agreements --accept-package-agreements
            Refresh-Path
            try { $null = Get-Command cargo -ErrorAction Stop; $cargoFound = $true } catch {}
            if ($cargoFound) {
                # Run rustup default stable to ensure toolchain is ready.
                rustup default stable 2>$null
                Refresh-Path
                Write-Success "Rust installed"
            } else {
                Write-Err "Rust installation completed but cargo is still not in PATH."
                $unresolved += "Rust/Cargo      https://rustup.rs"
            }
        } else {
            $unresolved += "Rust/Cargo      https://rustup.rs"
        }
    } else {
        Write-Warn "winget is not available — cannot auto-install Rust."
        $unresolved += "Rust/Cargo      https://rustup.rs"
    }
}

# Re-check version if cargo is now available.
if ($cargoFound -or (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $rustVer = (rustc --version) -replace 'rustc ', ''
    if ($rustVer -match '^(\d+)\.(\d+)') {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 1 -or ($major -eq 1 -and $minor -lt 94)) {
            Write-Warn "Rust $rustVer is too old (need >= 1.94)"
            $hasRustup = $false
            try { $null = Get-Command rustup -ErrorAction Stop; $hasRustup = $true } catch {}
            if ($hasRustup) {
                if (Ask-Install "Rust update (current: $rustVer, need >= 1.94)") {
                    Write-Info "Running rustup update ..."
                    rustup update stable
                    Refresh-Path
                    $rustVer = (rustc --version) -replace 'rustc ', ''
                    Write-Success "Rust updated to $rustVer"
                } else {
                    $unresolved += "Rust >= 1.94    run: rustup update stable"
                }
            } else {
                $unresolved += "Rust >= 1.94    https://rustup.rs  (then: rustup update stable)"
            }
        } else {
            Write-Success "Rust $rustVer"
        }
    } else {
        Write-Success "Rust $rustVer"
    }
}

# -- Node.js & npm --
if (-not $backendOnly) {
    $nodeFound = $false
    try { $null = Get-Command node -ErrorAction Stop; $nodeFound = $true } catch {}

    if (-not $nodeFound) {
        if ($hasWinget) {
            if (Ask-Install "Node.js (via winget)") {
                Write-Info "Installing Node.js LTS via winget ..."
                winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
                Refresh-Path
                try { $null = Get-Command node -ErrorAction Stop; $nodeFound = $true } catch {}
                if ($nodeFound) {
                    Write-Success "Node.js installed"
                } else {
                    Write-Err "Node.js installation completed but node is still not in PATH."
                    $unresolved += "Node.js >= 20   https://nodejs.org"
                }
            } else {
                $unresolved += "Node.js >= 20   https://nodejs.org"
            }
        } else {
            Write-Warn "winget is not available — cannot auto-install Node.js."
            $unresolved += "Node.js >= 20   https://nodejs.org"
        }
    }

    # Re-check version if node is now available.
    if ($nodeFound -or (Get-Command node -ErrorAction SilentlyContinue)) {
        $nodeVer = (node --version) -replace 'v', ''
        $nodeMajor = [int]($nodeVer -split '\.')[0]
        if ($nodeMajor -lt 20) {
            Write-Warn "Node.js $nodeVer is too old (need >= 20)"
            $unresolved += "Node.js >= 20   https://nodejs.org  (current: $nodeVer)"
        } else {
            Write-Success "Node.js $nodeVer"
        }
    }

    $npmFound = $false
    try { $null = Get-Command npm -ErrorAction Stop; $npmFound = $true } catch {}
    if ($npmFound) {
        Write-Success "npm $(npm --version)"
    } else {
        $unresolved += "npm             https://nodejs.org  (included with Node.js)"
    }
}

# -- C/C++ Build Tools (needed by native Rust crates like openssl-sys, ring) --
$hasCL = $false
try { $null = Get-Command cl.exe -ErrorAction Stop; $hasCL = $true } catch {}
if (-not $hasCL) {
    # Check common VS Build Tools locations
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vsPath) { $hasCL = $true }
    }
}
if (-not $hasCL) {
    Write-Warn "Visual Studio C++ Build Tools not detected."
    Write-Warn "Rust needs a C compiler to build native crates (openssl-sys, ring, etc.)."
    if ($hasWinget) {
        if (Ask-Install "Visual Studio Build Tools (via winget)") {
            Write-Info "Installing Visual Studio Build Tools ..."
            winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-source-agreements --accept-package-agreements --override "--add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --quiet --wait"
            Refresh-Path
            Write-Success "Build Tools installed (you may need to restart your terminal)"
        } else {
            $unresolved += "VS Build Tools   https://visualstudio.microsoft.com/visual-cpp-build-tools/"
        }
    } else {
        $unresolved += "VS Build Tools   https://visualstudio.microsoft.com/visual-cpp-build-tools/"
    }
} else {
    Write-Success "C/C++ Build Tools"
}

# -- Final gate --
if ($unresolved.Count -gt 0) {
    Write-Host ""
    Write-Err "The following dependencies are still missing:"
    Write-Host ""
    foreach ($item in $unresolved) {
        Write-Host "    * $item" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Err "Install them and re-run the script."
    exit 1
}

# -- 2. Create .env if missing --
Write-Step "Environment"

$ENV_FILE = Join-Path $SCRIPT_DIR ".env"
if (-not (Test-Path $ENV_FILE)) {
    Write-Info "Creating .env with dev defaults..."
    @"
# EctoLedger - Dev Environment
DATABASE_URL=postgres://ectoledger:ectoledger@localhost:5432/ectoledger
LLM_BACKEND=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:0.5b
GUARD_REQUIRED=false
RUST_LOG=info
"@ | Set-Content $ENV_FILE -Encoding UTF8
    Write-Success ".env created"
} else {
    Write-Success ".env already exists"
}

Get-Content $ENV_FILE | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]*)=(.*)$') {
        $envKey = $matches[1].Trim()
        # Strip inline comments (e.g. "true   # comment") and surrounding whitespace/quotes.
        $envVal = ($matches[2] -replace '\s*#.*$', '').Trim().Trim('"').Trim("'")
        [Environment]::SetEnvironmentVariable($envKey, $envVal, "Process")
    }
}
# -- Demo Mode --
if ($demo) {
    Write-Host ""
    Write-Host "  Demo Mode Activated" -ForegroundColor Green
    Write-Host ""

    # -- a. Environment isolation --
    Write-Info "Setting up isolated demo database..."
    Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
    $env:ECTO_DEMO_MODE = "true"
    $env:ECTO_DEV_MODE = "true"
    $env:GUARD_REQUIRED = "false"
    if (-not $env:RUST_LOG) { $env:RUST_LOG = "info" }
    Write-Success "Database: isolated demo PostgreSQL (pg-embed, separate from normal mode)"

    # -- b. LLM auto-detection --
    Write-Host ""
    Write-Info "Detecting LLM capabilities..."

    $demoLlmResolved = $false

    if ($env:OPENAI_API_KEY) {
        $env:LLM_BACKEND = "openai"
        Write-Success "OpenAI API key detected - using cloud LLM"
        $demoLlmResolved = $true
    } elseif ($env:ANTHROPIC_API_KEY) {
        $env:LLM_BACKEND = "anthropic"
        Write-Success "Anthropic API key detected - using cloud LLM"
        $demoLlmResolved = $true
    }

    if (-not $demoLlmResolved) {
        # -- c. Ollama detection + install --

        # Helper: add common Ollama install locations to PATH so we can find
        # ollama.exe even when the installer/winget PATH update hasn't been
        # picked up by the current shell session.
        function Ensure-OllamaPath {
            $candidates = @(
                (Join-Path $env:LOCALAPPDATA "Programs\Ollama"),
                (Join-Path $env:ProgramFiles   "Ollama")
            )
            foreach ($dir in $candidates) {
                $exe = Join-Path $dir "ollama.exe"
                if ((Test-Path $exe) -and ($env:Path -notlike "*$dir*")) {
                    $env:Path = "$dir;$env:Path"
                    return
                }
            }
        }

        Ensure-OllamaPath

        $ollamaCmd = Get-Command "ollama" -ErrorAction SilentlyContinue
        if ($ollamaCmd) {
            Write-Success "Ollama found at $($ollamaCmd.Source)"
        } else {
            Write-Host ""
            Write-Warn "Ollama not found. It is required to run local AI agents."
            Write-Host "  Auto-installing Ollama in 5 seconds... (Press Ctrl+C to cancel)" -ForegroundColor Yellow

            for ($i = 5; $i -ge 1; $i--) {
                Write-Host "`r  $i..." -NoNewline
                Start-Sleep -Seconds 1
            }
            Write-Host ""

            # Try winget first, then direct download
            $wingetCmd = Get-Command "winget" -ErrorAction SilentlyContinue
            if ($wingetCmd) {
                Write-Info "Running: winget install Ollama.Ollama"
                winget install Ollama.Ollama --accept-source-agreements --accept-package-agreements
            } else {
                Write-Info "winget not available - downloading Ollama installer directly..."
                $installerPath = Join-Path $env:TEMP "OllamaSetup.exe"
                Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile $installerPath -UseBasicParsing
                Write-Info "Running silent installer..."
                Start-Process -FilePath $installerPath -ArgumentList "/VERYSILENT","/NORESTART" -Wait
                Remove-Item $installerPath -ErrorAction SilentlyContinue
            }

            # Refresh PATH from registry AND add common install locations
            $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
            $env:Path = "$machinePath;$userPath"
            Ensure-OllamaPath

            if (-not (Get-Command "ollama" -ErrorAction SilentlyContinue)) {
                Write-Err "Ollama installation failed. Install manually: https://ollama.com/download"
                exit 1
            }
            Write-Success "Ollama installed"
            Write-Host "    You can safely close the Ollama chat window - the service runs in the background." -ForegroundColor DarkGray
        }

        # -- d. Ensure Ollama is running --
        # We only need the headless API server ("ollama serve"), NOT the
        # desktop app ("ollama app.exe") which opens a chat window the user
        # would have to interact with.  Probe the API port first; if it isn't
        # listening, kill any lingering desktop app and start a clean serve.
        $ollamaRunning = $false
        for ($probe = 0; $probe -lt 8; $probe++) {
            try {
                $null = Invoke-WebRequest -Uri "http://127.0.0.1:11434" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
                $ollamaRunning = $true
                break
            } catch {}
            Start-Sleep -Seconds 1
        }

        if (-not $ollamaRunning) {
            # If the desktop app is running but the API isn't responding,
            # stop it so we can start a clean headless server.
            Get-Process -Name "ollama app" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1

            Write-Info "Starting Ollama server (headless)..."
            Start-Process "ollama" -ArgumentList "serve" -WindowStyle Hidden

            # Windows Defender / first-time GPU init can be slow — allow up to
            # 60 seconds with progress feedback.
            $ollamaWait = 0
            $ollamaTimeout = 60
            while ($ollamaWait -lt $ollamaTimeout) {
                Start-Sleep -Seconds 2
                $ollamaWait += 2
                try {
                    $null = Invoke-WebRequest -Uri "http://127.0.0.1:11434" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
                    $ollamaRunning = $true
                    break
                } catch {}
                if ($ollamaWait % 10 -eq 0) {
                    Write-Host "    ...still waiting ($ollamaWait/$ollamaTimeout s)" -ForegroundColor DarkGray
                }
            }
            if (-not $ollamaRunning) {
                Write-Warn "Ollama did not respond within $ollamaTimeout seconds."
                Write-Warn "Cannot proceed without a running LLM backend."
                Write-Err "Start Ollama manually or set OPENAI_API_KEY / ANTHROPIC_API_KEY."
                exit 1
            } else {
                Write-Success "Ollama server running"
            }
        } else {
            Write-Success "Ollama already running at http://127.0.0.1:11434"
        }

        # -- e. Pull model --
        $modelList = ollama list 2>$null
        if ($modelList -match "qwen2.5:0.5b") {
            Write-Success "Model qwen2.5:0.5b already available"
        } else {
            Write-Host ""
            Write-Info "Pulling qwen2.5:0.5b model (this may take a few minutes on first run)..."
            try {
                ollama pull qwen2.5:0.5b
                Write-Success "Model qwen2.5:0.5b ready"
            } catch {
                Write-Err "Failed to pull qwen2.5:0.5b - cannot proceed without a model"
                exit 1
            }
        }

        $env:LLM_BACKEND = "ollama"
        $env:OLLAMA_MODEL = "qwen2.5:0.5b"
        $env:OLLAMA_BASE_URL = "http://127.0.0.1:11434"
    }

    # -- f. Summary --
    Write-Host ""
    Write-Step "Demo Configuration"
    $llmDisplay = if ($env:LLM_BACKEND -eq "ollama") { "ollama (qwen2.5:0.5b)" } else { $env:LLM_BACKEND }
    Write-Host "  Database:    isolated demo PostgreSQL (port 5433, .../postgres-demo)" -ForegroundColor Cyan
    Write-Host "  LLM Backend: $llmDisplay" -ForegroundColor Cyan
    Write-Host "  Guard:       disabled (demo)" -ForegroundColor Cyan
    Write-Host "  Demo Mode:   enabled" -ForegroundColor Cyan
    Write-Host ""
}

# -- 2b. Reset DB if requested --
if ($resetDb) {
    Write-Step "Resetting embedded database"
    if ($demo) {
        $PG_DATA_DIR = Join-Path $env:LOCALAPPDATA "ectoledger\postgres-demo"
    } else {
        $PG_DATA_DIR = Join-Path $env:LOCALAPPDATA "ectoledger\postgres"
    }
    if (Test-Path $PG_DATA_DIR) {
        Write-Warn "Deleting embedded Postgres data..."
        Remove-Item -Recurse -Force $PG_DATA_DIR
        Write-Success "Database reset"
    } else {
        Write-Info "No embedded database found"
    }
}

# -- 3. Build backend --
Write-Step "Backend"

$needBuild = $rebuild -or -not (Test-Path $BINARY)
# Auto-detect stale binary: rebuild if any .rs source is newer than the binary.
if (-not $needBuild -and (Test-Path $BINARY)) {
    $binaryTime = (Get-Item $BINARY).LastWriteTime
    $newerSrc = Get-ChildItem -Path (Join-Path $SCRIPT_DIR "crates") -Filter "*.rs" -Recurse |
        Where-Object { $_.LastWriteTime -gt $binaryTime } | Select-Object -First 1
    if ($newerSrc) {
        Write-Info "Source files changed since last build - rebuilding automatically."
        $needBuild = $true
    }
}
if ($needBuild) {
    Write-Info "Building EctoLedger (release mode + remote enclave)..."
    Push-Location $SCRIPT_DIR
    try {
        cargo build --release --features enclave-remote -p ectoledger --manifest-path (Join-Path $SCRIPT_DIR "Cargo.toml")
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Backend build failed. Check the errors above."
            exit 1
        }
        if (-not (Test-Path $BINARY)) {
            Write-Err "Build appeared to succeed but binary not found at: $BINARY"
            Write-Err "Try: cargo build --release --features enclave-remote -p ectoledger"
            exit 1
        }
        Write-Success "Backend built"
    } finally {
        Pop-Location
    }
} else {
    Write-Success "Backend already built"
}

# -- 4. GUI dependencies --
if (-not $backendOnly) {
    Write-Step "GUI dependencies"
    $nodeModules = Join-Path $GUI_DIR "node_modules"
    if (-not (Test-Path $nodeModules)) {
        Write-Info "Installing npm packages..."
        # Use Push-Location instead of --prefix because npm --prefix
        # does not resolve package.json correctly on Windows.
        Push-Location $GUI_DIR
        try {
            npm install --silent
            Write-Success "npm packages installed"
        } finally {
            Pop-Location
        }
    } else {
        Write-Success "node_modules present"
    }
}

# -- 5. Exit early if --setup --
if ($setup) {
    Write-Host ""
    Write-Success "Setup complete. Run .\ectoledger-win.ps1 to start."
    exit 0
}

# -- 5b. Guard auto-detection --
# If GUARD_REQUIRED is still "true" but the operator hasn't set
# GUARD_LLM_BACKEND and GUARD_LLM_MODEL, the session-creation handler will
# return a 500.  Gracefully downgrade rather than a cryptic error.
if ($env:GUARD_REQUIRED -eq 'true' -and (-not $env:GUARD_LLM_BACKEND -or -not $env:GUARD_LLM_MODEL)) {
    $env:GUARD_REQUIRED = 'false'
    Write-Warn "GUARD_LLM_BACKEND / GUARD_LLM_MODEL not set - disabling guard.  Set both to enable it."
}

# -- 6. Start backend --
Write-Step "Starting backend"

$bindPort = if ($env:ECTO_BIND_PORT) { $env:ECTO_BIND_PORT } else { "3000" }

if (-not $env:OBSERVER_TOKEN) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $env:OBSERVER_TOKEN = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ''
    Write-Warn "No OBSERVER_TOKEN set. Generated cryptographic token for this session."
    Write-Host "  Dashboard: http://127.0.0.1:$bindPort?token=$($env:OBSERVER_TOKEN)" -ForegroundColor Cyan
    Write-Host ""
}

$healthUrl = "http://127.0.0.1:$bindPort"
Write-Info "Starting backend on $healthUrl..."
# Snapshot the full process-scope environment so Start-Job (which runs in a
# new PowerShell runspace and does NOT inherit "Process"-scoped env changes
# made after the session started) receives all configured variables including
# OBSERVER_TOKEN, DATABASE_URL, LLM_BACKEND, etc.
$envSnapshot = [System.Environment]::GetEnvironmentVariables('Process')

$backendJob = Start-Job -ScriptBlock {
    param($bin, $log, $envVars, $workDir)
    # Set working directory so dotenvy can find .env and relative paths work.
    Set-Location $workDir
    # Re-apply every process-scope variable inside the job's runspace.
    foreach ($kv in $envVars.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($kv.Key, $kv.Value, 'Process')
    }
    & $bin serve *>> $log
} -ArgumentList $BINARY, $LOG_FILE, $envSnapshot, $SCRIPT_DIR

# Wait for backend to be healthy.
# Unlike the macOS launcher (which checks `kill -0 $PID` each iteration),
# Start-Job hides process crashes inside the job state.  We poll
# $backendJob.State every second so the user gets immediate feedback
# instead of looping silently for 120 s when the binary exits early.
$waitSecs = 120
$ready = $false
for ($i = 0; $i -lt $waitSecs; $i++) {
    # ── Detect early crash / exit ──
    $jState = $backendJob.State
    if ($jState -eq 'Completed' -or $jState -eq 'Failed') {
        Write-Host ""
        Write-Err "Backend process exited unexpectedly (job state: $jState)."
        $jobOutput = Receive-Job $backendJob -ErrorAction SilentlyContinue 2>&1
        if ($jobOutput) {
            Write-Host ""
            Write-Host "  Job output:" -ForegroundColor Yellow
            $jobOutput | ForEach-Object { Write-Host "    $_" }
        }
        if (Test-Path $LOG_FILE) {
            Write-Host ""
            Write-Host "  Last 20 lines of ectoledger.log:" -ForegroundColor Yellow
            Get-Content $LOG_FILE -Tail 20 | ForEach-Object { Write-Host "    $_" }
        }
        Write-Host ""
        # Actionable hints based on log content
        if ((Test-Path $LOG_FILE) -and (Select-String -Path $LOG_FILE -Pattern 'password authentication failed|Role.*does not exist|EmbeddedSetup|VersionMismatch' -Quiet)) {
            if ($demo) {
                Write-Warn "Try: .\ectoledger-win.ps1 -demo -resetDb"
            } else {
                Write-Warn "Try: .\ectoledger-win.ps1 -resetDb"
            }
        }
        if ((Test-Path $LOG_FILE) -and (Select-String -Path $LOG_FILE -Pattern 'address already in use|port .* in use' -Quiet)) {
            Write-Warn "Port $bindPort is occupied. Find the process with:"
            Write-Host "    netstat -ano | findstr :$bindPort" -ForegroundColor Yellow
            Write-Host "    taskkill /F /PID <PID>" -ForegroundColor Yellow
        }
        Remove-Job $backendJob -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # ── Health-check probe ──
    try {
        $r = Invoke-WebRequest -Uri "$healthUrl/api/status" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($r.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {}
    Start-Sleep -Seconds 1
    Write-Host "`r  Starting backend... $i s" -NoNewline
}

Write-Host ""
if (-not $ready) {
    Write-Err "Backend did not become healthy within ${waitSecs}s."
    if (Test-Path $LOG_FILE) {
        Write-Host ""
        Write-Host "  Last 20 lines of ectoledger.log:" -ForegroundColor Yellow
        Get-Content $LOG_FILE -Tail 20 | ForEach-Object { Write-Host "    $_" }
    }
    Stop-Job $backendJob -ErrorAction SilentlyContinue
    Remove-Job $backendJob -ErrorAction SilentlyContinue
    exit 1
}

Write-Success "Backend healthy at $healthUrl"
Write-Host ""
Write-Host "  Observer dashboard: $healthUrl" -ForegroundColor Cyan
Write-Host "  Backend logs:       Get-Content ectoledger.log -Wait" -ForegroundColor Cyan
Write-Host ""

# -- 7. Start GUI or wait --
if ($backendOnly) {
    Write-Step "Backend-only mode"
    Write-Info "Backend is running. Press Ctrl+C to stop."
    Write-Host ""
    Write-Host "  cargo run --bin ectoledger -- audit `"your prompt`"" -ForegroundColor White
    Write-Host ""
    Wait-Job $backendJob
    exit 0
}

Write-Step "Launching GUI"
# Tell the Tauri GUI to route all API calls to the standalone backend
# instead of its own embedded SQLite server.
$env:ECTO_HOST = "http://127.0.0.1:$bindPort"
Write-Info "Starting Tauri desktop app..."
Write-Host ""
Push-Location $GUI_DIR
try {
    npm run tauri dev
} finally {
    Stop-Job $backendJob -ErrorAction SilentlyContinue
    Remove-Job $backendJob -ErrorAction SilentlyContinue
    Pop-Location
}
