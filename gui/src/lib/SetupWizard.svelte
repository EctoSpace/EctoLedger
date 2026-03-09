<!--
  SetupWizard — Full first-launch wizard (Track 3: 6-step flow).
  Step 0: Auto-detection  Step 1: Express vs Custom
  Step 2: Database        Step 3: LLM Provider
  Step 4: Model Selection Step 5: Provisioning
-->
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onDestroy } from "svelte";
  import { Button, Card, Badge, Input, Select } from "./ui";

  interface Props {
    serverUrl: string;
    onComplete: () => void;
  }

  let { serverUrl, onComplete }: Props = $props();

  // ── State machine ────────────────────────────────────────────────────
  type SetupPath = "express" | "custom";
  type DbMode = "sqlite" | "postgres" | "memory";
  type LlmProvider = "ollama_install" | "ollama_existing" | "cloud";

  let step = $state(0);                          // 0..5
  let path = $state<SetupPath>("express");
  let dbMode = $state<DbMode>("sqlite");
  let llmProvider = $state<LlmProvider>("ollama_existing");
  let pgUrl = $state("");
  let ollamaHost = $state("http://127.0.0.1:11434");
  let cloudApiKey = $state("");
  let cloudEndpoint = $state("");
  let selectedModel = $state("");
  let selectedPolicy = $state("soc2-audit");

  // System state (Step 0 detection result)
  interface SystemState {
    os: string; arch: string; ram_gb: number | null;
    ollama_running: boolean; ollama_installed: boolean;
    existing_db_path: string | null; recommended_model: string;
  }
  let systemState = $state<SystemState | null>(null);
  let detectionError = $state("");

  // Provisioning (Step 5)
  let provisioning = $state(false);
  let provisionLog = $state<string[]>([]);
  let provisionError = $state("");
  let done = $state(false);

  // Available models fetched from running Ollama
  let models = $state<string[]>([]);

  // Track active Tauri event listeners for cleanup on component destroy.
  let _activeUnlisteners: Array<() => void> = [];
  let _alive = true;

  onDestroy(() => {
    _alive = false;
    for (const fn of _activeUnlisteners) fn();
    _activeUnlisteners = [];
  });

  const policyOptions = [
    { value: "soc2-audit",    label: "SOC 2 Type II" },
    { value: "pci-dss-audit", label: "PCI DSS" },
    { value: "iso42001",      label: "ISO 42001" },
    { value: "owasp-top10",   label: "OWASP Top 10" },
  ];

  // ── Step 0: Detection ────────────────────────────────────────────────
  $effect(() => {
    if (step === 0) runDetection();
  });

  async function runDetection() {
    detectionError = "";
    try {
      const state = await invoke<SystemState>("detect_system_state");
      systemState = state;
      selectedModel = state.recommended_model;
      step = 1;
    } catch (e) {
      detectionError = e instanceof Error ? e.message : String(e);
    }
  }

  // ── Step 3: Load Ollama models if running ────────────────────────────
  $effect(() => {
    if (step === 3 && systemState?.ollama_running) loadOllamaModels();
  });

  async function loadOllamaModels() {
    try {
      const raw = await invoke<{ models?: Array<{ name?: string }> }>("get_ollama_models", {
        args: {},
      });
      const ms: string[] = (raw?.models ?? []).map((m) => m.name ?? "").filter(Boolean);
      if (ms.length > 0) {
        models = ms;
        if (!selectedModel || !ms.includes(selectedModel)) selectedModel = ms[0];
      }
    } catch { /* ignore */ }
  }

  // ── Navigation ───────────────────────────────────────────────────────
  function next() {
    if (path === "express") {
      if (step === 1) { step = 5; runProvisioning(); }
    } else {
      if (step < 5) step++;
      if (step === 5) runProvisioning();
    }
  }

  function prev() {
    if (step <= 1) return;
    if (path === "express" && step === 5) { step = 1; return; }
    step--;
    if (step === 4 && llmProvider !== "ollama_install" && llmProvider !== "ollama_existing") step--;
  }

  // ── Step 5: Provisioning ─────────────────────────────────────────────
  async function runProvisioning() {
    step = 5;
    provisioning = true;
    provisionLog = [];
    provisionError = "";

    if (path === "custom" && llmProvider === "ollama_install") {
      provisionLog = [...provisionLog, "Starting Ollama installation…"];
      const unlisten = await listen<{ line: string }>("install_ollama_progress", (ev) => {
        if (!_alive) return;
        provisionLog = [...provisionLog, ev.payload.line];
      });
      _activeUnlisteners.push(unlisten);
      try {
        await invoke("install_ollama");
        provisionLog = [...provisionLog, "✓ Ollama installed."];
      } catch (e) {
        provisionError = `Ollama install failed: ${e}`;
        provisioning = false;
        unlisten();
        return;
      }
      unlisten();
    }

    if (selectedModel) {
      provisionLog = [...provisionLog, `Pulling model ${selectedModel}…`];
      const unlisten2 = await listen<{ line: string }>("pull_model_progress", (ev) => {
        if (!_alive) return;
        provisionLog = [...provisionLog, ev.payload.line];
      });
      _activeUnlisteners.push(unlisten2);
      try {
        await invoke("pull_model", { modelName: selectedModel });
        provisionLog = [...provisionLog, `✓ Model ${selectedModel} ready.`];
      } catch (e) {
        provisionLog = [...provisionLog, `Warning: pull failed — ${e}`];
      }
      unlisten2();
    }

    try {
      const isExpress = path === "express";
      const useOllama = isExpress
        ? (systemState?.ollama_running || systemState?.ollama_installed)
        : (llmProvider !== "cloud");
      const config: Record<string, unknown> = {
        llm_backend: useOllama ? "ollama" : "openai",
      };
      if (useOllama && selectedModel) config.ollama_model = selectedModel;
      if (!isExpress && llmProvider === "ollama_existing" && ollamaHost) config.ollama_base_url = ollamaHost;
      if (!isExpress && llmProvider === "cloud") {
        // Note: openai_api_key is not persisted via ConfigPayload — it must be
        // set as the OPENAI_API_KEY environment variable before launching.
        if (cloudEndpoint) config.ollama_base_url = cloudEndpoint;
      }
      await invoke("save_config", { payload: config });
      provisionLog = [...provisionLog, "✓ Configuration saved."];
    } catch (e) {
      provisionError = `Config save failed: ${e}`;
      provisioning = false;
      return;
    }

    try { await invoke("mark_setup_complete"); } catch { /* non-fatal */ }
    provisionLog = [...provisionLog, "✓ Setup complete."];
    provisioning = false;
    done = true;
  }

  let osLabel = $derived(
    systemState
      ? `${systemState.os} / ${systemState.arch}${ systemState.ram_gb != null ? ` / ${systemState.ram_gb.toFixed(0)} GB RAM` : ""}`
      : ""
  );
</script>

<div class="flex items-center justify-center min-h-screen w-screen bg-background p-6">
  <div class="w-full max-w-2xl mx-auto animate-fade-in">

    <!-- Progress (hidden on step 0) -->
    {#if step > 0}
      <div class="flex items-center gap-2 mb-12">
        {#each [1, 2, 3, 4, 5] as s}
          <div class="flex-1 h-1.5 rounded-full transition-colors {s <= step ? 'bg-accent' : 'bg-border'}"></div>
        {/each}
      </div>
    {/if}

    <!-- Step 0: Detecting -->
    {#if step === 0}
      <div class="text-center py-16">
        <div class="h-10 w-10 mx-auto mb-6 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
        <h2 class="text-xl font-bold text-text-primary mb-2">Detecting system capabilities…</h2>
        <p class="text-text-secondary text-sm">Checking for Ollama, existing databases, and hardware.</p>
        {#if detectionError}
          <div class="mt-6 p-4 rounded-lg bg-danger-muted border border-danger/30 text-sm text-danger text-left">
            <p class="font-semibold mb-1">Detection failed</p>
            <p>{detectionError}</p>
            <div class="mt-3">
              <Button variant="primary" onclick={runDetection}>Retry</Button>
            </div>
          </div>
        {/if}
      </div>

    <!-- Step 1: Express vs Custom -->
    {:else if step === 1}
      <Card title="Welcome to EctoLedger" subtitle="How would you like to set up?">
        {#snippet children()}
          {#if systemState}
            <p class="text-xs text-text-muted mb-4">Detected: {osLabel}</p>
          {/if}
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-10">
            <button
              class="text-left p-7 rounded-2xl border transition-all duration-200 cursor-pointer
                {path === 'express' ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
              onclick={() => (path = "express")}
            >
              <div class="flex items-center gap-2 mb-2">
                <span class="text-xl">⚡</span>
                <span class="font-semibold text-text-primary">Express</span>
                <Badge variant="success">{#snippet children()}Recommended{/snippet}</Badge>
              </div>
              <p class="text-xs text-text-secondary leading-relaxed">
                SQLite + best model for your system ({systemState?.recommended_model ?? "auto-selected"}). Ready in seconds.
              </p>
            </button>
            <button
              class="text-left p-7 rounded-2xl border transition-all duration-200 cursor-pointer
                {path === 'custom' ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
              onclick={() => (path = "custom")}
            >
              <div class="flex items-center gap-2 mb-2">
                <span class="text-xl">⚙</span>
                <span class="font-semibold text-text-primary">Custom Setup</span>
              </div>
              <p class="text-xs text-text-secondary leading-relaxed">
                Choose database backend, LLM provider, and model manually.
              </p>
            </button>
          </div>
          <div class="border-t border-border-muted/15 pt-6">
            <label for="wizard-policy" class="block text-xs font-semibold text-text-muted uppercase tracking-wider mb-2.5">Compliance policy</label>
            <Select id="wizard-policy" bind:value={selectedPolicy} options={policyOptions} />
          </div>
          <div class="flex justify-end mt-6">
            <Button variant="primary" onclick={next}>
              {#snippet children()}{path === "express" ? "Launch Express Setup" : "Continue →"}{/snippet}
            </Button>
          </div>
        {/snippet}
      </Card>

    <!-- Step 2: Database (Custom) -->
    {:else if step === 2}
      <Card title="Database Backend" subtitle="Where should EctoLedger store its ledger?">
        {#snippet children()}
          <div class="space-y-3 mb-6">
            {#each [
              { id: "sqlite",   icon: "🗄️", label: "SQLite (Embedded)",    desc: "File-based, zero config. Ideal for single-machine deployments.", badge: "Recommended", badgeVariant: "success" },
              { id: "postgres", icon: "🐘", label: "Connect PostgreSQL",    desc: "Enterprise-grade. Provide a PostgreSQL connection URL.",        badge: null,          badgeVariant: "" },
              { id: "memory",   icon: "🧠", label: "In-Memory",            desc: "Data is lost on restart. For testing only.",                   badge: "Testing only", badgeVariant: "warning" },
            ] as opt}
              <button
                class="w-full text-left p-6 rounded-2xl border transition-all duration-200 cursor-pointer
                  {dbMode === opt.id ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
                onclick={() => (dbMode = opt.id as DbMode)}
              >
                <div class="flex items-center gap-2 mb-1">
                  <span>{opt.icon}</span>
                  <span class="font-medium text-text-primary text-sm">{opt.label}</span>
                  {#if opt.badge}
                    <Badge variant={opt.badgeVariant as 'success' | 'warning'}>{#snippet children()}{opt.badge}{/snippet}</Badge>
                  {/if}
                </div>
                <p class="text-xs text-text-secondary">{opt.desc}</p>
                {#if opt.id === "postgres" && dbMode === "postgres"}
                  <Input bind:value={pgUrl} placeholder="postgresql://user:pass@host:5432/dbname" class="mt-3" />
                {/if}
              </button>
            {/each}
          </div>
          <div class="flex justify-between">
            <Button variant="ghost" onclick={prev}>{#snippet children()}Back{/snippet}</Button>
            <Button variant="primary" onclick={next}>{#snippet children()}Continue →{/snippet}</Button>
          </div>
        {/snippet}
      </Card>

    <!-- Step 3: LLM Provider (Custom) -->
    {:else if step === 3}
      <Card title="LLM Provider" subtitle="How will EctoLedger access a language model?">
        {#snippet children()}
          <div class="space-y-3 mb-6">
            {#each [
              { id: "ollama_install",  icon: "📦", label: "Install Ollama Locally",    desc: "Download and install Ollama, then pull a model." },
              { id: "ollama_existing", icon: "🦙", label: "Connect Existing Local LLM", desc: systemState?.ollama_running ? "✓ Ollama detected at http://127.0.0.1:11434" : "Provide the Ollama base URL." },
              { id: "cloud",           icon: "☁",  label: "Connect Cloud API",          desc: "Use OpenAI-compatible API." },
            ] as opt}
              <button
                class="w-full text-left p-6 rounded-2xl border transition-all duration-200 cursor-pointer
                  {llmProvider === opt.id ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
                onclick={() => (llmProvider = opt.id as LlmProvider)}
              >
                <div class="flex items-center gap-2 mb-1">
                  <span>{opt.icon}</span>
                  <span class="font-medium text-text-primary text-sm">{opt.label}</span>
                  {#if opt.id === "ollama_existing" && systemState?.ollama_running}
                    <Badge variant="success">{#snippet children()}Running{/snippet}</Badge>
                  {/if}
                </div>
                <p class="text-xs text-text-secondary">{opt.desc}</p>
                {#if opt.id === "ollama_existing" && llmProvider === "ollama_existing" && !systemState?.ollama_running}
                  <Input bind:value={ollamaHost} placeholder="http://127.0.0.1:11434" class="mt-3" />
                {/if}
                {#if opt.id === "cloud" && llmProvider === "cloud"}
                  <div class="mt-3 space-y-2">
                    <Input bind:value={cloudApiKey} placeholder="sk-… (API key)" type="password" />
                    <Input bind:value={cloudEndpoint} placeholder="https://api.openai.com/v1" />
                  </div>
                {/if}
              </button>
            {/each}
          </div>
          <div class="flex justify-between">
            <Button variant="ghost" onclick={prev}>{#snippet children()}Back{/snippet}</Button>
            <Button variant="primary" onclick={() => { step = 4; }}>{#snippet children()}Continue →{/snippet}</Button>
          </div>
        {/snippet}
      </Card>

    <!-- Step 4: Model Selection -->
    {:else if step === 4}
      <Card title="Model Selection" subtitle="Choose the model EctoLedger will use.">
        {#snippet children()}
          {@const modelCards = models.length > 0 ? models.map(m => ({ id: m, label: m })) : [
            { id: "llama3.2:3b",                   label: "Llama 3.2 3B — lightweight, fast" },
            { id: "llama3.1:8b",                   label: "Llama 3.1 8B — balanced" },
            { id: "llama3.3:70b-instruct-q4_K_M",  label: "Llama 3.3 70B — highest quality" },
          ]}
          <div class="space-y-2 mb-6">
            {#each modelCards as m}
              <button
                class="w-full text-left p-5 rounded-2xl border transition-all duration-200 cursor-pointer
                  {selectedModel === m.id ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
                onclick={() => (selectedModel = m.id)}
              >
                <div class="flex items-center gap-2">
                  <span class="font-mono text-sm text-text-primary">{m.label}</span>
                  {#if m.id === systemState?.recommended_model}
                    <Badge variant="accent">{#snippet children()}Recommended{/snippet}</Badge>
                  {/if}
                </div>
              </button>
            {/each}
          </div>
          <div class="flex justify-between">
            <Button variant="ghost" onclick={prev}>{#snippet children()}Back{/snippet}</Button>
            <Button variant="primary" onclick={next}>
              {#snippet children()}{llmProvider === "ollama_install" ? "Install & Pull Model" : "Pull Model"}{/snippet}
            </Button>
          </div>
        {/snippet}
      </Card>

    <!-- Step 5: Provisioning -->
    {:else if step === 5}
      <Card title="Setting Up EctoLedger" subtitle={done ? "All done!" : provisioning ? "Working…" : provisionError ? "Error" : "Provisioning"}>
        {#snippet children()}
          <div class="bg-background rounded-xl border border-border-muted/30 p-5 font-mono text-xs text-text-secondary h-48 overflow-y-auto flex flex-col gap-1.5 mb-5">
            {#if provisionLog.length === 0 && provisioning}
              <span class="text-text-muted animate-pulse">Starting provisioning…</span>
            {:else}
              {#each provisionLog as line}
                <span class="{line.startsWith('✓') ? 'text-success' : line.startsWith('Warning') ? 'text-warning' : 'text-text-secondary'}">{line}</span>
              {/each}
              {#if provisioning}<span class="text-accent animate-pulse">▌</span>{/if}
            {/if}
          </div>
          {#if provisionError}
            <div class="p-3 rounded-lg bg-danger-muted border border-danger/30 text-sm text-danger mb-4">{provisionError}</div>
            <div class="flex justify-between">
              <Button variant="ghost" onclick={() => { step = path === "express" ? 1 : 4; }}>{#snippet children()}Back{/snippet}</Button>
              <Button variant="primary" onclick={runProvisioning}>{#snippet children()}Retry{/snippet}</Button>
            </div>
          {:else if done}
            <div class="p-3 rounded-lg bg-success-muted border border-success/30 text-sm text-success mb-4">✓ EctoLedger is ready!</div>
            <div class="flex justify-end">
              <Button variant="success" onclick={onComplete}>{#snippet children()}Open EctoLedger →{/snippet}</Button>
            </div>
          {:else if provisioning}
            <div class="flex justify-center">
              <div class="h-5 w-5 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
            </div>
          {/if}
        {/snippet}
      </Card>
    {/if}

  </div>
</div>
