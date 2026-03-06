<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  interface Config {
    database_url?: string;
    llm_backend?: string;
    ollama_base_url?: string;
    ollama_model?: string;
    guard_required?: boolean;
    guard_llm_backend?: string | null;
    guard_llm_model?: string | null;
    max_steps?: number;
    agent_allowed_domains?: string[];
    // read-only — computed by server from env vars
    sandbox_mode?: string;  // "none" | "docker" | "firecracker"
    evm_enabled?: boolean;
  }

  let config = $state<Config | null>(null);
  let error = $state("");
  let saveError = $state("");
  let saving = $state(false);
  let ollamaModels = $state<{ name: string; size?: number }[]>([]);
  let ollamaErr = $state("");

  // Demo mode
  let demoMode = $state(false);
  let resetting = $state(false);
  let resetMsg = $state("");

  const backends = ["ollama", "openai", "anthropic"];

  onMount(() => {
    load();
    detectDemoMode();
  });

  async function detectDemoMode() {
    try {
      const dm = await invoke<boolean>("is_demo_mode");
      if (dm) demoMode = true;
    } catch {}
  }

  async function resetDemoData() {
    resetting = true;
    resetMsg = "";
    try {
      const res = await invoke<{ message?: string }>("reset_demo_data");
      resetMsg = res?.message ?? "Database reset successfully.";
    } catch (e) {
      resetMsg = `Reset failed: ${e}`;
    }
    resetting = false;
  }

  async function load() {
    if (!isTauri()) return;
    try {
      const data = await invoke<unknown>("get_config");
      config = data && typeof data === "object" && !Array.isArray(data)
        ? (data as Config)
        : null;
      error = "";
      saveError = "";
      if (config?.llm_backend === "ollama") {
        loadOllamaModels();
      }
    } catch (e) {
      error = String(e);
    }
  }

  async function loadOllamaModels() {
    ollamaErr = "";
    try {
      const data = await invoke<unknown>("get_ollama_models", {
        args: { baseUrlOverride: config?.ollama_base_url || undefined },
      });
      const obj = data && typeof data === "object" ? (data as Record<string, unknown>) : null;
      const models = (obj?.models as { name?: string; size?: number }[]) ?? [];
      ollamaModels = models.map((m) => ({
        name: m.name ?? "unknown",
        size: m.size,
      }));
    } catch (e) {
      ollamaErr = String(e);
      ollamaModels = [];
    }
  }

  function formatSize(bytes: number | undefined): string {
    if (bytes == null) return "—";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  async function save() {
    if (!isTauri() || !config) return;
    saving = true;
    saveError = "";
    try {
      const payload = {
        database_url: config.database_url || undefined,
        llm_backend: config.llm_backend || undefined,
        ollama_base_url: config.ollama_base_url || undefined,
        ollama_model: config.ollama_model || undefined,
        guard_required: config.guard_required ?? undefined,
        guard_llm_backend: config.guard_llm_backend || undefined,
        guard_llm_model: config.guard_llm_model || undefined,
        max_steps: config.max_steps ?? undefined,
        agent_allowed_domains: config.agent_allowed_domains?.length ? config.agent_allowed_domains : undefined,
      };
      await invoke("save_config", { payload });
    } catch (e) {
      saveError = String(e);
    } finally {
      saving = false;
    }
  }

  function domainsToText(arr: string[] | undefined): string {
    return (arr ?? []).join(", ");
  }

  function textToDomains(s: string): string[] {
    return s
      .split(",")
      .map((x) => x.trim())
      .filter((x) => x.length > 0);
  }

  let domainsText = $derived(domainsToText(config?.agent_allowed_domains));
</script>

<div class="flex flex-col gap-8 pb-6">
  <div class="p-8 rounded-2xl max-w-2xl bg-surface shadow-sm">
    <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-5">Settings</h2>
    <p class="text-text-muted text-sm">
      Edit below and save. Settings are persisted to <code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">~/.ectoledger/settings.json</code>.
      Restart the backend for runtime changes to take effect.
    </p>

    {#if error}
      <p class="text-danger text-sm">{error}</p>
    {:else if config}
      <form onsubmit={(e) => { e.preventDefault(); save(); }}>
        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">Database</h3>
          <input
            type="text"
            class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
            bind:value={config!.database_url}
            placeholder="postgres://..."
          />
        </section>

        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">LLM</h3>
          <dl class="text-sm m-0">
            <dt class="text-text-muted mt-3">Backend</dt>
            <dd class="mt-1 ml-0">
              <select class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm cursor-pointer focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={config.llm_backend} onchange={() => { if (config?.llm_backend === "ollama") loadOllamaModels(); }}>
                {#each backends as b}
                  <option value={b}>{b}</option>
                {/each}
              </select>
            </dd>
            <dt class="text-text-muted mt-3">Ollama URL</dt>
            <dd class="mt-1 ml-0"><input type="text" class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={config!.ollama_base_url} placeholder="http://localhost:11434" /></dd>
            <dt class="text-text-muted mt-3">Ollama Model</dt>
            <dd class="mt-1 ml-0">
              {#if config!.llm_backend === "ollama"}
                <select class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm cursor-pointer focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={config!.ollama_model}>
                  {#each ollamaModels as m}
                    <option value={m.name}>{m.name} ({formatSize(m.size)})</option>
                  {/each}
                  {#if config!.ollama_model && !ollamaModels.find((x) => x.name === config!.ollama_model)}
                    <option value={config!.ollama_model}>{config!.ollama_model} (custom)</option>
                  {/if}
                </select>
                {#if ollamaErr}
                  <p class="text-xs text-danger leading-relaxed">{ollamaErr}</p>
                {/if}
              {:else}
                <input type="text" class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={config!.ollama_model} placeholder="model name" />
              {/if}
            </dd>
          </dl>
        </section>

        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">Guard</h3>
          <dl class="text-sm m-0">
            <dt class="text-text-muted mt-3">Required</dt>
            <dd class="mt-1 ml-0">
              <select
                class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm cursor-pointer focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
                value={config!.guard_required ? "true" : "false"}
                onchange={(e) => { config!.guard_required = (e.target as HTMLSelectElement).value === "true"; }}
              >
                <option value="true">Yes</option>
                <option value="false">No</option>
              </select>
            </dd>
            <dt class="text-text-muted mt-3">Guard LLM Backend</dt>
            <dd class="mt-1 ml-0"><input type="text" class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={config!.guard_llm_backend} placeholder="ollama" /></dd>
            <dt class="text-text-muted mt-3">Guard LLM Model</dt>
            <dd class="mt-1 ml-0"><input type="text" class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={config!.guard_llm_model} placeholder="model" /></dd>
          </dl>
        </section>

        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">Agent</h3>
          <dl class="text-sm m-0">
            <dt class="text-text-muted mt-3">Max steps</dt>
            <dd class="mt-1 ml-0"><input type="number" class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={config!.max_steps} min="1" /></dd>
            <dt class="text-text-muted mt-3">Allowed domains (HTTP)</dt>
            <dd class="mt-1 ml-0">
              <input
                type="text"
                class="w-full max-w-[420px] bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
                value={domainsText}
                oninput={(e) => { config!.agent_allowed_domains = textToDomains((e.target as HTMLInputElement).value); }}
                placeholder="example.com, api.example.com"
              />
            </dd>
          </dl>
        </section>

        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">Sandbox Mode <span class="inline-block text-xs font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full ml-2 bg-surface-elevated text-text-muted align-middle">{config!.sandbox_mode ?? "none"}</span></h3>
          <p class="text-xs text-text-muted leading-relaxed">
            {#if config!.sandbox_mode === "firecracker"}
              Firecracker microVM is active (<code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">ECTO_FC_BINARY</code> is set). Commands run inside an isolated KVM guest.
            {:else if config!.sandbox_mode === "docker"}
              Docker/Podman sandbox is active (<code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">ECTO_DOCKER_IMAGE</code> is set). Commands run in a container with
              <code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">--network=none --read-only --security-opt no-new-privileges</code>.
            {:else}
              No hardware sandbox configured. Set <code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">ECTO_FC_BINARY</code> (Firecracker) or
              <code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">ECTO_DOCKER_IMAGE</code> (Docker/Podman) in your environment to enable isolation.
            {/if}
          </p>
        </section>

        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">EVM Anchoring
            {#if config!.evm_enabled}
              <span class="inline-block text-xs font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full ml-2 bg-success-muted text-success align-middle">✓ enabled</span>
            {:else}
              <span class="inline-block text-xs font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full ml-2 bg-danger-muted text-danger align-middle">× not configured</span>
            {/if}
          </h3>
          <p class="text-xs text-text-muted leading-relaxed">
            {#if config.evm_enabled}
              Anchor transactions will be submitted to the configured EVM chain after each orchestration seal.
            {:else}
              Set <code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">EVM_RPC_URL</code>, <code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">EVM_CHAIN_ID</code>, <code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">EVM_CONTRACT_ADDRESS</code>, and
              <code class="text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md">EVM_PRIVATE_KEY</code> to enable on-chain ledger anchoring.
            {/if}
          </p>
        </section>

        {#if saveError}
          <p class="text-danger text-sm">{saveError}</p>
        {/if}

        <div class="flex gap-4 mt-8">
          <button type="button" class="bg-transparent border border-border-muted/30 rounded-xl text-accent px-5 py-3 text-sm cursor-pointer hover:bg-surface-elevated transition-all duration-200" onclick={load}>↻ Refresh</button>
          <button type="submit" class="bg-accent border-none rounded-xl text-white px-6 py-3 text-sm cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed transition-all duration-200 active:scale-[0.98] shadow-sm shadow-accent/20 hover:shadow-md hover:bg-accent-hover" disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    {:else}
      <p class="text-text-secondary text-sm">Loading…</p>
    {/if}
  </div>

  {#if demoMode}
    <div class="p-8 rounded-2xl max-w-2xl bg-surface shadow-sm">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Demo Mode</h2>
      <p class="text-text-muted text-sm mb-4">
        Reset the test database to erase all sessions, events, snapshots, and action logs.
        This will not affect tokens, webhooks, or policy files.
      </p>
      {#if resetMsg}
        <p class="text-sm mb-3 {resetMsg.startsWith('Reset failed') ? 'text-danger' : 'text-success'}">{resetMsg}</p>
      {/if}
      <button
        type="button"
        class="bg-danger/90 border-none rounded-xl text-white px-6 py-3 text-sm cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed transition-all duration-200 active:scale-[0.98] hover:bg-danger"
        onclick={resetDemoData}
        disabled={resetting}
      >
        {resetting ? "Resetting…" : "Reset Test Database"}
      </button>
    </div>
  {/if}
</div>
