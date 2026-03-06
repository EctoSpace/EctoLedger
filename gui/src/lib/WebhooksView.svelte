<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  interface Webhook {
    id: string;
    label: string;
    url: string;
    siem_format: string;
    filter_kinds: string[];
    enabled: boolean;
    created_at: string;
  }

  const ALL_KINDS = [
    "user_prompt", "llm_response", "tool_call", "tool_result",
    "guard_violation", "tripwire_triggered", "key_rotation",
    "session_start", "session_end", "verifiable_credential",
  ];

  const FORMAT_LABELS: Record<string, string> = {
    json: "JSON",
    cef: "CEF (ArcSight)",
    leef: "LEEF (QRadar)",
  };

  let webhooks = $state<Webhook[]>([]);
  let loading = $state(false);
  let error = $state("");
  let success = $state("");

  // Create form
  let newLabel = $state("");
  let newUrl = $state("");
  let newBearer = $state("");
  let newFormat = $state("json");
  let newFilterKinds = $state<string[]>([]);
  let newEnabled = $state(true);
  let creating = $state(false);
  let showCreate = $state(false);

  onMount(load);

  async function load() {
    if (!isTauri()) return;
    loading = true;
    error = "";
    try {
      const data = await invoke<unknown>("get_webhooks");
      webhooks = Array.isArray(data) ? (data as Webhook[]) : [];
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function create() {
    if (!isTauri() || !newLabel.trim() || !newUrl.trim()) return;
    creating = true;
    error = "";
    success = "";
    try {
      await invoke("create_webhook", {
        label: newLabel.trim(),
        url: newUrl.trim(),
        bearerToken: newBearer.trim() || null,
        siemFormat: newFormat,
        filterKinds: newFilterKinds,
        enabled: newEnabled,
      });
      success = "Webhook created.";
      newLabel = "";
      newUrl = "";
      newBearer = "";
      newFormat = "json";
      newFilterKinds = [];
      newEnabled = true;
      showCreate = false;
      await load();
    } catch (e) {
      error = String(e);
    } finally {
      creating = false;
    }
  }

  async function deleteHook(id: string) {
    if (!isTauri() || !confirm("Delete this webhook? This cannot be undone.")) return;
    error = "";
    success = "";
    try {
      await invoke("delete_webhook", { webhookId: id });
      success = "Webhook deleted.";
      await load();
    } catch (e) {
      error = String(e);
    }
  }

  let togglingId = $state<string | null>(null);

  async function toggleHook(wh: Webhook) {
    if (!isTauri() || togglingId) return;
    togglingId = wh.id;
    error = "";
    success = "";
    try {
      await invoke("toggle_webhook", { webhookId: wh.id, enabled: !wh.enabled });
      await load();
    } catch (e) {
      error = String(e);
    } finally {
      togglingId = null;
    }
  }

  function toggleFilterKind(kind: string) {
    if (newFilterKinds.includes(kind)) {
      newFilterKinds = newFilterKinds.filter((k) => k !== kind);
    } else {
      newFilterKinds = [...newFilterKinds, kind];
    }
  }

  function formatKindsDisplay(kinds: string[]): string {
    if (!kinds || kinds.length === 0) return "All events";
    if (kinds.length <= 3) return kinds.join(", ");
    return `${kinds.slice(0, 3).join(", ")} +${kinds.length - 3} more`;
  }

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleString();
  }
</script>

<div class="flex flex-col gap-6 pb-6">
  <h2 class="text-xl font-bold text-text-primary">Webhooks</h2>
  <p class="text-text-muted text-sm">Forward ledger events to external SIEM systems or endpoints.</p>

  {#if error}
    <div class="bg-danger-muted border border-danger/30 text-danger px-4 py-3 rounded-xl text-sm">{error}</div>
  {:else if success}
    <div class="bg-success-muted border border-success/30 text-success px-4 py-3 rounded-xl text-sm">{success}</div>
  {/if}

  <!-- Create panel toggle -->
  <div class="flex items-center gap-4">
    <button class="bg-success hover:bg-success/80 text-white rounded-xl px-6 py-3 text-sm cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 active:scale-[0.98] shadow-sm hover:shadow-md" onclick={() => (showCreate = !showCreate)}>
      {showCreate ? "✕ Cancel" : "+ Add Webhook"}
    </button>
    <button class="bg-transparent border border-border-muted/30 text-text-muted rounded-xl px-4 py-2 text-xs cursor-pointer hover:text-text-primary hover:bg-surface-elevated transition-all duration-200" onclick={load}>↺ Refresh</button>
  </div>

  {#if showCreate}
    <section class="bg-background rounded-2xl px-7 py-6 shadow-sm">
      <h3 class="text-base font-semibold text-text-primary mb-5">New Webhook</h3>
      <div class="flex gap-4 flex-wrap mb-5">
        <div class="flex flex-col gap-1.5 flex-[1.5] min-w-[140px]">
          <label for="wh-label" class="text-xs text-text-muted uppercase tracking-wide">Label</label>
          <input id="wh-label" type="text" bind:value={newLabel} placeholder="e.g. Splunk SIEM" class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-sans focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200" />
        </div>
        <div class="flex flex-col gap-1.5 flex-[2] min-w-[140px]">
          <label for="webhook-url" class="text-xs text-text-muted uppercase tracking-wide">Endpoint URL</label>
          <input id="webhook-url" type="url" bind:value={newUrl} placeholder="https://siem.example.com/events" class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-sans focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200" />
        </div>
        <div class="flex flex-col gap-1.5 flex-1 min-w-[140px]">
          <label for="wh-format" class="text-xs text-text-muted uppercase tracking-wide">SIEM Format</label>
          <select id="wh-format" bind:value={newFormat} class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-sans focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200">
            {#each Object.entries(FORMAT_LABELS) as [val, lbl]}
              <option value={val}>{lbl}</option>
            {/each}
          </select>
        </div>
      </div>

      <div class="flex gap-4 flex-wrap mb-5">
        <div class="flex flex-col gap-1.5 flex-[2] min-w-[140px]">
          <label for="wh-bearer" class="text-xs text-text-muted uppercase tracking-wide">Bearer Token (optional)</label>
          <input id="wh-bearer" type="password" bind:value={newBearer} placeholder="Leave blank for none" class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-sans focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200" />
        </div>
        <div class="flex flex-col gap-1 flex-1 min-w-[140px] justify-end pt-4">
          <label class="flex items-center gap-1.5 cursor-pointer text-sm text-text-primary">
            <input type="checkbox" bind:checked={newEnabled} />
            <span>Enable on create</span>
          </label>
        </div>
      </div>

      <div class="flex flex-col gap-1.5 min-w-[140px] mb-5">
        <span class="text-xs text-text-muted uppercase tracking-wide">Filter Event Kinds <span class="normal-case text-text-muted text-xs">(empty = all events)</span></span>
        <div class="flex flex-wrap gap-2.5 mt-2">
          {#each ALL_KINDS as kind}
            <button
              type="button"
              class="px-3.5 py-2 rounded-xl text-xs cursor-pointer border transition-all duration-200 font-mono {newFilterKinds.includes(kind) ? 'bg-accent-muted border-accent text-accent' : 'bg-border-muted border-border-muted/30 text-text-muted hover:border-text-muted'}"
              onclick={() => toggleFilterKind(kind)}
            >{kind}</button>
          {/each}
        </div>
      </div>

      <div class="flex gap-4 mt-3">
        <button class="bg-success hover:bg-success/80 text-white rounded-xl px-6 py-3 text-sm cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 active:scale-[0.98] shadow-sm hover:shadow-md" onclick={create} disabled={creating || !newLabel.trim() || !newUrl.trim()}>
          {creating ? "Creating…" : "Create Webhook"}
        </button>
      </div>
    </section>
  {/if}

  <!-- Webhook list -->
  <section class="bg-surface rounded-2xl px-7 py-6 shadow-sm">
    <h3 class="text-base font-semibold text-text-primary mb-5">Registered Webhooks</h3>
    {#if loading}
      <p class="text-text-muted text-sm">Loading…</p>
    {:else if webhooks.length === 0}
      <p class="text-text-muted text-sm">No webhooks configured. Click "Add Webhook" to get started.</p>
    {:else}
      <div class="flex flex-col gap-3">
        {#each webhooks as wh}
          <div class="bg-background rounded-2xl px-6 py-5 flex justify-between items-center gap-4 transition-all duration-200 {wh.enabled ? '' : 'opacity-55'}">
            <div class="flex-1 min-w-0 flex flex-col gap-1">
              <div class="flex items-center gap-2.5 flex-wrap">
                <span class="font-semibold text-text-primary text-sm">{wh.label}</span>
                <span class="text-xs bg-border-muted text-text-secondary px-2 py-0.5 rounded-lg font-mono">{FORMAT_LABELS[wh.siem_format] ?? wh.siem_format}</span>
                <span class="text-xs px-2 py-0.5 rounded-full font-semibold {wh.enabled ? 'bg-success-muted text-success' : 'bg-gray-500/15 text-text-secondary'}">
                  {wh.enabled ? "Enabled" : "Disabled"}
                </span>
              </div>
              <div class="text-xs text-accent overflow-hidden text-ellipsis whitespace-nowrap">{wh.url}</div>
              <div class="text-xs text-text-muted">
                Events: {formatKindsDisplay(wh.filter_kinds)} &nbsp;&bull;&nbsp;
                Created: {formatDate(wh.created_at)}
              </div>
            </div>
            <div class="flex gap-3 shrink-0">
              <button
                class="bg-transparent border border-border-muted/30 text-text-muted rounded-xl px-4 py-2 text-xs cursor-pointer hover:text-text-primary hover:bg-surface-elevated transition-all duration-200"
                onclick={() => toggleHook(wh)}
                disabled={togglingId === wh.id}
                title="{wh.enabled ? 'Disable' : 'Enable'} webhook"
              >
                {wh.enabled ? "Disable" : "Enable"}
              </button>
              <button class="bg-danger hover:bg-danger/80 text-white rounded-xl px-4 py-2 text-xs cursor-pointer transition-all duration-200" onclick={() => deleteHook(wh.id)}>Delete</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>
