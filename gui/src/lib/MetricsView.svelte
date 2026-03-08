<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  let content = $state("");
  let error = $state("");
  let loading = $state(true);

  onMount(load);

  async function load() {
    if (!isTauri()) {
      error = "Run this app via the Ecto Ledger desktop window (./ectoledger-mac, ./ectoledger-linux, or .\\ectoledger-win.ps1), not in a browser.";
      loading = false;
      return;
    }
    loading = true;
    error = "";
    try {
      content = await invoke<string>("get_prometheus_metrics");
    } catch (e) {
      error = String(e);
      content = "";
    } finally {
      loading = false;
    }
  }
</script>

<div class="flex flex-col gap-6 pb-6">
  <div class="rounded-2xl p-7 bg-surface shadow-sm border border-border-muted/40 flex flex-col flex-1 min-h-0">
    <!-- No px-2.5: the panel's p-7 provides uniform inset on all sides -->
    <div class="flex justify-between items-center mb-6">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted">Prometheus Metrics</h2>
      <button
        class="bg-transparent border border-border-muted/30 rounded-xl text-accent px-5 py-2.5 text-sm cursor-pointer hover:bg-surface-elevated transition-all duration-200 disabled:opacity-60 disabled:cursor-not-allowed"
        onclick={load}
        disabled={loading}
      >
        <!-- ↻ renders unreliably in the Tauri WebView; use plain text -->
        {loading ? "Loading…" : "Refresh"}
      </button>
    </div>

    {#if error}
      <!-- No px-2.5: error text aligns with the panel's own p-7 boundary -->
      <p class="text-danger text-sm">{error}</p>
    {:else if loading}
      <p class="text-text-muted text-sm">Loading metrics…</p>
    {:else}
      <!-- No mx-2.5: the pre already has p-6 inner padding; panel provides outer -->
      <pre class="flex-1 min-h-0 overflow-auto bg-background border border-border-muted/30 rounded-xl p-6 text-sm font-mono text-text-primary whitespace-pre-wrap break-all">{content}</pre>
    {/if}
  </div>
</div>
