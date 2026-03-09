<!--
  LiveDashboard.svelte — Real-time SSE event feed + observer pop-out (Track 5).

  Features:
  • Server-Sent Events from /api/stream?token=<observerToken>
  • Auto-scrolling event log (pauses on hover, resumes on leave)
  • Metrics cards refreshed on every SSE heartbeat
  • "Pop out" opens a frameless WebviewWindow with the built-in observer page
-->
<script lang="ts">
  import { onDestroy, onMount, tick } from "svelte";
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
  import { Badge, Card } from "./ui/index.js";

  // ── Props ─────────────────────────────────────────────────────────────────
  interface Props { serverUrl: string; }
  let { serverUrl }: Props = $props();

  // ── State ─────────────────────────────────────────────────────────────────
  interface LiveEvent {
    id: number;
    ts: string;
    category: string;
    data: string;
    isError: boolean;
  }

  let events     = $state<LiveEvent[]>([]);
  let connected  = $state(false);
  let error      = $state("");
  let paused     = $state(false);   // auto-scroll only
  let eventCount = $state(0);
  let metrics    = $state<Record<string, unknown> | null>(null);
  let feedEl     = $state<HTMLElement | null>(null);

  let sseSource: EventSource | null = null;
  let alive = true;

  // ── Exponential back-off state ─────────────────────────────────────────────
  // Starts at 2 s, doubles on each consecutive error, caps at 120 s.
  // Resets to the initial value on a successful open.
  const BACKOFF_INITIAL = 2_000;
  const BACKOFF_MAX     = 120_000;
  let backoffMs = BACKOFF_INITIAL;

  // ── SSE connection ─────────────────────────────────────────────────────────
  async function connect() {
    if (!isTauri()) {
      error = "Live Dashboard is only available in the EctoLedger desktop app.";
      return;
    }
    if (!serverUrl) return;
    // Don't open a new connection while the tab is hidden — wait for visibility.
    if (document.hidden) return;

    let token: string;
    try {
      token = await invoke<string>("observer_token");
    } catch (e) {
      error = `Could not retrieve observer token: ${e}`;
      return;
    }

    const url = `${serverUrl}/api/stream?token=${encodeURIComponent(token)}`;
    sseSource = new EventSource(url);

    sseSource.onopen = () => {
      if (!alive) return;
      connected = true;
      error = "";
      backoffMs = BACKOFF_INITIAL; // reset on successful connection
    };

    sseSource.onerror = () => {
      if (!alive) return;
      connected = false;
      const retryAfterSec = Math.round(backoffMs / 1_000);
      error = `Stream disconnected — reconnecting in ${retryAfterSec} s…`;
      sseSource?.close();
      sseSource = null;
      const delay = backoffMs;
      backoffMs = Math.min(backoffMs * 2, BACKOFF_MAX); // double for next failure
      setTimeout(() => { if (alive && !document.hidden) connect(); }, delay);
    };

    sseSource.addEventListener("event", async (e: MessageEvent) => {
      if (!alive) return;
      let category = "event";
      let data = e.data as string;
      let isError = false;

      try {
        const parsed = JSON.parse(e.data as string) as Record<string, unknown>;
        if (parsed.type) category = String(parsed.type);
        if (parsed.error) { isError = true; category = "error"; data = String(parsed.error); }
        else if (parsed.data) data = typeof parsed.data === "string" ? parsed.data : JSON.stringify(parsed.data, null, 2);
        // refresh metrics on heartbeat
        if (category === "heartbeat" || category === "metrics") {
          loadMetrics();
        }
      } catch {
        // raw string event
      }

      const ev: LiveEvent = {
        id: ++eventCount,
        ts: new Date().toLocaleTimeString(),
        category,
        data,
        isError,
      };
      events = [...events.slice(-499), ev]; // keep last 500

      if (!paused) {
        await tick();
        feedEl?.scrollTo({ top: feedEl.scrollHeight, behavior: "smooth" });
      }
    });
  }

  // ── Metrics ────────────────────────────────────────────────────────────────
  async function loadMetrics() {
    try {
      const data = await invoke<unknown>("get_metrics");
      if (!alive) return;
      metrics = data && typeof data === "object" && !Array.isArray(data)
        ? (data as Record<string, unknown>)
        : null;
    } catch { /* non-fatal */ }
  }

  // ── Pop-out observer ───────────────────────────────────────────────────────
  async function popOut() {
    try {
      const token = await invoke<string>("observer_token");
      const observerUrl = `${serverUrl}/?token=${encodeURIComponent(token)}`;
      new WebviewWindow("observer", {
        url: observerUrl,
        title: "EctoLedger Observer",
        width: 900,
        height: 640,
        resizable: true,
        decorations: true,
      });
    } catch (e) {
      error = `Failed to open observer window: ${e}`;
    }
  }

  // ── Visibility-aware reconnect ────────────────────────────────────────────
  function onVisibilityChange() {
    if (!alive) return;
    if (!document.hidden && !sseSource) {
      // Tab came back into view and the connection is dead — reconnect immediately.
      backoffMs = BACKOFF_INITIAL;
      connect();
    } else if (document.hidden && sseSource) {
      // Tab hidden — close connection to save resources; will reopen on visibility.
      sseSource.close();
      sseSource = null;
      connected = false;
    }
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────
  onMount(() => {
    document.addEventListener("visibilitychange", onVisibilityChange);
    connect();
    loadMetrics();
  });

  onDestroy(() => {
    alive = false;
    document.removeEventListener("visibilitychange", onVisibilityChange);
    sseSource?.close();
    sseSource = null;
  });

  // ── Helpers ────────────────────────────────────────────────────────────────
  function categoryColor(cat: string): string {
    if (cat === "error") return "text-danger";
    if (cat === "warning") return "text-warning";
    if (cat === "heartbeat") return "text-text-muted";
    if (cat === "action") return "text-blue-400";
    if (cat === "tripwire") return "text-red-400";
    if (cat === "chat_message" || cat === "chat") return "text-yellow-400";
    return "text-text-secondary";
  }

  function formatKey(k: string): string {
    return k.split("_").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
  }
</script>

<div class="flex flex-col gap-7">

  <!-- Header ---------------------------------------------------------------->
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div class="min-w-0">
      <h1 class="text-2xl font-semibold text-text-primary tracking-tight">Active Audit</h1>
      <p class="text-sm text-text-muted mt-0.5">Real-time audit event stream</p>
    </div>
    <div class="flex items-center gap-3 shrink-0">
      <div class="flex items-center gap-2">
        {#if connected}
          <Badge variant="success" dot>Connected</Badge>
        {:else if error}
          <Badge variant="danger" dot>Disconnected</Badge>
        {:else}
          <Badge variant="default" dot>Connecting…</Badge>
        {/if}
      </div>
    </div>
  </div>

  {#if error}
    <div class="p-3 rounded-lg bg-danger-muted border border-danger/30 text-sm text-danger">{error}</div>
  {/if}

  <!-- Metrics cards --------------------------------------------------------->
  {#if metrics && Object.keys(metrics).length > 0}
    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-5">
      {#each Object.entries(metrics) as [key, value]}
        {#if value !== null && typeof value === "object" && !Array.isArray(value)}
          <!-- Nested object: render each sub-key as its own card -->
          {#each Object.entries(value as Record<string, unknown>) as [subKey, subVal]}
            {@const sv = String(subVal)}
            <div class="bg-surface rounded-2xl p-6 shadow-sm">
              <p class="text-[10px] uppercase tracking-widest text-text-muted font-semibold mb-1">{formatKey(key)} · {formatKey(subKey)}</p>
              <p class="text-xl font-bold text-text-primary truncate" title={sv}>{sv}</p>
            </div>
          {/each}
        {:else}
          {@const displayVal = String(value)}
          <div class="bg-surface rounded-2xl p-6 shadow-sm">
            <p class="text-[10px] uppercase tracking-widest text-text-muted font-semibold mb-1.5">{formatKey(key)}</p>
            <p class="text-xl font-bold text-text-primary truncate" title={displayVal}>{displayVal}</p>
          </div>
        {/if}
      {/each}
    </div>
  {/if}

  <!-- Event feed ------------------------------------------------------------>
  <Card title="Event Stream" subtitle="{eventCount} events">
    {#snippet children()}
      <div class="flex flex-col gap-2 min-h-0">
        <!-- Controls -->
        <div class="flex items-center justify-between">
          <p class="text-xs text-text-muted">{paused ? "Auto-scroll paused" : "Auto-scrolling"}</p>
          <div class="flex gap-2">
            <button
              class="text-xs px-4 py-2 rounded-xl bg-surface border border-border-muted/20 text-text-muted hover:bg-surface-elevated transition-all duration-200"
              onclick={() => (paused = !paused)}
            >
              {paused ? "▶ Resume" : "⏸ Pause"}
            </button>
            <button
              class="text-xs px-4 py-2 rounded-xl bg-surface border border-border-muted/20 text-text-muted hover:bg-surface-elevated transition-all duration-200"
              onclick={() => { events = []; eventCount = 0; }}
            >
              ✕ Clear
            </button>
          </div>
        </div>

        <!-- Log -->
        <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
        <div
          bind:this={feedEl}
          role="log"
          aria-live="polite"
          aria-label="Live event feed"
          class="min-h-48 max-h-[28rem] overflow-y-auto bg-background rounded-xl border border-border-muted/15 p-5 font-mono text-xs space-y-2"
          onmouseenter={() => (paused = true)}
          onmouseleave={() => (paused = false)}
        >
          {#if events.length === 0}
            <p class="text-text-muted italic">Waiting for events…</p>
          {:else}
            {#each events as ev (ev.id)}
              <div class="flex gap-2 leading-snug">
                <span class="text-text-muted shrink-0">{ev.ts}</span>
                <span class="shrink-0 uppercase font-semibold {categoryColor(ev.category)}">[{ev.category}]</span>
                <span class="text-text-primary break-all whitespace-pre-wrap">{ev.data}</span>
              </div>
            {/each}
          {/if}
        </div>
      </div>
    {/snippet}
  </Card>

</div>
