<!--
  ObserverPanel.svelte — Native Svelte replacement for the iframe Observer.

  Renders a compact session sidebar + event timeline with:
  • Color-coded event type badges matching the Observer palette
  • Hash chain visualisation (previous_hash → content_hash per event)
  • Client-side SHA-256 chain verification via SubtleCrypto
  • Live SSE streaming for running sessions
  • Findings table for "complete" actions

  Data is fetched through Tauri IPC (invoke), which handles auth
  transparently — no postMessage token relay or cross-origin issues.
-->
<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";
  import { StatusDot } from "./ui/index.js";

  // ── Props ──────────────────────────────────────────────────────────────
  interface Props { serverUrl: string; }
  let { serverUrl }: Props = $props();

  // ── Types ──────────────────────────────────────────────────────────────
  interface Session {
    id: string;
    goal: string;
    goal_hash?: string;
    status: string;
    created_at: string;
    finished_at: string | null;
    llm_backend?: string;
    llm_model?: string;
  }

  interface EventRow {
    id?: number;
    sequence: number;
    previous_hash: string;
    content_hash: string;
    payload: Record<string, unknown> | string;
    created_at: string;
  }

  // ── State ──────────────────────────────────────────────────────────────
  let sessions       = $state<Session[]>([]);
  let activeId       = $state<string | null>(null);
  let activeSession  = $state<Session | null>(null);
  let events         = $state<EventRow[]>([]);
  let eventsLoading  = $state(false);
  let sessionsLoading = $state(false);
  let searchQuery    = $state("");
  let statusFilter   = $state<string | null>(null);
  let error          = $state("");

  // Chain verification
  type VerifyResult = "pass" | "fail";
  let verifyResults = $state<Record<number, VerifyResult>>({});
  let verifyBanner  = $state<{ type: "pass" | "fail" | "running"; text: string } | null>(null);
  let verifying     = $state(false);

  // Expanded event bodies
  let expandedBodies = $state<Set<number>>(new Set());

  // SSE for live updates on running sessions
  let sseSource: EventSource | null = null;
  let sseToken  = "";
  let alive     = true;

  // Auto-refresh
  let refreshInterval: ReturnType<typeof setInterval> | null = null;

  // ── Lifecycle ──────────────────────────────────────────────────────────
  onMount(async () => {
    if (!isTauri()) return;
    try {
      sseToken = await invoke<string>("observer_token");
    } catch { /* non-critical — SSE won't work but IPC still does */ }
    await loadSessions();
    refreshInterval = setInterval(() => {
      if (!document.hidden) loadSessions();
    }, 10_000);
  });

  onDestroy(() => {
    alive = false;
    if (sseSource) { sseSource.close(); sseSource = null; }
    if (refreshInterval) clearInterval(refreshInterval);
  });

  // ── Event type → colour map (matches Observer palette) ─────────────
  const TYPE_COLORS: Record<string, { border: string; dot: string; bg?: string }> = {
    genesis:               { border: "#a371f7", dot: "#a371f7" },
    prompt_input:          { border: "#3fb950", dot: "#3fb950" },
    thought:               { border: "#58a6ff", dot: "#58a6ff" },
    action:                { border: "#d29922", dot: "#d29922" },
    observation:           { border: "#a371f7", dot: "#a371f7" },
    schema_error:          { border: "#f85149", dot: "#f85149", bg: "rgba(248,81,73,0.06)" },
    circuit_breaker:       { border: "#f85149", dot: "#f85149", bg: "rgba(248,81,73,0.06)" },
    approval_required:     { border: "#f0883e", dot: "#f0883e" },
    approval_decision:     { border: "#3fb950", dot: "#3fb950" },
    anchor:                { border: "#a371f7", dot: "#a371f7" },
    key_rotation:          { border: "#58a6ff", dot: "#58a6ff" },
    verifiable_credential: { border: "#a371f7", dot: "#a371f7" },
    cross_ledger_seal:     { border: "#58a6ff", dot: "#58a6ff" },
    chat_message:          { border: "#8b949e", dot: "#8b949e" },
  };

  const DEFAULT_COLOR = { border: "#30363d", dot: "#30363d" };

  function typeColor(t: string) { return TYPE_COLORS[t] ?? DEFAULT_COLOR; }

  // ── Data fetching ──────────────────────────────────────────────────────
  async function loadSessions() {
    if (!isTauri()) return;
    sessionsLoading = true;
    try {
      const data = await invoke<unknown>("get_sessions", {
        status: statusFilter || null,
        limit: 100,
        offset: 0,
      });
      if (!alive) return;
      sessions = Array.isArray(data) ? data as Session[] : [];
    } catch (e) {
      error = String(e);
    } finally {
      sessionsLoading = false;
    }
  }

  async function selectSession(id: string) {
    if (!isTauri()) return;
    activeId = id;
    activeSession = sessions.find(s => s.id === id) ?? null;
    events = [];
    eventsLoading = true;
    verifyResults = {};
    verifyBanner = null;
    expandedBodies = new Set();

    // Stop any prior SSE
    if (sseSource) { sseSource.close(); sseSource = null; }

    try {
      const data = await invoke<unknown>("get_events", { sessionId: id });
      if (!alive || activeId !== id) return;
      events = normaliseEvents(data);
    } catch (e) {
      if (!alive || activeId !== id) return;
      error = `Failed to load events: ${e}`;
    } finally {
      eventsLoading = false;
    }

    // Start SSE for running sessions
    if (activeSession?.status === "running") {
      startSSE(id);
    }
  }

  function normaliseEvents(data: unknown): EventRow[] {
    if (!Array.isArray(data)) return [];
    return (data as Record<string, unknown>[]).map(e => ({
      id: e.id as number | undefined,
      sequence: (e.sequence as number) ?? 0,
      previous_hash: (e.previous_hash as string) ?? "",
      content_hash: (e.content_hash as string) ?? "",
      payload: typeof e.payload === "string" ? (() => { try { return JSON.parse(e.payload as string); } catch { return e.payload; } })() : (e.payload as Record<string, unknown>),
      created_at: (e.created_at as string) ?? "",
    }));
  }

  // ── SSE live streaming ─────────────────────────────────────────────────
  const SSE_BACKOFF_INIT = 2000;
  const SSE_BACKOFF_MAX  = 30000;
  let sseBackoff = SSE_BACKOFF_INIT;

  function startSSE(sessionId: string) {
    if (!serverUrl || !sseToken) return;
    try {
      const url = `${serverUrl}/api/stream?session_id=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(sseToken)}`;
      const es = new EventSource(url);
      sseSource = es;

      es.onopen = () => { sseBackoff = SSE_BACKOFF_INIT; };

      es.onmessage = (msg) => {
        if (!alive || activeId !== sessionId) { es.close(); return; }
        try {
          const raw = JSON.parse(msg.data) as Record<string, unknown>;
          // If it has a sequence and content_hash, treat as a full event
          if (raw.sequence !== undefined && raw.content_hash) {
            const ev: EventRow = {
              sequence: raw.sequence as number,
              previous_hash: (raw.previous_hash as string) ?? "",
              content_hash: (raw.content_hash as string) ?? "",
              payload: typeof raw.payload === "string" ? (() => { try { return JSON.parse(raw.payload as string); } catch { return raw.payload; } })() : (raw.payload as Record<string, unknown>),
              created_at: (raw.created_at as string) ?? new Date().toISOString(),
            };
            // Only append if we don't already have this sequence
            if (!events.some(e => e.sequence === ev.sequence)) {
              events = [...events, ev];
            }
          }
          // Check for session completion
          const payload = typeof raw.payload === "object" ? raw.payload as Record<string, unknown> : null;
          const evType = payload?.type ?? raw.type;
          if (evType === "action" && (payload as any)?.name === "complete") {
            // Session is done — reload to get the final state
            es.close();
            sseSource = null;
            loadSessions();
          }
        } catch { /* ignore unparseable */ }
      };

      es.addEventListener("event", (e: Event) => {
        const msg = e as MessageEvent;
        if (!alive || activeId !== sessionId) { es.close(); return; }
        try {
          const raw = JSON.parse(msg.data) as Record<string, unknown>;
          if (raw.sequence !== undefined && raw.content_hash) {
            const ev: EventRow = {
              sequence: raw.sequence as number,
              previous_hash: (raw.previous_hash as string) ?? "",
              content_hash: (raw.content_hash as string) ?? "",
              payload: typeof raw.payload === "string" ? (() => { try { return JSON.parse(raw.payload as string); } catch { return raw.payload; } })() : (raw.payload as Record<string, unknown>),
              created_at: (raw.created_at as string) ?? new Date().toISOString(),
            };
            if (!events.some(e => e.sequence === ev.sequence)) {
              events = [...events, ev];
            }
          }
        } catch { /* ignore */ }
      });

      es.onerror = () => {
        es.close();
        sseSource = null;
        if (alive && activeId === sessionId) {
          setTimeout(() => {
            if (alive && activeId === sessionId) startSSE(sessionId);
          }, sseBackoff);
          sseBackoff = Math.min(sseBackoff * 2, SSE_BACKOFF_MAX);
        }
      };
    } catch {
      // EventSource unavailable — silently fall back to manual refresh
    }
  }

  // ── Payload formatting ─────────────────────────────────────────────────
  function parsePayload(raw: unknown): Record<string, unknown> {
    if (typeof raw === "string") { try { return JSON.parse(raw); } catch { return { type: "unknown", content: raw }; } }
    if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw as Record<string, unknown>;
    return { type: "unknown", content: String(raw) };
  }

  function eventType(ev: EventRow): string {
    const p = parsePayload(ev.payload);
    return (p.type as string) ?? "unknown";
  }

  function formatType(t: string): string {
    return t.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  }

  function formatPayloadContent(ev: EventRow): string {
    const p = parsePayload(ev.payload);
    const t = (p.type as string) ?? "";
    switch(t) {
      case "genesis":            return (p.message as string) ?? "";
      case "prompt_input":       return (p.content as string) ?? "";
      case "thought":            return (p.content as string) ?? "";
      case "observation":        return (p.content as string) ?? "";
      case "schema_error":       return `Schema Error (attempt ${p.attempt}/${p.max_attempts}): ${p.message ?? ""}`;
      case "circuit_breaker":    return `Circuit breaker: ${p.reason ?? ""} (${p.consecutive_failures} failures)`;
      case "action": {
        const name = (p.name as string) ?? "";
        let paramStr = "";
        if (p.params) {
          const params = p.params as Record<string, unknown>;
          if (params.command) paramStr = String(params.command);
          else if (params.path) paramStr = String(params.path);
          else if (params.url) paramStr = String(params.url);
          else paramStr = JSON.stringify(p.params, null, 2);
        }
        return name + (paramStr ? ": " + paramStr : "");
      }
      case "approval_required":  return `Approval required for ${p.action_name ?? ""}: ${p.action_params_summary ?? ""}`;
      case "approval_decision":  return `Approval ${p.approved ? "granted" : "denied"}${p.reason ? " — " + p.reason : ""}`;
      case "cross_ledger_seal":  return `Cross-ledger seal: ${shortHash(p.seal_hash as string)}…`;
      case "anchor":             return `Anchored: ${shortHash(p.ledger_tip_hash as string)}…${p.bitcoin_block_height ? ` (block ${p.bitcoin_block_height})` : ""}`;
      case "key_rotation":       return `Key rotation #${p.rotation_index}: ${shortHash(p.new_public_key as string)}…`;
      case "verifiable_credential": return `VC JWT: ${((p.vc_jwt as string) ?? "").substring(0, 40)}…`;
      case "chat_message":       return `[${p.role ?? ""}] ${p.content ?? ""}`;
      default:                   return JSON.stringify(p, null, 2);
    }
  }

  function shortHash(h: unknown): string {
    if (typeof h !== "string" || !h) return "—";
    return h.substring(0, 8);
  }

  function fmtTime(iso: string): string {
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  }

  function statusVariant(s: string): "success" | "warning" | "danger" | "default" {
    switch(s) {
      case "running": return "success";
      case "completed": return "default";
      case "failed": return "danger";
      case "aborted": return "warning";
      default: return "default";
    }
  }

  function getFindings(ev: EventRow): Record<string, unknown>[] | null {
    const p = parsePayload(ev.payload);
    if ((p.type as string) !== "action" || (p.name as string) !== "complete") return null;
    const params = p.params as Record<string, unknown> | undefined;
    if (!params || !Array.isArray(params.findings)) return null;
    return params.findings as Record<string, unknown>[];
  }

  function sevClass(s: string): string {
    const lower = (s ?? "").toLowerCase();
    if (lower === "critical") return "text-red-500 font-bold";
    if (lower === "high") return "text-orange-400 font-semibold";
    if (lower === "medium") return "text-yellow-400";
    return "text-text-secondary";
  }

  // ── Sidebar filtering ─────────────────────────────────────────────────
  function filteredSessions(): Session[] {
    let list = sessions;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(s =>
        s.id.toLowerCase().includes(q) ||
        (s.goal ?? "").toLowerCase().includes(q)
      );
    }
    return list;
  }

  function toggleBody(seq: number) {
    expandedBodies = new Set(expandedBodies);
    if (expandedBodies.has(seq)) expandedBodies.delete(seq);
    else expandedBodies.add(seq);
  }

  // ── Chain verification (SHA-256 via SubtleCrypto) ──────────────────────

  // Canonical payload JSON matching Rust's serde serialisation
  const FIELD_ORDER: Record<string, string[]> = {
    genesis:                 ["type","message"],
    prompt_input:            ["type","content"],
    thought:                 ["type","content"],
    schema_error:            ["type","message","attempt","max_attempts"],
    circuit_breaker:         ["type","reason","consecutive_failures"],
    action:                  ["type","name","params"],
    observation:             ["type","content"],
    approval_required:       ["type","gate_id","action_name","action_params_summary"],
    approval_decision:       ["type","gate_id","approved","reason"],
    cross_ledger_seal:       ["type","seal_hash","session_ids","session_tip_hashes"],
    anchor:                  ["type","ledger_tip_hash","ots_proof_hex","bitcoin_block_height"],
    key_rotation:            ["type","new_public_key","rotation_index"],
    verifiable_credential:   ["type","vc_jwt"],
    chat_message:            ["type","role","content","backend","model"],
  };

  const SKIP_IF_NONE: Record<string, Record<string, boolean>> = {
    chat_message: { backend: true, model: true },
  };

  function canonicalValue(v: unknown): string {
    if (v === null || v === undefined) return "null";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (typeof v === "number") {
      if (Number.isInteger(v)) return String(v);
      return JSON.stringify(v);
    }
    if (typeof v === "string") return JSON.stringify(v);
    if (Array.isArray(v)) {
      return "[" + v.map(canonicalValue).join(",") + "]";
    }
    const keys = Object.keys(v as object).sort();
    const parts = keys.map(k => JSON.stringify(k) + ":" + canonicalValue((v as Record<string, unknown>)[k]));
    return "{" + parts.join(",") + "}";
  }

  function canonicalPayloadJson(payload: Record<string, unknown>): string {
    const t = payload.type as string;
    const order = FIELD_ORDER[t];
    if (!order) return canonicalValue(payload);
    const skips = SKIP_IF_NONE[t] ?? {};
    const parts: string[] = [];
    for (const k of order) {
      const val = payload[k];
      if (skips[k] && (val === null || val === undefined)) continue;
      parts.push(JSON.stringify(k) + ":" + canonicalValue(val));
    }
    return "{" + parts.join(",") + "}";
  }

  async function sha256hex(str: string): Promise<string> {
    const buf = new TextEncoder().encode(str);
    const ab = await crypto.subtle.digest("SHA-256", buf);
    const arr = new Uint8Array(ab);
    return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  const ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

  async function verifyChain() {
    if (!activeId || events.length === 0) return;
    verifying = true;
    verifyResults = {};
    verifyBanner = { type: "running", text: "Verifying hash chain…" };

    try {
      // Re-fetch events to ensure we have the latest sorted set
      const data = await invoke<unknown>("get_events", { sessionId: activeId });
      const evts = normaliseEvents(data).sort((a, b) => a.sequence - b.sequence);

      let expectedPrev = ZERO_HASH;
      for (const ev of evts) {
        if (ev.previous_hash !== expectedPrev) {
          verifyResults = { ...verifyResults, [ev.sequence]: "fail" };
          verifyBanner = {
            type: "fail",
            text: `Chain broken at seq ${ev.sequence} — previous_hash mismatch (expected ${shortHash(expectedPrev)}… got ${shortHash(ev.previous_hash)}…)`
          };
          verifying = false;
          return;
        }
        const payload = parsePayload(ev.payload);
        const input = ev.previous_hash + "\0" + String(ev.sequence) + "\0" + canonicalPayloadJson(payload);
        const computed = await sha256hex(input);
        if (computed !== ev.content_hash) {
          verifyResults = { ...verifyResults, [ev.sequence]: "fail" };
          verifyBanner = {
            type: "fail",
            text: `Chain broken at seq ${ev.sequence} — content_hash mismatch (expected ${shortHash(computed)}… got ${shortHash(ev.content_hash)}…)`
          };
          verifying = false;
          return;
        }
        verifyResults = { ...verifyResults, [ev.sequence]: "pass" };
        expectedPrev = ev.content_hash;
      }

      verifyBanner = {
        type: "pass",
        text: `Chain verified — ${evts.length} event${evts.length !== 1 ? "s" : ""}, all hashes valid`
      };
    } catch (e) {
      verifyBanner = { type: "fail", text: `Verification error: ${e}` };
    } finally {
      verifying = false;
    }
  }
</script>

<!-- ═══════════════════════════════════════════════════════════════════════
  Template
═══════════════════════════════════════════════════════════════════════ -->
<div class="flex h-full min-h-0 overflow-hidden rounded-2xl border border-border-muted/20 bg-surface">
  <!-- ── Sidebar ─────────────────────────────────────────────────────── -->
  <aside class="w-56 min-w-56 flex flex-col border-r border-border-muted/30 bg-surface overflow-hidden">
    <!-- Header -->
    <div class="px-3 pt-3 pb-2">
      <h3 class="text-[11px] font-bold uppercase tracking-wider text-text-muted m-0 mb-2">Sessions</h3>
      <input
        type="text"
        class="w-full bg-surface-elevated/30 border border-border-muted/25 rounded-lg text-text-primary text-xs px-2.5 py-1.5 outline-none focus:border-accent/50 transition-colors placeholder:text-text-muted"
        placeholder="Search…"
        bind:value={searchQuery}
      />
    </div>

    <!-- Filter pills -->
    <div class="flex gap-1 px-3 pb-2 flex-wrap">
      {#each [null, "running", "completed", "failed"] as f}
        <button
          class="text-[10px] px-2 py-0.5 rounded-full border transition-colors cursor-pointer
            {statusFilter === f
              ? 'bg-accent/15 border-accent/40 text-accent font-semibold'
              : 'bg-transparent border-border-muted/30 text-text-muted hover:text-text-secondary hover:border-border-muted/50'}"
          onclick={() => { statusFilter = f; loadSessions(); }}
        >
          {f ? f.charAt(0).toUpperCase() + f.slice(1) : "All"}
        </button>
      {/each}
    </div>

    <!-- Session list -->
    <div class="flex-1 overflow-y-auto px-1.5 pb-2">
      {#if sessionsLoading && sessions.length === 0}
        <p class="text-text-muted text-[10px] text-center py-4">Loading…</p>
      {/if}
      {#each filteredSessions() as s (s.id)}
        <button
          class="w-full text-left px-2.5 py-2 rounded-lg mb-0.5 border border-transparent transition-colors cursor-pointer
            {activeId === s.id
              ? 'bg-accent/10 border-accent/25'
              : 'bg-transparent hover:bg-surface-elevated/40'}"
          onclick={() => selectSession(s.id)}
        >
          <div class="flex items-center gap-1.5 mb-0.5">
            <StatusDot status={s.status === "running" ? "running" : s.status === "completed" ? "passed" : s.status === "failed" ? "failed" : "idle"} />
            <span class="text-[10px] font-mono text-text-muted">{s.id.slice(0, 8)}…</span>
          </div>
          <p class="text-[11px] text-text-primary m-0 line-clamp-2 leading-snug">{s.goal || "—"}</p>
          <span class="text-[9px] text-text-muted">{fmtTime(s.created_at)}</span>
        </button>
      {/each}
      {#if !sessionsLoading && filteredSessions().length === 0}
        <p class="text-text-muted text-[10px] text-center py-4">No sessions</p>
      {/if}
    </div>
  </aside>

  <!-- ── Main panel ──────────────────────────────────────────────────── -->
  <div class="flex-1 min-w-0 flex flex-col overflow-hidden">
    {#if !activeId}
      <!-- Empty state -->
      <div class="flex-1 flex items-center justify-center">
        <p class="text-text-muted text-xs">Select a session to view its event timeline</p>
      </div>
    {:else}
      <!-- Session header -->
      <div class="flex items-center gap-3 px-4 py-3 border-b border-border-muted/20 min-h-[44px]">
        <span class="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full
          {activeSession?.status === 'running' ? 'bg-[rgba(63,185,80,0.15)] text-[#3fb950]'
          : activeSession?.status === 'completed' ? 'bg-[rgba(88,166,255,0.15)] text-[#58a6ff]'
          : activeSession?.status === 'failed' ? 'bg-[rgba(248,81,73,0.15)] text-[#f85149]'
          : 'bg-[rgba(139,148,158,0.15)] text-[#8b949e]'}"
        >
          {activeSession?.status ?? "—"}
        </span>
        <span class="text-xs text-text-primary truncate flex-1">{activeSession?.goal ?? "—"}</span>
        <button
          class="text-[10px] font-semibold text-accent bg-accent/10 border border-accent/25 rounded-lg px-3 py-1 cursor-pointer hover:bg-accent/20 transition-colors disabled:opacity-40 disabled:cursor-default shrink-0"
          onclick={verifyChain}
          disabled={verifying || events.length === 0}
        >
          {verifying ? "Verifying…" : "✓ Verify Chain"}
        </button>
      </div>

      <!-- Verify banner -->
      {#if verifyBanner}
        <div class="flex items-center gap-2 px-4 py-2 text-xs animate-[slidein_0.2s_ease]
          {verifyBanner.type === 'pass' ? 'bg-[rgba(63,185,80,0.1)] text-[#3fb950] border-b border-[rgba(63,185,80,0.2)]'
          : verifyBanner.type === 'fail' ? 'bg-[rgba(248,81,73,0.1)] text-[#f85149] border-b border-[rgba(248,81,73,0.2)]'
          : 'bg-[rgba(210,153,34,0.1)] text-[#d29922] border-b border-[rgba(210,153,34,0.2)]'}"
        >
          <span>{verifyBanner.type === "pass" ? "✅" : verifyBanner.type === "fail" ? "❌" : "⏳"}</span>
          <span>{verifyBanner.text}</span>
        </div>
      {/if}

      <!-- Timeline -->
      <div class="flex-1 overflow-y-auto px-4 py-3 pl-10">
        {#if eventsLoading}
          <p class="text-text-muted text-xs py-8 text-center">Loading events…</p>
        {:else if events.length === 0}
          <p class="text-text-muted text-xs py-8 text-center">No events yet{activeSession?.status === "running" ? " — waiting for stream…" : ""}</p>
        {:else}
          {#each events as ev, i (ev.sequence)}
            {@const et = eventType(ev)}
            {@const color = typeColor(et)}
            {@const vr = verifyResults[ev.sequence]}
            {@const content = formatPayloadContent(ev)}
            {@const findings = getFindings(ev)}
            {@const isLong = content.length > 300}
            {@const isExpanded = expandedBodies.has(ev.sequence)}

            <div
              class="relative mb-0.5 py-2 px-3 pl-4 rounded-md transition-colors hover:bg-surface-elevated/40"
              style:border-left="3px solid {color.border}"
              style:background={color.bg ?? "transparent"}
            >
              <!-- Timeline connector line -->
              <div
                class="absolute -left-5 top-0 w-0.5 bg-border-muted"
                style:bottom={i === events.length - 1 ? "50%" : "-2px"}
              ></div>
              <!-- Timeline dot -->
              <div
                class="absolute -left-[22px] top-4 w-2.5 h-2.5 rounded-full border-2 border-background"
                style:background={color.dot}
              ></div>

              <!-- Event header -->
              <div class="flex items-center gap-2 mb-1">
                <span class="text-[10px] font-mono text-text-muted">#{ev.sequence}</span>
                <span
                  class="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-px rounded-full bg-surface-elevated/60"
                  style:color={color.border}
                >{formatType(et)}</span>
                <span class="text-[10px] text-text-muted ml-auto">{fmtTime(ev.created_at)}</span>
                {#if vr === "pass"}
                  <span class="text-[10px] text-[#3fb950]" title="Hash verified">✓</span>
                {:else if vr === "fail"}
                  <span class="text-[10px] text-[#f85149]" title="Hash mismatch">✗</span>
                {/if}
              </div>

              <!-- Event body -->
              <div
                class="text-[11px] text-text-primary leading-relaxed whitespace-pre-wrap break-words font-mono
                  {!isExpanded && isLong ? 'max-h-[120px] overflow-hidden' : ''}"
              >{content}</div>
              {#if isLong}
                <button
                  class="text-[10px] text-accent bg-transparent border-none cursor-pointer p-0 mt-1 hover:underline"
                  onclick={() => toggleBody(ev.sequence)}
                >{isExpanded ? "Show less" : "Show more"}</button>
              {/if}

              <!-- Findings table -->
              {#if findings && findings.length > 0}
                <div class="mt-2 overflow-x-auto">
                  <table class="w-full text-[10px] border-collapse">
                    <thead>
                      <tr class="border-b border-border-muted/30">
                        <th class="text-left py-1 px-2 text-text-muted font-semibold">Severity</th>
                        <th class="text-left py-1 px-2 text-text-muted font-semibold">Title</th>
                        <th class="text-left py-1 px-2 text-text-muted font-semibold">Evidence</th>
                        <th class="text-left py-1 px-2 text-text-muted font-semibold">Recommendation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each findings as f}
                        <tr class="border-b border-border-muted/15">
                          <td class="py-1 px-2 {sevClass(String(f.severity ?? 'low'))}">{f.severity ?? "low"}</td>
                          <td class="py-1 px-2 text-text-primary">{f.title ?? ""}</td>
                          <td class="py-1 px-2 text-text-secondary">{f.evidence ?? ""}</td>
                          <td class="py-1 px-2 text-text-secondary">{f.recommendation ?? ""}</td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}

              <!-- Hash chain -->
              <div class="flex items-center gap-1.5 mt-1.5 text-[9px] font-mono">
                <span class="px-1.5 py-px rounded border border-border-muted/30 text-text-muted" title="previous_hash: {ev.previous_hash}">{shortHash(ev.previous_hash)}</span>
                <span class="text-text-muted">→</span>
                <span class="px-1.5 py-px rounded border border-accent/25 text-accent" title="content_hash: {ev.content_hash}">{shortHash(ev.content_hash)}</span>
              </div>
            </div>
          {/each}
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  @keyframes slidein {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: none; }
  }
</style>
