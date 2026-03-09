<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-shell";
  import { onMount, onDestroy } from "svelte";
  import ObserverPanel from "./ObserverPanel.svelte";

  let { serverUrl = "", onNavigateToTab }: { serverUrl?: string; onNavigateToTab?: (tab: string) => void } = $props();
  // Initialized to empty string; set via Tauri invoke("server_url") in onMount.
  // Keeping this empty prevents any accidental fetch against a hardcoded localhost
  // before the real backend URL is resolved (important in containerised deployments).
  let dashboardUrl = $state("");
  let observerToken = $state("");
  let metrics = $state<Record<string, unknown> | null>(null);
  let metricsErr = $state("");
  let tauriReady = $state(false);
  let pollTimeout = $state<ReturnType<typeof setTimeout> | null>(null);
  let _alive = true;

  function formatMetricKey(k: string): string {
    return k
      .split("_")
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
      .join(" ");
  }

  function formatMetricValue(v: unknown): string {
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      const entries = Object.entries(v as Record<string, unknown>);
      if (entries.length > 0) {
        return entries
          .map(([k, val]) => `${formatMetricKey(k)}: ${val}`)
          .join(", ");
      }
    }
    return String(v);
  }

  onMount(async () => {
    if (!isTauri()) {
      metricsErr = "Run this app via the EctoLedger desktop window (./ectoledger-mac, ./ectoledger-linux, or .\\ectoledger-win.ps1), not in a browser.";
      return;
    }
    tauriReady = true;
    try {
      dashboardUrl = await invoke<string>("dashboard_url");
      observerToken = await invoke<string>("observer_token");
    } catch (e) {
      metricsErr = `Failed to initialise dashboard: ${e}`;
    }
    await loadMetrics();
    function scheduleMetricsPoll() {
      if (!_alive) return;
      const delay = _metricsErrorCount >= 3
        ? Math.min(10_000 * Math.pow(2, _metricsErrorCount - 2), 60_000)
        : 10_000;
      pollTimeout = setTimeout(async () => {
        if (!document.hidden) await loadMetrics();
        scheduleMetricsPoll();
      }, delay);
    }
    scheduleMetricsPoll();
    const onVisChange = () => {
      if (!document.hidden && !pollTimeout) scheduleMetricsPoll();
    };
    document.addEventListener("visibilitychange", onVisChange);
    // Store handler ref for cleanup
    _visibilityHandler = onVisChange;
  });

  let _visibilityHandler: (() => void) | null = null;

  onDestroy(() => {
    _alive = false;
    if (_visibilityHandler) document.removeEventListener("visibilitychange", _visibilityHandler);
    if (pollTimeout) clearTimeout(pollTimeout);
    if (sessionPoll) clearTimeout(sessionPoll);
    if (approvalPoll) clearInterval(approvalPoll);
    if (sseSource) { sseSource.close(); sseSource = null; }
  });

  let _loadingMetrics = false;
  let _metricsErrorCount = 0;
  async function loadMetrics() {
    if (!tauriReady || _loadingMetrics) return;
    _loadingMetrics = true;
    try {
      const data = await invoke<unknown>("get_metrics");
      if (!_alive) return;
      metrics = data && typeof data === "object" && !Array.isArray(data)
        ? (data as Record<string, unknown>)
        : null;
      metricsErr = ""; // clear previous error on success
      _metricsErrorCount = 0;
    } catch (e) {
      _metricsErrorCount++;
      const msg = String(e);
      // Suppress noisy rate-limit errors — they are transient and self-healing.
      const isRateLimit = msg.includes("429") || msg.includes("Too Many Requests") || msg.includes("rate limit");
      if (isRateLimit) {
        // Silently retry — don't alarm the user with background poll failures.
      } else {
        metricsErr = msg;
      }
    } finally {
      _loadingMetrics = false;
    }
  }

  let prompt = $state("");
  let running = $state(false);
  let result = $state("");
  let rawResult = $state<unknown>(null);
  let showRawOutput = $state(false);

  // Live event streaming state (populated after "Run Agent" creates a session).
  interface LiveEvent {
    typeLabel: string;
    content: string;
    isError: boolean;
    isComplete: boolean;
    /** Semantic colour hint: 'chat' | 'tripwire' | 'action' | null */
    colorHint: "chat" | "tripwire" | "action" | null;
  }
  let liveSessionId = $state<string | null>(null);
  let liveEvents = $state<LiveEvent[]>([]);
  let sessionDone = $state(false);
  let sessionPoll = $state<ReturnType<typeof setTimeout> | null>(null);
  let lastEventCount = $state(0);
  let noNewEventsCount = $state(0);
  let pendingApproval = $state<Record<string, unknown> | null>(null);
  let approvalReason = $state("");
  let approvalError = $state("");
  let decidingApproval = $state(false);
  let approvalPoll = $state<ReturnType<typeof setInterval> | null>(null);

  // ── Verifiable Credential (proof) state ──────────────────────────────
  let vcData = $state<Record<string, unknown> | null>(null);
  let vcLoading = $state(false);
  let vcError = $state("");
  let vcVerifyResult = $state<{ valid?: boolean; error?: string } | null>(null);
  let vcVerifying = $state(false);

  async function fetchVcForSession() {
    if (!liveSessionId || !tauriReady) return;
    vcLoading = true;
    vcError = "";
    vcData = null;
    vcVerifyResult = null;
    try {
      const data = await invoke<unknown>("get_session_vc", { sessionId: liveSessionId });
      vcData = data as Record<string, unknown>;
    } catch (e) {
      vcError = String(e);
    } finally {
      vcLoading = false;
    }
  }

  async function verifyVc() {
    if (!liveSessionId || !tauriReady) return;
    vcVerifying = true;
    vcVerifyResult = null;
    try {
      const data = await invoke<unknown>("verify_session_vc", { sessionId: liveSessionId });
      vcVerifyResult = data as { valid?: boolean; error?: string };
    } catch (e) {
      vcVerifyResult = { error: String(e) };
    } finally {
      vcVerifying = false;
    }
  }

  function downloadVcJson() {
    if (!vcData || !liveSessionId) return;
    const blob = new Blob([JSON.stringify(vcData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ectoledger-vc-${liveSessionId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  /**
   * Extract a human-readable string from an arbitrary JSON response.
   * Tries common agent schema fields first, then falls back to a
   * key-value summary, finally to pretty-printed JSON.
   */
  function parseResponse(raw: unknown): string {
    if (raw == null) return "";
    if (typeof raw === "string") return raw;
    if (Array.isArray(raw)) return JSON.stringify(raw, null, 2);
    if (typeof raw !== "object") return String(raw);

    const obj = raw as Record<string, unknown>;

    // Agent thought / action / observation fields
    for (const key of ["justification", "observation", "thought", "message", "content", "result", "answer"]) {
      if (typeof obj[key] === "string" && (obj[key] as string).length > 0) {
        return obj[key] as string;
      }
    }

    // Session creation response (goal + status present)
    if (typeof obj.goal === "string" && obj.status) {
      const id = typeof obj.id === "string" ? `\nSession ID: ${(obj.id as string).slice(0, 8)}…` : "";
      return `Session started.\nGoal: ${obj.goal}\nStatus: ${obj.status}${id}`;
    }

    // Generic: join top-level scalar values as key: value lines
    const lines = Object.entries(obj)
      .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
      .map(([k, v]) => `${k}: ${v}`);
    if (lines.length > 0) return lines.join("\n");

    return JSON.stringify(raw, null, 2);
  }

  function parseLiveEventItem(ev: unknown): LiveEvent | null {
    if (!ev || typeof ev !== "object") return null;
    const e = ev as Record<string, unknown>;
    const rawPayload = e.payload;
    if (!rawPayload) return null;
    let p: Record<string, unknown>;
    if (typeof rawPayload === "string") {
      try { p = JSON.parse(rawPayload); } catch { return null; }
    } else if (typeof rawPayload === "object" && !Array.isArray(rawPayload)) {
      p = rawPayload as Record<string, unknown>;
    } else return null;

    const type = (p.type as string) || "unknown";
    let typeLabel = type.charAt(0).toUpperCase() + type.slice(1).toLowerCase();
    let content = "";
    let isError = false;
    let isComplete = false;
    let colorHint: LiveEvent["colorHint"] = null;

    switch (type) {
      case "genesis":
        content = (p.message as string) || "Ledger initialized.";
        break;
      case "prompt_input":
        typeLabel = "Prompt Input";
        content = (p.content as string) || "";
        break;
      case "schema_error": {
        const attempt = p.attempt ?? "?";
        const maxAttempts = p.max_attempts ?? "?";
        const schemaMsg = (p.message as string) || "Unknown validation error";
        typeLabel = `Schema Error (${attempt}/${maxAttempts})`;
        content = schemaMsg;
        isError = true;
        break;
      }
      case "circuit_breaker": {
        const cbReason = (p.reason as string) || "Too many consecutive failures";
        const cbCount = p.consecutive_failures ?? "?";
        typeLabel = `Circuit Breaker (${cbCount} failures)`;
        content = cbReason;
        isError = true;
        break;
      }
      case "thought": {
        const c = (p.content as string) ?? "";
        if (c.startsWith("SCHEMA ERROR")) {
          typeLabel = "Schema Error";
          isError = true;
        } else if (c.startsWith("Tripwire rejected:") || c.startsWith("Policy rejected:")) {
          typeLabel = "Tripwire Rejected";
          isError = true;
          colorHint = "tripwire";
        } else if (c.startsWith("Security:")) {
          typeLabel = "Security Alert";
          isError = true;
          colorHint = "tripwire";
        }
        content = c;
        break;
      }
      case "action": {
        const name = (p.name as string) ?? "";
        if (name === "complete") {
          isComplete = true;
          typeLabel = "Complete";
          const findings = (p.params as Record<string, unknown>)?.findings;
          content = Array.isArray(findings)
            ? `${findings.length} finding(s): ${
                (findings as Record<string, unknown>[]).map((f) => f.title ?? "").join(", ")
              }`
            : "Agent finished.";
        } else {
          typeLabel = "Action";
          colorHint = "action";
          content = name + (p.params ? ": " + JSON.stringify(p.params) : "");
        }
        break;
      }
      case "observation": {
        const obs = p.content;
        content = typeof obs === "string" ? obs : JSON.stringify(obs ?? "");
        break;
      }
      case "chat_message": {
        const role = (p.role as string) ?? "unknown";
        const backend = p.backend as string | undefined;
        const model = p.model as string | undefined;
        if (role === "user") {
          typeLabel = "💬 You";
        } else {
          const tag = backend ? `${backend}${model ? " / " + model : ""}` : "LLM";
          typeLabel = `🤖 ${tag}`;
        }
        colorHint = "chat";
        content = (p.content as string) || "";
        break;
      }
      default:
        content = Object.entries(p)
          .filter(([k]) => k !== "type")
          .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`)
          .join("\n");
    }
    return { typeLabel, content, isError, isComplete, colorHint };
  }

  function stopPolling() {
    if (sessionPoll) { clearTimeout(sessionPoll); sessionPoll = null; }
    if (sseSource) { sseSource.close(); sseSource = null; }
    if (approvalPoll) { clearInterval(approvalPoll); approvalPoll = null; }
    running = false;
  }

  async function pollApproval() {
    if (!liveSessionId || !tauriReady || sessionDone) return;
    try {
      // Server returns { pending: PendingApproval | null }
      const wrapper = await invoke<{ pending: Record<string, unknown> | null }>(
        "get_pending_approval",
        { sessionId: liveSessionId },
      );
      pendingApproval =
        wrapper && typeof wrapper === "object" && wrapper.pending
          ? (wrapper.pending as Record<string, unknown>)
          : null;
    } catch { /* no active gate — ignore */ }
  }

  async function decideApproval(approved: boolean) {
    if (!pendingApproval || !liveSessionId || decidingApproval) return;
    const gateId = String(pendingApproval.gate_id ?? "");
    decidingApproval = true;
    approvalError = "";
    try {
      await invoke("post_approval_decision", {
        sessionId: liveSessionId,
        gateId,
        approved,
        reason: approvalReason || null,
      });
      pendingApproval = null;
      approvalReason = "";
    } catch (e) {
      approvalError = `Approval decision failed: ${e}`;
      console.error("Approval decision failed:", e);
    } finally {
      decidingApproval = false;
    }
  }

  // ── SSE EventSource — real-time feed from embedded server ─────────────
  let sseSource = $state<EventSource | null>(null);

  /** Open an SSE connection for the current session.  Falls back to polling
   *  if the EventSource constructor throws (e.g. restrictive CSP). */
  function startSSE(sessionId: string) {
    if (!dashboardUrl || !observerToken) {
      // No URL yet — fall back to polling.
      scheduleSessionPoll();
      return;
    }
    try {
      const url = `${dashboardUrl}/api/stream?session_id=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(observerToken)}`;
      const es = new EventSource(url);
      sseSource = es;

      es.onmessage = (msg) => {
        if (!_alive) { es.close(); return; }
        try {
          const raw = JSON.parse(msg.data);
          const ev = parseLiveEventItem(raw);
          if (ev) {
            liveEvents = [...liveEvents, ev].slice(-500);
            if (ev.isComplete) {
              sessionDone = true;
              es.close();
              sseSource = null;
              if (approvalPoll) { clearInterval(approvalPoll); approvalPoll = null; }
              running = false;
            }
          }
        } catch { /* ignore unparseable frames */ }
      };

      es.onerror = () => {
        // SSE failed — close and fall back to polling.
        es.close();
        sseSource = null;
        if (!sessionDone && _alive) {
          scheduleSessionPoll();
        } else if (approvalPoll) {
          clearInterval(approvalPoll);
          approvalPoll = null;
        }
      };
    } catch {
      // EventSource not available — fall back to polling.
      scheduleSessionPoll();
    }
  }

  /** Schedule the next poll with exponential backoff: 2 s base, doubles on
   *  consecutive empty responses, caps at 16 s. */
  function scheduleSessionPoll() {
    if (!_alive || sessionDone) return;
    const baseMs = 2000;
    const delay = Math.min(baseMs * Math.pow(2, noNewEventsCount), 16000);
    sessionPoll = setTimeout(pollSessionEvents, delay);
  }

  let _polling = false;
  async function pollSessionEvents() {
    if (_polling || !liveSessionId || !tauriReady || !_alive) return;
    _polling = true;
    try {
      const rawevs = await invoke<unknown>("get_events", { sessionId: liveSessionId });
      const arr = Array.isArray(rawevs) ? rawevs : [];
      liveEvents = arr.map(parseLiveEventItem).filter((e): e is LiveEvent => e !== null);

      if (arr.length === lastEventCount) {
        noNewEventsCount++;
      } else {
        noNewEventsCount = 0;
        lastEventCount = arr.length;
      }

      const hasComplete = liveEvents.some((e) => e.isComplete);
      // Stop after a complete action, or after ~16 s with no new events once
      // the agent has already produced at least one event.
      if (hasComplete || (noNewEventsCount >= 8 && lastEventCount > 0)) {
        stopPolling();
        sessionDone = true;
      } else {
        scheduleSessionPoll();
      }
    } catch {
      noNewEventsCount++;
      if (noNewEventsCount >= 8) {
        stopPolling();
      } else {
        scheduleSessionPoll();
      }
    } finally {
      _polling = false;
    }
  }

  /** Full agent cognitive loop — creates a session, streams events. */
  async function runAgent() {
    if (!prompt.trim() || !tauriReady) return;
    // Reset all live-event state.
    running = true;
    result = "";
    rawResult = null;
    liveSessionId = null;
    liveEvents = [];
    sessionDone = false;
    lastEventCount = 0;
    noNewEventsCount = 0;
    pendingApproval = null;
    approvalReason = "";
    vcData = null;
    vcError = "";
    vcVerifyResult = null;
    if (sessionPoll) { clearTimeout(sessionPoll); sessionPoll = null; }
    if (approvalPoll) { clearInterval(approvalPoll); approvalPoll = null; }

    const goalText = prompt;
    prompt = "";
    try {
      const res = await invoke<unknown>("run_prompt", { args: { goal: goalText } });
      if (!_alive) return;
      rawResult = res;
      if (res && typeof res === "object" && !Array.isArray(res)) {
        const sr = res as Record<string, unknown>;
        liveSessionId = typeof sr.id === "string" ? sr.id : null;
        result = liveSessionId
          ? `Session ${liveSessionId.slice(0, 8)}… started — watching for agent events…`
          : parseResponse(res);
      } else {
        result = typeof res === "string" ? res : JSON.stringify(res, null, 2);
      }
      if (liveSessionId) {
        // Prefer SSE for real-time event streaming; falls back to polling.
        startSSE(liveSessionId);
        // Poll for human-approval gates every 3 s.
        approvalPoll = setInterval(pollApproval, 3000);
      } else {
        running = false;
      }
    } catch (e) {
      if (!_alive) return;
      result = String(e);
      rawResult = null;
      running = false;
    }
  }
</script>

<div class="grid grid-cols-[minmax(280px,420px)_1fr] gap-6 h-full overflow-hidden">
  <!-- ═══ Left Column: Agent Control & Live Feed ═══ -->
  <section class="rounded-xl p-5 bg-surface shadow-sm border border-border-muted/40 min-w-0 flex flex-col gap-5 overflow-y-auto overflow-x-hidden">
    <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted m-0">Agent Goal</h2>
    <textarea
      class="w-full bg-surface-elevated/30 border border-border-muted/30 rounded-xl text-text-primary font-mono px-5 py-4 text-sm resize-y outline-none leading-relaxed focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
      bind:value={prompt}
      placeholder="Enter agent goal…"
      rows="4"
    ></textarea>
    <button
      class="bg-success hover:bg-green-600 border-none rounded-xl px-7 py-3.5 text-base font-semibold text-white cursor-pointer self-start transition-all duration-200 disabled:opacity-50 disabled:cursor-default active:scale-[0.98] shadow-sm shadow-success/20 hover:shadow-md"
      onclick={runAgent}
      disabled={running}
    >
      {running ? "Running…" : "▶ Run Agent"}
    </button>

    {#if pendingApproval}
      <!-- ── Approval gate ──────────────────────────────────────────── -->
      <div class="mt-2 rounded-2xl border border-warning/30 bg-warning-muted p-5 flex flex-col gap-4">
        <div class="flex items-center gap-2">
          <span class="text-warning text-base">⏸</span>
          <span class="text-xs font-bold text-warning uppercase tracking-wide">Approval Required</span>
        </div>
        {#if pendingApproval.action_name}
          <p class="text-sm text-text-primary m-0">
            <span class="font-semibold">Action:</span> {String(pendingApproval.action_name)}
          </p>
        {/if}
        {#if pendingApproval.action_params_summary}
          <p class="text-xs text-text-secondary m-0 font-mono break-all">{String(pendingApproval.action_params_summary)}</p>
        {/if}
        {#if pendingApproval.description}
          <p class="text-xs text-text-secondary m-0">{String(pendingApproval.description)}</p>
        {/if}
        <textarea
          class="w-full bg-surface-elevated/30 border border-border-muted/30 rounded-xl text-text-primary px-5 py-3 text-sm resize-none outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
          bind:value={approvalReason}
          placeholder="Reason (optional)…"
          rows="2"
        ></textarea>
        <div class="flex gap-3">
          <button
            class="flex-1 bg-success border-none rounded-xl px-5 py-2.5 text-sm font-semibold text-white cursor-pointer hover:bg-green-600 transition-all duration-200 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            onclick={() => decideApproval(true)}
            disabled={decidingApproval}
          >{decidingApproval ? '…' : '✓ Approve'}</button>
          <button
            class="flex-1 bg-danger border-none rounded-xl px-5 py-2.5 text-sm font-semibold text-white cursor-pointer hover:bg-red-600 transition-all duration-200 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            onclick={() => decideApproval(false)}
            disabled={decidingApproval}
          >{decidingApproval ? '…' : '✗ Deny'}</button>
        </div>
        {#if approvalError}
          <p class="text-xs text-danger mt-1">{approvalError}</p>
        {/if}
      </div>
    {/if}

    {#if liveEvents.length > 0}
      <!-- ── Live Event Feed ─────────────────────────────────────── -->
      <div class="flex justify-between items-center mt-1">
        <span class="text-xs font-semibold text-text-secondary uppercase tracking-wide">
          {#if running}Live Feed{:else if sessionDone}Complete{:else}Events{/if}
        </span>
        {#if running}
          <button class="bg-transparent border border-border-muted/30 rounded-xl text-accent text-xs px-4 py-1.5 cursor-pointer hover:bg-surface-elevated transition-all duration-200" onclick={stopPolling}>■ Stop</button>
        {/if}
      </div>
      <div class="flex-1 min-h-0 bg-surface-elevated/20 border border-border-muted/20 rounded-2xl p-5 font-mono text-xs text-text-primary whitespace-pre-wrap overflow-y-auto overflow-x-hidden break-words flex flex-col gap-2">
        {#each liveEvents as ev}
          <div class="flex flex-col gap-0.5 px-4 py-2.5 rounded-xl border-l-2
            {ev.colorHint === 'tripwire' ? 'bg-red-500/10 border-l-red-500'
            : ev.isError ? 'bg-danger-muted/30 border-l-danger'
            : ev.colorHint === 'chat' ? 'bg-yellow-400/10 border-l-yellow-400'
            : ev.colorHint === 'action' ? 'bg-blue-400/10 border-l-blue-400'
            : ev.isComplete ? 'bg-background border-l-success'
            : 'bg-background border-l-border-muted'}">
            <span class="text-[0.65rem] font-bold uppercase tracking-wide
              {ev.colorHint === 'tripwire' ? 'text-red-400'
              : ev.isError ? 'text-danger'
              : ev.colorHint === 'chat' ? 'text-yellow-400'
              : ev.colorHint === 'action' ? 'text-blue-400'
              : ev.isComplete ? 'text-success'
              : 'text-text-muted'}">{ev.typeLabel}</span>
            {#if ev.content}<span class="text-xs text-text-primary whitespace-pre-wrap break-words leading-snug">{ev.content}</span>{/if}
          </div>
        {/each}
      </div>

      <!-- Cryptographic Proof — shown when session is done -->
      {#if sessionDone && liveSessionId}
        <div class="mt-3 border border-border-muted/20 rounded-2xl p-5 bg-surface-elevated/15">
          <span class="text-sm font-semibold uppercase tracking-wider text-text-muted">Cryptographic Proof</span>
          {#if !vcData && !vcLoading && !vcError}
            <button
              class="mt-2 bg-accent/15 border border-accent/30 hover:bg-accent/25 text-accent rounded-xl px-5 py-2.5 text-xs font-semibold cursor-pointer transition-all duration-200 active:scale-[0.98]"
              onclick={fetchVcForSession}
            >
              🔐 Fetch Verifiable Credential
            </button>
          {/if}
          {#if vcLoading}
            <p class="text-text-muted text-xs mt-2">Loading credential…</p>
          {/if}
          {#if vcError}
            <div class="mt-2 p-3 bg-danger-muted/30 border border-danger/30 rounded-lg text-danger text-xs">{vcError}</div>
          {/if}
          {#if vcData}
            <div class="flex flex-col gap-3 mt-2">
              <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                {#if vcData.vc_payload && typeof vcData.vc_payload === 'object'}
                  {@const payload = vcData.vc_payload as Record<string, unknown>}
                  <span class="text-text-muted">Issuer</span>
                  <span class="text-text-primary font-mono break-all">{payload.issuer ?? payload.iss ?? '—'}</span>
                  <span class="text-text-muted">Issued</span>
                  <span class="text-text-primary font-mono">{payload.issuanceDate ?? payload.iat ?? '—'}</span>
                  <span class="text-text-muted">Session</span>
                  <span class="text-text-primary font-mono">{liveSessionId}</span>
                {/if}
              </div>
              {#if vcData.vc_jwt}
                <details>
                  <summary class="text-xs text-text-muted cursor-pointer hover:text-text-secondary">View VC JWT</summary>
                  <pre class="mt-1 text-xs text-text-primary bg-background rounded-lg p-3 overflow-x-auto max-h-24 overflow-y-auto font-mono break-all whitespace-pre-wrap">{vcData.vc_jwt}</pre>
                </details>
              {/if}
              <details>
                <summary class="text-xs text-text-muted cursor-pointer hover:text-text-secondary">View raw VC JSON</summary>
                <pre class="mt-1 text-xs text-text-primary bg-background rounded-lg p-3 overflow-x-auto max-h-48 overflow-y-auto font-mono">{JSON.stringify(vcData.vc_payload ?? vcData, null, 2)}</pre>
              </details>
              <div class="flex items-center gap-2 flex-wrap">
                <button
                  class="bg-success/15 border border-success/30 hover:bg-success/25 text-success rounded-xl px-4 py-2 text-xs font-semibold cursor-pointer transition-all duration-200 active:scale-[0.98]"
                  onclick={downloadVcJson}
                >
                  ⬇ Download VC
                </button>
                <button
                  class="bg-accent/15 border border-accent/30 hover:bg-accent/25 text-accent rounded-xl px-4 py-2 text-xs font-semibold cursor-pointer transition-all duration-200 active:scale-[0.98] disabled:opacity-50 disabled:cursor-default"
                  onclick={verifyVc}
                  disabled={vcVerifying}
                >
                  {vcVerifying ? 'Verifying…' : '✓ Verify Signature'}
                </button>
                {#if vcVerifyResult}
                  {#if vcVerifyResult.error}
                    <span class="text-xs px-2 py-0.5 rounded-full bg-danger-muted border border-danger/30 text-danger">✗ {vcVerifyResult.error}</span>
                  {:else if vcVerifyResult.valid === false}
                    <span class="text-xs px-2 py-0.5 rounded-full bg-danger-muted border border-danger/30 text-danger">✗ Invalid</span>
                  {:else}
                    <span class="text-xs px-2 py-0.5 rounded-full bg-success-muted border border-success/30 text-success">✓ Signature valid</span>
                  {/if}
                {/if}
              </div>
            </div>
          {/if}
        </div>
      {/if}
    {:else if result || rawResult !== null}
      <!-- Session / plain result -->
      <div class="flex justify-between items-center mt-2">
        <span class="text-xs font-semibold text-text-muted uppercase tracking-wide">Response</span>
        <label class="flex items-center gap-2 text-xs text-text-muted cursor-pointer select-none">
          <input type="checkbox" bind:checked={showRawOutput} />
          Raw
        </label>
      </div>
      {#if showRawOutput}
        <pre class="bg-surface-elevated/20 border border-border-muted/20 rounded-2xl p-5 font-mono text-xs text-text-primary whitespace-pre-wrap overflow-y-auto overflow-x-auto max-h-[200px] break-words">{JSON.stringify(rawResult, null, 2)}</pre>
      {:else}
        <div class="bg-surface-elevated/20 border border-border-muted/20 rounded-2xl p-5 text-sm text-text-primary whitespace-pre-wrap overflow-y-auto overflow-x-auto max-h-[200px] break-words leading-relaxed">{parseResponse(rawResult ?? result)}</div>
      {/if}
    {/if}
  </section>

  <!-- ═══ Right Column: Metrics & Dashboard ═══ -->
  <section class="rounded-xl p-5 bg-surface shadow-sm border border-border-muted/40 min-w-0 flex flex-col gap-5 overflow-hidden">
    <!-- Header: no extra px-2.5 — section's p-5 provides uniform inset -->
    <div class="flex justify-between items-center">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted m-0">Prometheus Metrics</h2>
      <!-- ↻ renders unreliably in the Tauri WebView; use plain text instead -->
      <button class="bg-transparent border border-border-muted/30 rounded-xl text-accent px-4 py-1.5 text-xs cursor-pointer hover:bg-surface-elevated transition-all duration-200 shrink-0" onclick={loadMetrics}>Refresh</button>
    </div>

    {#if metricsErr && !metricsErr.includes("rate limit") && !metricsErr.includes("Rate limit")}
      <!-- No extra px-2.5: error text aligns with the section's own padding -->
      <p class="text-danger text-xs font-mono">{metricsErr}</p>
    {:else if metrics}
      <ul class="list-none flex flex-col gap-2">
        {#each Object.entries(metrics) as [k, v]}
          {#if v !== null && typeof v === "object" && !Array.isArray(v)}
            <!-- Nested object: one row per sub-key instead of a single crammed string -->
            {#each Object.entries(v as Record<string, unknown>) as [subK, subV]}
              <!-- No mx-2.5: section's p-5 is the sole horizontal boundary -->
              <li class="flex justify-between gap-4 bg-surface-elevated/20 rounded-xl px-5 py-3 font-mono min-w-0">
                <span class="text-text-muted shrink-0 text-xs">{formatMetricKey(k)} · {formatMetricKey(subK)}</span>
                <span class="text-accent font-semibold text-right text-xs tabular-nums" title={String(subV)}>{String(subV)}</span>
              </li>
            {/each}
          {:else}
            <li class="flex justify-between gap-4 bg-surface-elevated/20 rounded-xl px-5 py-3 font-mono min-w-0">
              <span class="text-text-muted shrink-0 text-xs">{formatMetricKey(k)}</span>
              <span class="text-accent font-semibold text-right text-xs tabular-nums" title={formatMetricValue(v)}>{formatMetricValue(v)}</span>
            </li>
          {/if}
        {/each}
      </ul>
    {:else}
      <p class="text-text-secondary text-xs">Loading…</p>
    {/if}

    <!-- Native Observer panel — replaces the old iframe embed -->
    <div class="flex-1 min-h-0 mt-3">
      <ObserverPanel {serverUrl} />
    </div>
  </section>
</div>
