<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import { writeFile } from "@tauri-apps/plugin-fs";
  import { onMount, onDestroy } from "svelte";

  interface Session {
    id: string;
    goal: string;
    goal_hash?: string;
    status: string;
    created_at: string;
    finished_at: string | null;
  }

  interface RawEvent {
    id?: number;
    sequence?: number;
    payload?: string | { type?: string; [k: string]: unknown };
    created_at?: string;
  }

  interface GroupedEvent {
    key: string;
    type: string;
    content: string;
    count: number;
    occurrences: { seq: number; timestamp: string; type: string }[];
  }

  let sessions = $state<Session[]>([]);
  let selected = $state<string | null>(null);
  let events = $state<RawEvent[]>([]);
  let loading = $state(false);
  let sessionError = $state("");
  let exporting = $state(false);
  let exportingReport = $state(false);
  let exportMsg = $state("");

  // pagination / filtering
  const PAGE_SIZE = 20;
  let statusFilter = $state<string | null>(null);
  let offset = $state(0);
  let more = $state(false);

  // verifiable credential cache/loading
  let vcData = $state<{ vc_jwt: string; vc_payload: any } | null>(null);
  let vcLoading = $state(false);
  let vcError = $state("");
  // VC on-demand verification
  let vcVerifyResult = $state<{ valid?: boolean; claims?: any; error?: string } | null>(null);
  let vcVerifying = $state(false);
  let eventsLoading = $state(false);

  let _alive = true;
  onDestroy(() => { _alive = false; });

  onMount(load);


  async function load() {
    if (!isTauri()) return;
    loading = true;
    sessionError = "";
    try {
      const data = await invoke<unknown>("get_sessions", {
        status: statusFilter || null,
        limit: PAGE_SIZE,
        offset,
      });
      sessions = Array.isArray(data) ? (data as Session[]) : [];
      more = sessions.length === PAGE_SIZE;
    } catch (e) {
      sessionError = String(e);
      sessions = [];
    } finally {
      loading = false;
    }
  }

  async function selectSession(id: string) {
    if (!isTauri()) return;
    selected = id;
    events = [];
    eventsLoading = true;
    vcData = null;
    vcError = "";
    vcVerifyResult = null;
    expandedKeys = new Set();
    exportMsg = "";
    try {
      const data = await invoke<unknown>("get_events", { sessionId: id });
      if (!_alive || selected !== id) return; // stale response guard
      events = Array.isArray(data) ? data : [];
    } catch (e) {
      if (!_alive || selected !== id) return;
      events = [];
      sessionError = `Failed to load events: ${e}`;
    } finally {
      eventsLoading = false;
    }
    // if session is completed, fetch VC as well
    const sess = sessions.find((s) => s.id === id);
    if (sess && sess.status === "completed") {
      loadVC(id);
    }
  }

  async function loadVC(id: string) {
    if (!isTauri()) return;
    vcLoading = true;
    vcError = "";
    vcData = null;
    vcVerifyResult = null;
    try {
      const data = await invoke<unknown>("get_session_vc", { sessionId: id });
      if (!_alive || selected !== id) return; // stale response guard
      vcData = data as any;
    } catch (e) {
      if (!_alive || selected !== id) return;
      vcError = String(e);
      vcData = null;
    } finally {
      vcLoading = false;
    }
  }

  async function verifyVC(id: string) {
    if (!isTauri()) return;
    vcVerifying = true;
    vcVerifyResult = null;
    try {
      const data = await invoke<unknown>("verify_session_vc", { sessionId: id });
      if (!_alive || selected !== id) return;
      vcVerifyResult = data as any;
    } catch (e) {
      if (!_alive || selected !== id) return;
      vcVerifyResult = { error: String(e) };
    } finally {
      vcVerifying = false;
    }
  }


  function formatEventType(t: string): string {
    return t
      .split("_")
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
      .join(" ");
  }

  function formatEventDisplay(ev: RawEvent): { type: string; content: string } {
    const raw = ev.payload;
    if (raw == null) return { type: "Event", content: JSON.stringify(ev, null, 2) };

    // Payload may arrive as a pre-serialised JSON string — parse it first.
    let p: Record<string, unknown>;
    if (typeof raw === "string") {
      try { p = JSON.parse(raw); }
      catch { return { type: "Event", content: raw }; }
    } else if (typeof raw === "object" && !Array.isArray(raw)) {
      p = raw as Record<string, unknown>;
    } else {
      return { type: "Event", content: JSON.stringify(raw, null, 2) };
    }

    const t = (p.type as string) ?? "event";
    let content: string;
    switch (t) {
      case "genesis":
        content = (p.message as string) ?? JSON.stringify(p, null, 2);
        break;
      case "thought":
      case "observation":
        content = (p.content as string) ?? JSON.stringify(p, null, 2);
        break;
      case "action": {
        const paramStr = p.params != null
          ? JSON.stringify(p.params, null, 2)
          : "";
        content = paramStr ? `${p.name as string}\n${paramStr}` : String(p.name ?? JSON.stringify(p, null, 2));
        break;
      }
      case "approval_required":
        content = `Gate: ${p.gate_id}\nAction: ${p.action_name}${p.action_params_summary ? `\n${p.action_params_summary}` : ""}`;
        break;
      case "approval_decision":
        content = `Gate: ${p.gate_id}\n${p.approved ? "✅ Approved" : "❌ Denied"}${p.reason ? `\nReason: ${p.reason}` : ""}`;
        break;
      case "cross_ledger_seal":
        content = `Seal hash: ${p.seal_hash}`;
        break;
      case "anchor":
        content = `Ledger tip: ${p.ledger_tip_hash}${
          p.bitcoin_block_height != null ? `\nBitcoin block: ${p.bitcoin_block_height}` : ""
        }`;
        break;
      case "key_rotation":
        content = `Rotation #${p.rotation_index}\nNew key: ${p.new_public_key}`;
        break;
      default:
        content = JSON.stringify(p, null, 2);
    }
    return { type: formatEventType(t), content };
  }

  function groupEvents(evs: RawEvent[]): GroupedEvent[] {
    const byKey = new Map<string, GroupedEvent>();
    for (const ev of evs) {
      const { type, content } = formatEventDisplay(ev);
      const key = `${type}\n${content}`;
      const occ = {
        seq: (ev.sequence as number) ?? 0,
        timestamp: (ev.created_at as string) ?? "",
        type: (typeof ev.payload === "object" && ev.payload != null
          ? (ev.payload as { type?: string }).type
          : undefined) ?? "event",
      };
      if (byKey.has(key)) {
        const g = byKey.get(key)!;
        g.count += 1;
        g.occurrences.push(occ);
      } else {
        byKey.set(key, {
          key,
          type,
          content,
          count: 1,
          occurrences: [occ],
        });
      }
    }
    return Array.from(byKey.values());
  }

  let expandedKeys = $state<Set<string>>(new Set());

  function toggleExpanded(key: string) {
    expandedKeys = new Set(expandedKeys);
    if (expandedKeys.has(key)) {
      expandedKeys.delete(key);
    } else {
      expandedKeys.add(key);
    }
  }

  async function exportCert() {
    if (!selected || !isTauri()) return;
    exporting = true;
    exportMsg = "";
    try {
      const bytes = await invoke<number[]>("export_certificate", { sessionId: selected });
      const path = await save({
        defaultPath: `audit-${selected.slice(0, 8)}.elc`,
        filters: [{ name: "EctoLedger Certificate", extensions: ["elc"] }],
      });
      if (path) {
        await writeFile(path, new Uint8Array(bytes));
        exportMsg = `Certificate saved to ${path}`;
      } else {
        exportMsg = "Save cancelled.";
      }
    } catch (e) {
      exportMsg = String(e);
    } finally {
      exporting = false;
    }
  }

  async function downloadReport() {
    if (!selected || !isTauri()) return;
    exportingReport = true;
    exportMsg = "";
    try {
      const bytes = await invoke<number[]>("download_report", { sessionId: selected });
      const path = await save({
        defaultPath: `report-${selected.slice(0, 8)}.json`,
        filters: [{ name: "JSON Report", extensions: ["json"] }],
      });
      if (path) {
        await writeFile(path, new Uint8Array(bytes));
        exportMsg = `Report saved to ${path}`;
      } else {
        exportMsg = "Save cancelled.";
      }
    } catch (e) {
      exportMsg = String(e);
    } finally {
      exportingReport = false;
    }
  }

  const groupedEvents = $derived(groupEvents(events));

  function prevPage() {
    offset = Math.max(0, offset - PAGE_SIZE);
    selected = null;
    events = [];
    load();
  }

  function nextPage() {
    if (more) {
      offset += PAGE_SIZE;
      selected = null;
      events = [];
      load();
    }
  }


</script>

<div class="flex gap-6 h-full overflow-hidden">
  <aside class="bg-surface rounded-2xl w-64 min-w-64 p-6 overflow-y-auto shadow-sm">
    <div class="flex justify-between items-center mb-5">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted">Audit History</h2>
      <button class="bg-transparent border border-border-muted/30 rounded-xl text-accent px-4 py-2 text-sm cursor-pointer hover:bg-surface-elevated transition-all duration-200" onclick={load}>↻</button>
    </div>
    <div class="flex items-center gap-3 px-4 py-3">
      <label for="status-filter" class="text-sm text-text-muted">Status</label>
      <select id="status-filter" class="bg-background border border-border-muted/40 rounded-xl px-4 py-2 text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={statusFilter} onchange={() => { offset = 0; load(); }}>
        <option value="">All</option>
        <option value="running">Running</option>
        <option value="completed">Completed</option>
        <option value="failed">Failed</option>
        <option value="aborted">Aborted</option>
      </select>
      <div class="ml-auto flex gap-2">
        <button class="bg-transparent border border-border-muted/30 rounded-xl text-accent px-4 py-2 text-xs cursor-pointer hover:bg-surface-elevated transition-all duration-200" onclick={prevPage} disabled={offset === 0}>← Prev</button>
        <button class="bg-transparent border border-border-muted/30 rounded-xl text-accent px-4 py-2 text-xs cursor-pointer hover:bg-surface-elevated transition-all duration-200" onclick={nextPage} disabled={!more}>Next →</button>
      </div>
    </div>

    {#if sessionError}
      <p class="text-danger text-sm">{sessionError}</p>
    {/if}
    {#if loading}
      <p class="text-text-muted text-sm">Loading…</p>
    {:else if sessions.length === 0 && !sessionError}
      <p class="text-text-muted text-sm">No sessions found.</p>
    {:else}
      <ul class="list-none">
        {#each sessions as s}
          <li>
            <div
              class="w-full flex justify-between items-center px-4 py-3.5 bg-transparent border-none rounded-xl text-text-primary/70 text-sm cursor-pointer text-left transition-all duration-200 hover:bg-surface-elevated {selected === s.id ? 'bg-surface-elevated text-accent' : ''}"
              role="button"
              tabindex="0"
              onclick={() => selectSession(s.id)}
              onkeydown={(e) => (e.key === "Enter" || e.key === " ") && selectSession(s.id)}
            >
              <span class="font-mono">{s.id.slice(0, 8)}…</span>
              <span class="text-xs px-3 py-1.5 rounded-full font-semibold {s.status === 'completed' ? 'bg-success-muted text-success' : 'bg-warning-muted text-warning'}">
                {s.status}
              </span>
              {#if s.status === 'completed'}
                <button type="button" class="ml-2 bg-transparent border border-accent/30 text-accent px-3 py-1.5 text-xs rounded-xl cursor-pointer hover:bg-surface-elevated transition-all duration-200" onclick={(e) => { e.stopPropagation(); loadVC(s.id); }} title="Load/verifiable credential">
                  VC
                </button>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </aside>

  <main class="bg-surface rounded-2xl flex-1 min-w-0 p-7 overflow-y-auto flex flex-col gap-6 shadow-sm">
    {#if !selected}
      <p class="text-text-muted text-sm text-center mt-16">Select a session to view events.</p>
    {:else}
      {#if vcLoading}
        <p class="text-text-muted text-sm">Loading credential…</p>
      {:else if vcError}
        <div class="bg-danger-muted border border-danger/20 text-danger px-5 py-4 rounded-xl text-sm">{vcError}</div>
      {:else if vcData}
        <div class="bg-surface-elevated/20 border border-border-muted/20 rounded-2xl p-6 mb-5">
          <h3>Verifiable Credential</h3>
          <textarea readonly rows={5} class="w-full bg-background border border-border-muted/40 rounded-xl text-text-primary font-mono resize-none mb-4">{vcData.vc_jwt}</textarea>
          <pre class="bg-background border border-border-muted/30 rounded-xl p-4 text-text-primary text-sm overflow-x-auto">{JSON.stringify(vcData.vc_payload, null, 2)}</pre>
          <div class="flex items-center gap-4 mt-4">
            <button
              class="bg-transparent border border-border-muted/30 rounded-xl text-accent px-4 py-2 text-xs cursor-pointer hover:bg-surface-elevated transition-all duration-200"
              onclick={() => selected && verifyVC(selected)}
              disabled={vcVerifying}
            >
              {vcVerifying ? "Verifying…" : "✓ Verify VC"}
            </button>
            {#if vcVerifyResult}
              {#if vcVerifyResult.error}
                <span class="text-sm px-3 py-1.5 rounded-full bg-danger-muted border border-danger/20 text-danger">✗ {vcVerifyResult.error}</span>
              {:else if vcVerifyResult.valid === false}
                <span class="text-sm px-3 py-1.5 rounded-full bg-danger-muted border border-danger/20 text-danger">✗ Invalid signature</span>
              {:else}
                <span class="text-sm px-3 py-1.5 rounded-full bg-success-muted border border-success/20 text-success">✓ Signature valid</span>
              {/if}
            {/if}
          </div>
        </div>
      {/if}

      <div class="flex justify-between items-start">
        <div>
          <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted">Events</h2>
          <p class="text-xs text-text-muted mt-2 font-mono">{sessions.find(s => s.id === selected)?.goal ?? "—"}</p>
        </div>
        <div class="flex gap-3">
          <button class="bg-accent text-white border-none rounded-xl px-6 py-3 text-sm font-semibold cursor-pointer disabled:opacity-50 disabled:cursor-default transition-all duration-200 active:scale-[0.98] shadow-sm shadow-accent/20 hover:shadow-md hover:bg-accent-hover" onclick={exportCert} disabled={exporting}>
            {exporting ? "Exporting…" : "⬇ Certificate"}
          </button>
          <button class="bg-surface-elevated text-accent border border-border-muted/40 rounded-xl px-6 py-3 text-sm font-semibold cursor-pointer disabled:opacity-50 disabled:cursor-default transition-all duration-200 active:scale-[0.98] shadow-xs hover:bg-surface" onclick={downloadReport} disabled={exportingReport}>
            {exportingReport ? "Downloading…" : "⬇ Report"}
          </button>
        </div>
      </div>

      {#if exportMsg}
        <div class="bg-background border border-border-muted/20 rounded-xl p-5 text-sm text-text-primary whitespace-pre-wrap max-h-[120px] overflow-y-auto {exportMsg.startsWith('fs.') || exportMsg.includes('not allowed') ? 'border-danger text-danger' : ''}">
          {exportMsg}
        </div>
      {/if}

      {#if eventsLoading}
        <p class="text-text-muted text-sm">Loading events…</p>
      {:else if events.length === 0}
        <p class="text-text-muted text-sm">No events for this session.</p>
      {:else}
        <ul class="flex flex-col gap-3.5">
          {#each groupedEvents as g}
            <li class="p-5 flex flex-col gap-3 bg-surface-elevated/20 border border-border-muted/15 rounded-2xl">
              {#if g.count > 1}
                <button
                  class="flex items-center gap-2 bg-transparent border-none text-inherit cursor-pointer text-left p-0"
                  type="button"
                  onclick={() => toggleExpanded(g.key)}
                >
                  <span class="font-semibold text-accent text-sm">{g.type}</span>
                  <span class="bg-surface-elevated px-2.5 py-1 rounded-xl text-xs text-text-muted">×{g.count}</span>
                  <span class="ml-auto text-xs text-text-muted">{expandedKeys.has(g.key) ? "▼" : "▶"}</span>
                </button>
              {:else}
                <div class="flex items-center gap-2 bg-transparent border-none text-inherit cursor-default text-left p-0">
                  <span class="font-semibold text-accent text-sm">{g.type}</span>
                  {#if g.occurrences[0]}
                    <span class="ml-auto text-xs text-text-muted font-mono whitespace-nowrap">#{g.occurrences[0].seq} &middot; {g.occurrences[0].timestamp}</span>
                  {/if}
                </div>
              {/if}
              <div class="text-sm text-text-primary whitespace-pre-wrap break-words">{g.content}</div>
              {#if expandedKeys.has(g.key) && g.count > 1}
                <div class="mt-2 text-xs">
                  <table class="w-full border-collapse">
                    <thead>
                      <tr>
                        <th class="px-4 py-2.5 text-left border-b border-border-muted/15 text-text-muted font-semibold">Seq</th>
                        <th class="px-4 py-2.5 text-left border-b border-border-muted/15 text-text-muted font-semibold">Time</th>
                        <th class="px-4 py-2.5 text-left border-b border-border-muted/15 text-text-muted font-semibold">Type</th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each g.occurrences as occ}
                        <tr>
                          <td class="px-4 py-2.5 text-left border-b border-border-muted/10">{occ.seq}</td>
                          <td class="px-4 py-2.5 text-left border-b border-border-muted/10">{occ.timestamp}</td>
                          <td class="px-4 py-2.5 text-left border-b border-border-muted/10">{occ.type}</td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  </main>
</div>
