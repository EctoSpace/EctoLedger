<!--
  TestingView — Testing & Verification tab.

  Unified testing menu with collapsible Happy Path and Sad Path sections.
  In demo mode, sessions use the mock LLM backend so no external LLM
  dependency is required for tests to run.
-->
<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { Button, Card, Badge, Input } from "./ui";
  import adversarialTests from "./adversarial-tests.json";
  import happyPathTests from "./happy-path-tests.json";

  let _alive = true;
  onDestroy(() => { _alive = false; });

  interface Props {
    serverUrl: string;
  }

  let { serverUrl }: Props = $props();

  // ── Demo mode detection ──────────────────────────────────────────────────
  let demoMode = $state(false);

  async function detectDemoMode() {
    try {
      const dm = await invoke<boolean>("is_demo_mode");
      if (dm) demoMode = true;
    } catch { /* ignore — may fail in browser preview */ }
    // Fallback: ask the backend's /api/status endpoint
    if (!demoMode && serverUrl) {
      try {
        const res = await fetch(`${serverUrl}/api/status`, { signal: AbortSignal.timeout(5000) });
        if (res.ok) {
          const body = await res.json();
          if (body?.demo_mode) demoMode = true;
        }
      } catch { /* ignore */ }
    }
  }

  // ── Section collapse state ───────────────────────────────────────────────
  let happyExpanded = $state(true);
  let sadExpanded = $state(true);

  // ── Whitelist panel ──────────────────────────────────────────────────────
  let whitelistPatterns = $state<string[]>([]);
  let newPattern = $state("");
  function addPattern() {
    const p = newPattern.trim();
    if (p && !whitelistPatterns.includes(p)) {
      whitelistPatterns = [...whitelistPatterns, p];
      newPattern = "";
    }
  }
  function removePattern(p: string) {
    whitelistPatterns = whitelistPatterns.filter((x) => x !== p);
  }

  // ── Happy path tests ────────────────────────────────────────────────────
  type TestStatus = "idle" | "running" | "pass" | "fail";
  let happyStatuses = $state<Record<string, TestStatus>>({});
  let happyResults  = $state<Record<string, string>>({});
  let happySessionIds = $state<Record<string, string>>({});

  async function runHappyTest(testId: string, prompt: string) {
    happyStatuses = { ...happyStatuses, [testId]: "running" };
    happyResults  = { ...happyResults,  [testId]: "" };
    try {
      const session = await invoke<{ id: string; status: string }>("run_prompt", {
        args: { goal: prompt },
      });

      happySessionIds = { ...happySessionIds, [testId]: session.id };

      const TERMINAL = new Set(["completed", "aborted", "failed"]);
      const POLL_INTERVAL_MS = 1500;
      const TIMEOUT_MS = 30_000;
      const started = Date.now();
      let finalStatus = session.status;

      while (!TERMINAL.has(finalStatus) && Date.now() - started < TIMEOUT_MS && _alive) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        if (!_alive) break;
        try {
          const updated = await invoke<{ id: string; status: string }>("get_session", {
            sessionId: session.id,
          });
          finalStatus = updated.status;
        } catch { break; }
      }

      const passed = finalStatus === "completed";
      happyStatuses = { ...happyStatuses, [testId]: passed ? "pass" : "fail" };
      happyResults  = {
        ...happyResults,
        [testId]: passed
          ? `Session completed ✓ (${session.id.slice(0, 12)}…)`
          : `Session did not complete ✗ (status: ${finalStatus})`,
      };

      // Refresh sessions list after test completes
      loadSessions();
    } catch (e) {
      happyStatuses = { ...happyStatuses, [testId]: "fail" };
      happyResults  = { ...happyResults,  [testId]: String(e) };
    }
  }

  async function runAllHappyTests() {
    for (const t of happyPathTests) {
      await runHappyTest(t.id, t.prompt);
    }
  }

  // ── Adversarial tests (sad path) ─────────────────────────────────────────
  let testStatuses = $state<Record<string, TestStatus>>({});
  let testResults  = $state<Record<string, string>>({});
  let sadSessionIds = $state<Record<string, string>>({});

  async function runAdversarialTest(testId: string, prompt: string) {
    testStatuses = { ...testStatuses, [testId]: "running" };
    testResults  = { ...testResults,  [testId]: "" };
    try {
      const session = await invoke<{ id: string; status: string }>("run_prompt", {
        args: { goal: prompt },
      });

      sadSessionIds = { ...sadSessionIds, [testId]: session.id };

      const TERMINAL = new Set(["completed", "aborted", "failed"]);
      const POLL_INTERVAL_MS = 1500;
      const TIMEOUT_MS = 30_000;
      const started = Date.now();
      let finalStatus = session.status;

      while (!TERMINAL.has(finalStatus) && Date.now() - started < TIMEOUT_MS && _alive) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        if (!_alive) break;
        try {
          const updated = await invoke<{ id: string; status: string }>("get_session", {
            sessionId: session.id,
          });
          finalStatus = updated.status;
        } catch { break; }
      }

      const blocked = finalStatus === "aborted" || finalStatus === "failed";
      testStatuses = { ...testStatuses, [testId]: blocked ? "pass" : "fail" };
      testResults  = {
        ...testResults,
        [testId]: blocked
          ? `Tripwire triggered ✓ (session ${finalStatus})`
          : `Prompt was NOT blocked ✗ (status: ${finalStatus})`,
      };

      // Refresh sessions list after test completes
      loadSessions();
    } catch (e) {
      testStatuses = { ...testStatuses, [testId]: "fail" };
      testResults  = { ...testResults,  [testId]: String(e) };
    }
  }

  async function runAllAdversarialTests() {
    for (const t of adversarialTests) {
      await runAdversarialTest(t.id, t.prompt);
    }
  }

  // ── VC Verification ──────────────────────────────────────────────────────
  let sessionId = $state("");
  let loading = $state(false);
  let vcData = $state<Record<string, unknown> | null>(null);
  let verifyResult = $state<{ valid: boolean; message: string } | null>(null);
  let error = $state("");

  // Session list for quick-pick
  let sessions = $state<Array<{ id: string; goal: string; status: string }>>([]);
  let loadingSessions = $state(true);

  async function loadSessions() {
    loadingSessions = true;
    try {
      const data = await invoke<Array<{ id: string; goal: string; status: string }>>("get_sessions");
      sessions = data ?? [];
    } catch {
      sessions = [];
    }
    loadingSessions = false;
  }

  onMount(() => {
    loadSessions();
    detectDemoMode();
  });

  /** The currently selected session object (if any). */
  let selectedSession = $derived(sessions.find((s) => s.id === sessionId));
  /** Whether the selected session can have a VC (only completed sessions). */
  let canHaveVC = $derived(selectedSession?.status === "completed");

  async function fetchVC() {
    if (!sessionId) return;
    loading = true;
    error = "";
    vcData = null;
    verifyResult = null;
    try {
      const vc = await invoke<Record<string, unknown>>("get_session_vc", { sessionId });
      vcData = vc;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    loading = false;
  }

  async function verifyVC() {
    if (!sessionId) return;
    loading = true;
    error = "";
    try {
      const result = await invoke<{ valid: boolean; message: string }>("verify_session_vc", { sessionId });
      verifyResult = result;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    loading = false;
  }

  function selectSession(id: string) {
    sessionId = id;
    vcData = null;
    verifyResult = null;
    error = "";
  }
</script>

<div class="space-y-8 animate-fade-in">
  <!-- Header -->
  <div>
    <h1 class="text-xl font-bold text-text-primary">Testing & Verification</h1>
    <p class="text-sm text-text-muted mt-1">Verify session integrity, run happy-path and adversarial security tests.</p>
  </div>

  <!-- Demo mode banner -->
  {#if demoMode}
    <div class="flex items-center gap-3 p-4 rounded-xl bg-amber-400/5 border border-amber-400/20">
      <div class="shrink-0 w-8 h-8 rounded-lg bg-amber-400/10 flex items-center justify-center">
        <svg class="w-4 h-4 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
      </div>
      <div>
        <p class="text-sm font-medium text-amber-400">Demo Mode</p>
        <p class="text-xs text-text-muted mt-0.5">Sessions use the mock LLM backend — no external LLM service required. The agent pipeline runs for real and produces genuine Verifiable Credentials.</p>
      </div>
    </div>
  {/if}

  <!-- ═══════════════════════════════════════════════════════════════════════
       WHITELIST PANEL (full width)
       ═══════════════════════════════════════════════════════════════════════ -->
  <Card title="Prompt Whitelist" subtitle="Patterns always allowed through regardless of policy">
    {#snippet children()}
      <div class="space-y-3">
        {#if whitelistPatterns.length === 0}
          <p class="text-sm text-text-muted">No whitelist patterns. Add a pattern to permit matching prompts.</p>
        {:else}
          <div class="flex flex-wrap gap-2">
            {#each whitelistPatterns as p}
              <span class="flex items-center gap-1 bg-surface-elevated border border-border rounded-full px-3 py-1 text-xs font-mono text-text-primary">
                {p}
                <button class="ml-1 text-text-muted hover:text-danger transition-colors" onclick={() => removePattern(p)} aria-label="Remove pattern">&times;</button>
              </span>
            {/each}
          </div>
        {/if}
        <div class="flex flex-wrap gap-2">
          <Input bind:value={newPattern} placeholder="e.g. *.internal.*" class="flex-1 min-w-[180px]"
            onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') addPattern(); }} />
          <Button variant="secondary" onclick={addPattern} disabled={!newPattern.trim()}>
            {#snippet children()}Add{/snippet}
          </Button>
        </div>
      </div>
    {/snippet}
  </Card>

  <!-- ═══════════════════════════════════════════════════════════════════════
       SESSION & VERIFICATION (full width, always visible)
       ═══════════════════════════════════════════════════════════════════════ -->
  <div class="space-y-4">
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <!-- Session picker -->
      <Card title="Sessions" subtitle="Select a session to verify">
        {#snippet children()}
          <div class="flex justify-end mb-2">
            <Button variant="secondary" onclick={loadSessions} loading={loadingSessions}>
              {#snippet children()}↻ Refresh{/snippet}
            </Button>
          </div>
          {#if loadingSessions}
            <div class="flex items-center gap-2.5 py-5">
              <div class="h-4 w-4 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
              <span class="text-xs text-text-secondary">Loading sessions…</span>
            </div>
          {:else if sessions.length === 0}
            <p class="text-sm text-text-muted py-4">No sessions found. Run a test first.</p>
          {:else}
            <div class="space-y-1.5 max-h-80 overflow-y-auto">
              {#each sessions as session}
                <button
                  class="w-full text-left px-4 py-3 rounded-xl text-sm transition-all duration-200 cursor-pointer
                    {sessionId === session.id
                      ? 'bg-accent-muted border border-accent/30'
                      : 'hover:bg-surface-elevated border border-transparent'}"
                  onclick={() => selectSession(session.id)}
                >
                  <div class="flex items-center justify-between">
                    <span class="text-text-primary truncate flex-1 mr-2 font-mono text-xs">{session.id.slice(0, 12)}…</span>
                    <Badge
                      variant={session.status === 'completed' ? 'success' : session.status === 'failed' ? 'danger' : session.status === 'aborted' ? 'danger' : session.status === 'running' ? 'accent' : 'default'}
                      dot
                    >
                      {#snippet children()}{session.status}{/snippet}
                    </Badge>
                  </div>
                  {#if session.goal}
                    <p class="text-xs text-text-secondary mt-1 truncate">{session.goal}</p>
                  {/if}
                </button>
              {/each}
            </div>
          {/if}
        {/snippet}
      </Card>

      <!-- Verification panel -->
      <div class="lg:col-span-2 space-y-4">
        <Card title="Verification" subtitle={sessionId ? `Session: ${sessionId.slice(0, 16)}…` : "Select a session"}>
          {#snippet children()}
            <div class="space-y-4">
              <div class="flex flex-wrap gap-3">
                <Input
                  bind:value={sessionId}
                  placeholder="Session ID (or select from list)"
                  class="flex-1 min-w-[180px]"
                />
                <div class="flex gap-2 shrink-0">
                  <Button variant="primary" onclick={fetchVC} loading={loading} disabled={!sessionId || (selectedSession != null && !canHaveVC)}>
                    {#snippet children()}Fetch VC{/snippet}
                  </Button>
                  <Button variant="secondary" onclick={verifyVC} loading={loading} disabled={!sessionId || (selectedSession != null && !canHaveVC)}>
                    {#snippet children()}Verify{/snippet}
                  </Button>
                </div>
              </div>

              <!-- Info message for non-completed sessions -->
              {#if selectedSession && !canHaveVC}
                <div class="flex items-center gap-2.5 p-3 rounded-lg bg-amber-400/5 border border-amber-400/20">
                  <svg class="w-4 h-4 text-amber-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                  <p class="text-xs text-text-secondary">
                    {#if selectedSession.status === "aborted"}
                      This session was <strong class="text-danger">aborted</strong> by the tripwire — no Verifiable Credential is issued for blocked sessions. This is expected for adversarial/sad-path tests.
                    {:else if selectedSession.status === "failed"}
                      This session <strong class="text-danger">failed</strong> — no Verifiable Credential was generated. Only successfully completed sessions produce a VC.
                    {:else}
                      This session is <strong class="text-accent">{selectedSession.status}</strong> — a Verifiable Credential is only available after completion.
                    {/if}
                  </p>
                </div>
              {/if}

              {#if error}
                <div class="p-3 rounded-lg bg-danger-muted border border-danger/30 text-sm text-danger">{error}</div>
              {/if}

              {#if verifyResult}
                {@const r = verifyResult}
                <div class="p-4 rounded-lg border {r.valid ? 'bg-success-muted border-success/30' : 'bg-danger-muted border-danger/30'}">
                  <div class="flex items-center gap-2 mb-2">
                    <Badge variant={r.valid ? 'success' : 'danger'} dot>
                      {#snippet children()}{r.valid ? 'Valid' : 'Invalid'}{/snippet}
                    </Badge>
                  </div>
                  <p class="text-sm text-text-secondary">{r.message}</p>
                </div>
              {/if}

              {#if vcData}
                <div class="space-y-2">
                  <h4 class="text-sm font-semibold text-text-primary">Verifiable Credential</h4>
                  <pre class="p-6 rounded-xl bg-surface-elevated border border-border-muted/15 text-xs text-text-secondary font-mono overflow-x-auto max-h-96 overflow-y-auto">{JSON.stringify(vcData, null, 2)}</pre>
                </div>
              {/if}
            </div>
          {/snippet}
        </Card>

        <!-- Quick checks -->
        <Card title="Integrity Checks">
          {#snippet children()}
            <div class="grid grid-cols-2 gap-4">
              <div class="p-5 rounded-xl bg-surface-elevated border border-border-muted/15">
                <div class="text-xs text-text-muted uppercase tracking-wider mb-1">Merkle Root</div>
                <div class="text-sm text-text-primary font-mono">
                  {#if vcData && (vcData as Record<string, unknown>).merkle_root}
                    {String((vcData as Record<string, unknown>).merkle_root).slice(0, 24)}…
                  {:else}
                    <span class="text-text-muted">—</span>
                  {/if}
                </div>
              </div>
              <div class="p-5 rounded-xl bg-surface-elevated border border-border-muted/15">
                <div class="text-xs text-text-muted uppercase tracking-wider mb-1">Signature</div>
                <div class="text-sm text-text-primary font-mono">
                  {#if vcData && (vcData as Record<string, unknown>).proof}
                    <Badge variant="success" dot>{#snippet children()}Signed{/snippet}</Badge>
                  {:else}
                    <span class="text-text-muted">—</span>
                  {/if}
                </div>
              </div>
              <div class="p-5 rounded-xl bg-surface-elevated border border-border-muted/15">
                <div class="text-xs text-text-muted uppercase tracking-wider mb-1">Events</div>
                <div class="text-sm text-text-primary">
                  {#if vcData && (vcData as Record<string, unknown>).event_count}
                    {(vcData as Record<string, unknown>).event_count}
                  {:else}
                    <span class="text-text-muted">—</span>
                  {/if}
                </div>
              </div>
              <div class="p-5 rounded-xl bg-surface-elevated border border-border-muted/15">
                <div class="text-xs text-text-muted uppercase tracking-wider mb-1">Policy Hash</div>
                <div class="text-sm text-text-primary font-mono">
                  {#if vcData && (vcData as Record<string, unknown>).policy_hash}
                    {String((vcData as Record<string, unknown>).policy_hash).slice(0, 24)}…
                  {:else}
                    <span class="text-text-muted">—</span>
                  {/if}
                </div>
              </div>
            </div>
          {/snippet}
        </Card>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════════════════════════════════════
       HAPPY PATH SECTION
       ═══════════════════════════════════════════════════════════════════════ -->
  <div class="rounded-2xl border border-border-muted/20 bg-surface overflow-hidden">
    <!-- Section header (click to toggle) -->
    <button
      class="w-full flex items-center justify-between px-6 py-4 cursor-pointer hover:bg-surface-elevated/50 transition-colors"
      onclick={() => (happyExpanded = !happyExpanded)}
    >
      <div class="flex items-center gap-3">
        <svg
          class="w-4 h-4 text-text-muted transition-transform duration-200 {happyExpanded ? 'rotate-90' : ''}"
          viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
        >
          <polyline points="9 18 15 12 9 6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <div class="flex items-center gap-2">
          <div class="w-2.5 h-2.5 rounded-full bg-success"></div>
          <h2 class="text-base font-semibold text-text-primary">Happy Path Tests</h2>
        </div>
        <span class="text-xs text-text-muted">({happyPathTests.length} tests)</span>
      </div>
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <div role="toolbar" tabindex="-1" class="flex items-center gap-3" onclick={(e: MouseEvent) => e.stopPropagation()}>
        <Button variant="primary" onclick={runAllHappyTests}>
          {#snippet children()}Run All{/snippet}
        </Button>
      </div>
    </button>

    <!-- Collapsible content -->
    {#if happyExpanded}
      <div class="px-6 pb-6 space-y-6 border-t border-border-muted/10">
        <!-- Test cards grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-5 pt-5">
          {#each happyPathTests as test}
            {@const status = happyStatuses[test.id] ?? "idle"}
            {@const resultText = happyResults[test.id] ?? ""}
            {@const hasSession = !!happySessionIds[test.id]}
            <div class="bg-surface-elevated rounded-2xl p-5 flex flex-col gap-3.5 border border-border-muted/10 hover:border-border-muted/25 transition-all duration-200">
              <div class="flex items-start justify-between gap-2">
                <div>
                  <p class="text-xs text-text-muted uppercase tracking-wider mb-0.5">{test.category}</p>
                  <h3 class="text-sm font-semibold text-text-primary">{test.name}</h3>
                </div>
                {#if status === "idle"}
                  <Badge variant="default">{#snippet children()}Idle{/snippet}</Badge>
                {:else if status === "running"}
                  <Badge variant="accent" dot>{#snippet children()}Running{/snippet}</Badge>
                {:else if status === "pass"}
                  <Badge variant="success" dot>{#snippet children()}Pass{/snippet}</Badge>
                {:else}
                  <Badge variant="danger" dot>{#snippet children()}Fail{/snippet}</Badge>
                {/if}
              </div>
              <p class="text-xs text-text-secondary leading-relaxed">{test.description}</p>
              <div class="bg-surface rounded-xl border border-border-muted/15 p-3.5">
                <p class="text-[10px] text-text-muted uppercase tracking-wider mb-1">Prompt</p>
                <p class="text-xs font-mono text-text-primary break-words">{test.prompt}</p>
              </div>
              {#if resultText}
                <p class="text-xs {status === 'pass' ? 'text-success' : 'text-danger'}">{resultText}</p>
              {/if}
              <div class="flex gap-2">
                <Button
                  variant={status === "running" ? "secondary" : "primary"}
                  onclick={() => runHappyTest(test.id, test.prompt)}
                  loading={status === "running"}
                >
                  {#snippet children()}{status === "running" ? "Running…" : "Run Test"}{/snippet}
                </Button>
                {#if hasSession && status === "pass"}
                  <Button variant="secondary" onclick={() => selectSession(happySessionIds[test.id])}>
                    {#snippet children()}Select Session{/snippet}
                  </Button>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </div>

  <!-- ═══════════════════════════════════════════════════════════════════════
       SAD PATH SECTION
       ═══════════════════════════════════════════════════════════════════════ -->
  <div class="rounded-2xl border border-border-muted/20 bg-surface overflow-hidden">
    <!-- Section header (click to toggle) -->
    <button
      class="w-full flex items-center justify-between px-6 py-4 cursor-pointer hover:bg-surface-elevated/50 transition-colors"
      onclick={() => (sadExpanded = !sadExpanded)}
    >
      <div class="flex items-center gap-3">
        <svg
          class="w-4 h-4 text-text-muted transition-transform duration-200 {sadExpanded ? 'rotate-90' : ''}"
          viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
        >
          <polyline points="9 18 15 12 9 6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <div class="flex items-center gap-2">
          <div class="w-2.5 h-2.5 rounded-full bg-danger"></div>
          <h2 class="text-base font-semibold text-text-primary">Sad Path Tests</h2>
        </div>
        <span class="text-xs text-text-muted">({adversarialTests.length} tests)</span>
      </div>
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <div role="toolbar" tabindex="-1" class="flex items-center gap-3" onclick={(e: MouseEvent) => e.stopPropagation()}>
        <Button variant="danger" onclick={runAllAdversarialTests}>
          {#snippet children()}Run All{/snippet}
        </Button>
      </div>
    </button>

    <!-- Collapsible content -->
    {#if sadExpanded}
      <div class="px-6 pb-6 border-t border-border-muted/10">
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 pt-5">
          {#each adversarialTests as test}
            {@const status = testStatuses[test.id] ?? "idle"}
            {@const resultText = testResults[test.id] ?? ""}
            <div class="bg-surface-elevated rounded-2xl p-5 flex flex-col gap-3.5 border border-border-muted/10 hover:border-border-muted/25 transition-all duration-200">
              <div class="flex items-start justify-between gap-2">
                <div>
                  <p class="text-xs text-text-muted uppercase tracking-wider mb-0.5">{test.category}</p>
                  <h3 class="text-sm font-semibold text-text-primary">{test.name}</h3>
                </div>
                {#if status === "idle"}
                  <Badge variant="default">{#snippet children()}Idle{/snippet}</Badge>
                {:else if status === "running"}
                  <Badge variant="accent" dot>{#snippet children()}Running{/snippet}</Badge>
                {:else if status === "pass"}
                  <Badge variant="success" dot>{#snippet children()}Pass{/snippet}</Badge>
                {:else}
                  <Badge variant="danger" dot>{#snippet children()}Fail{/snippet}</Badge>
                {/if}
              </div>
              <p class="text-xs text-text-secondary leading-relaxed">{test.description}</p>
              <div class="bg-surface rounded-xl border border-border-muted/15 p-3.5">
                <p class="text-[10px] text-text-muted uppercase tracking-wider mb-1">Prompt</p>
                <p class="text-xs font-mono text-text-primary break-words">{test.prompt}</p>
              </div>
              {#if resultText}
                <p class="text-xs {status === 'pass' ? 'text-success' : 'text-danger'}">{resultText}</p>
              {/if}
              <Button
                variant={status === "running" ? "secondary" : "primary"}
                onclick={() => runAdversarialTest(test.id, test.prompt)}
                loading={status === "running"}
              >
                {#snippet children()}{status === "running" ? "Running…" : "Run Test"}{/snippet}
              </Button>
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </div>
</div>
