<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { getVersion } from "@tauri-apps/api/app";
  import { onMount } from "svelte";

  let { activeTab = $bindable(), serverUrl = "" }: { activeTab: string; serverUrl?: string } = $props();

  let appVersion = $state("…");
  let demoMode = $state(false);

  if (isTauri()) {
    getVersion().then((v) => (appVersion = `v${v}`)).catch(() => { appVersion = "v?.?.?"; });
    // Primary: read env var from inside the Tauri process (works on Linux/macOS
    // but may miss it on Windows where the Start-Job → npm → cargo → Tauri
    // spawn chain can lose process-scope env vars).
    invoke<boolean>("is_demo_mode").then((v) => { if (v) demoMode = true; }).catch(() => {});
  } else {
    appVersion = `v${__APP_VERSION__}`;
  }

  // Fallback: ask the backend's public /api/status endpoint for demo_mode.
  // This is the authoritative path on Windows because the backend process
  // always receives ECTO_DEMO_MODE via the explicit env-snapshot mechanism
  // in the PowerShell launcher.  We use onMount (instead of a top-level if)
  // so the fetch runs after the DOM is ready and the backend has fully started.
  // A single retry after 2 s handles slow Windows cold-starts.
  onMount(() => {
    if (!serverUrl) return;
    const checkStatus = () =>
      fetch(`${serverUrl}/api/status`, { signal: AbortSignal.timeout(5000) })
        .then((r) => (r.ok ? r.json() : Promise.reject()))
        .then((body: { demo_mode?: boolean }) => { if (body?.demo_mode) demoMode = true; });

    checkStatus().catch(() => {
      // Retry once after 2 s — backend may still be initialising on Windows.
      setTimeout(() => checkStatus().catch(() => {}), 2000);
    });
  });

  /* ── SVG icon paths (lucide, stroke-only, viewBox 0 0 24 24) ── */
  const icons: Record<string, string> = {
    dashboard:     `<path stroke-linecap="round" stroke-linejoin="round" d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline stroke-linecap="round" stroke-linejoin="round" points="9 22 9 12 15 12 15 22"/>`,
    livedashboard: `<polyline stroke-linecap="round" stroke-linejoin="round" points="22 12 18 12 15 21 9 3 6 12 2 12"/>`,
    sessions:      `<path stroke-linecap="round" stroke-linejoin="round" d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4" stroke-linecap="round"/><path stroke-linecap="round" stroke-linejoin="round" d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>`,
    metrics:       `<line stroke-linecap="round" x1="18" y1="20" x2="18" y2="10"/><line stroke-linecap="round" x1="12" y1="20" x2="12" y2="4"/><line stroke-linecap="round" x1="6"  y1="20" x2="6"  y2="14"/>`,
    testing:       `<polygon stroke-linecap="round" stroke-linejoin="round" points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>`,
    policies:      `<path stroke-linecap="round" stroke-linejoin="round" d="M9 11l3 3L22 4"/><path stroke-linecap="round" stroke-linejoin="round" d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>`,
    tripwire:      `<path stroke-linecap="round" stroke-linejoin="round" d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line stroke-linecap="round" x1="12" y1="9" x2="12" y2="13"/><line stroke-linecap="round" x1="12" y1="17" x2="12.01" y2="17"/>`,
    tokens:        `<rect stroke-linecap="round" stroke-linejoin="round" x="3" y="11" width="18" height="11" rx="2" ry="2"/><path stroke-linecap="round" stroke-linejoin="round" d="M7 11V7a5 5 0 0 1 10 0v4"/>`,
    webhooks:      `<polyline stroke-linecap="round" stroke-linejoin="round" points="22 12 16 12 14 15 10 9 8 12 2 12"/><path stroke-linecap="round" stroke-linejoin="round" d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>`,
    devhub:        `<polyline stroke-linecap="round" stroke-linejoin="round" points="16 18 22 12 16 6"/><polyline stroke-linecap="round" stroke-linejoin="round" points="8 6 2 12 8 18"/>`,
    settings:      `<circle cx="12" cy="12" r="3"/><path stroke-linecap="round" stroke-linejoin="round" d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>`,
  };

  interface NavItem {
    id: string;
    label: string;
    section?: string;
  }

  const tabs: NavItem[] = [
    { id: "dashboard",     label: "Live Metrics",    section: "Core" },
    { id: "livedashboard", label: "Active Audit" },
    { id: "sessions",      label: "Audit History" },
    { id: "metrics",       label: "Metrics" },
    { id: "testing",       label: "Testing",         section: "Verification" },
    { id: "policies",      label: "Policies" },
    { id: "tripwire",      label: "Tripwire" },
    { id: "tokens",        label: "Tokens",          section: "Admin" },
    { id: "webhooks",      label: "Webhooks" },
    { id: "devhub",        label: "Dev Hub",         section: "Developer" },
    { id: "settings",      label: "Settings" },
  ];
</script>

<nav class="w-64 min-w-64 flex flex-col bg-surface border-r border-border-muted/15 shadow-sm py-6 px-4 overflow-y-auto overflow-x-hidden">
  <!-- Wordmark -->
  <div class="flex items-center gap-3.5 px-3 mb-6 pb-5 border-b border-border-muted/10">
    <img src="/el-logo.webp" alt="" class="w-9 h-9 object-contain shrink-0" />
    <span class="text-lg font-semibold tracking-tight text-text-primary">EctoLedger</span>
    {#if demoMode}
      <span class="ml-auto text-[10px] font-bold uppercase tracking-widest text-amber-400 bg-amber-400/10 border border-amber-400/25 rounded-md px-2 py-0.5 select-none">Demo</span>
    {/if}
  </div>

  <!-- Navigation -->
  <ul class="flex-1 space-y-px list-none">
    {#each tabs as t}
      {#if t.section}
        <li class="pt-8 pb-3 px-3 first:pt-0">
          <span class="text-[11px] uppercase tracking-[0.12em] text-text-muted font-semibold">{t.section}</span>
        </li>
      {/if}
      <li>
        <button
          class="flex items-center gap-3 w-full px-4 py-2.5 border-none rounded-xl cursor-pointer text-sm transition-all duration-200
            {activeTab === t.id
              ? 'bg-accent/8 text-accent font-medium border-l-2 border-l-accent'
              : 'bg-transparent text-text-secondary hover:bg-surface-elevated hover:text-text-primary border-l-2 border-l-transparent'}"
          onclick={() => (activeTab = t.id)}
        >
          <!-- SVG icon: 16×16 display, lucide style -->
          <svg
            width="16" height="16" viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.75"
            class="shrink-0 {activeTab === t.id ? 'text-accent' : 'text-text-muted'}"
          >
            {@html icons[t.id] ?? ""}
          </svg>
          <span class="truncate">{t.label}</span>
        </button>
      </li>
    {/each}
  </ul>

  <!-- Footer -->
  <div class="flex flex-col items-center gap-2.5 pt-6 mt-4">
    {#if isTauri()}
      <button
        class="bg-transparent border border-border-muted/30 rounded-xl text-text-secondary px-4 py-2 text-xs cursor-pointer hover:text-text-primary hover:bg-surface-elevated transition-all duration-200 w-full mx-1"
        onclick={() => invoke("open_devtools").catch(console.error)}
        title="Open Developer Console"
      >
        DevTools
      </button>
    {/if}
    <span class="text-text-muted text-[10px]">{appVersion}</span>
  </div>
</nav>
