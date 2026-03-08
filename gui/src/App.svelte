<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import Sidebar from "./lib/Sidebar.svelte";
  import Dashboard from "./lib/Dashboard.svelte";
  import Sessions from "./lib/Sessions.svelte";
  import PolicyEditor from "./lib/PolicyEditor.svelte";
  import TripwireView from "./lib/TripwireView.svelte";
  import MetricsView from "./lib/MetricsView.svelte";
  import Settings from "./lib/Settings.svelte";
  import TokensView from "./lib/TokensView.svelte";
  import WebhooksView from "./lib/WebhooksView.svelte";
  import SetupWizard from "./lib/SetupWizard.svelte";
  import TestingView from "./lib/TestingView.svelte";
  import DevHub from "./lib/DevHub.svelte";
  import LiveDashboard from "./lib/LiveDashboard.svelte";

  let activeTab = $state("dashboard");
  let serverUrl = $state("");
  let initialized = $state(false);
  let initError = $state("");
  let needsSetup = $state(false);

  /**
   * Initialization routine: the embedded server is started by Tauri's setup
   * hook, so we just read the URL from the Rust backend.
   */
  async function initializeServerUrl(): Promise<string> {
    if (!isTauri()) {
      throw new Error(
        "Run this app via the Ecto Ledger desktop window, not in a browser."
      );
    }
    try {
      return await invoke<string>("server_url");
    } catch {
      const candidates = [3000, 4141, 8080];
      for (const port of candidates) {
        const candidate = `http://127.0.0.1:${port}`;
        try {
          const res = await fetch(`${candidate}/api/config`, {
            signal: AbortSignal.timeout(1500),
          });
          if (res.ok) {
            const body = await res.json();
            if (body && typeof body === "object" && "llm_backend" in body) {
              return candidate;
            }
          }
        } catch {
          // port not responding, try next
        }
      }
      throw new Error(
        "Could not determine backend server URL. Ensure the Ecto Ledger backend is running."
      );
    }
  }

  onMount(async () => {
    try {
      serverUrl = await initializeServerUrl();
      // Check if first launch — if no LLM config is set, show wizard
      try {
        const complete = await invoke<boolean>("check_setup_complete");
        if (!complete) needsSetup = true;
      } catch {
        // Tauri command unavailable in browser preview — show dashboard anyway
      }
      initialized = true;
    } catch (e) {
      initError = e instanceof Error ? e.message : String(e);
    }
  });

  function handleSetupComplete() {
    needsSetup = false;
    activeTab = "dashboard";
  }
</script>

{#if initError}
  <div class="flex items-center justify-center h-screen w-screen bg-background">
    <div class="max-w-md p-12 bg-surface rounded-2xl shadow-md text-center animate-fade-in">
      <h2 class="text-danger font-semibold text-lg mb-5">Connection Error</h2>
      <p class="text-text-primary text-sm leading-relaxed">{initError}</p>
      <p class="text-text-muted text-xs mt-5">Check that the backend is running and try restarting the application.</p>
    </div>
  </div>
{:else if !initialized}
  <div class="flex flex-col items-center justify-center gap-6 h-screen w-screen bg-background">
    <div class="text-center animate-pulse-gentle">
      <div class="h-10 w-10 mx-auto mb-6 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
      <p class="text-accent text-sm">Connecting to backend…</p>
    </div>
  </div>
{:else if needsSetup}
  <SetupWizard {serverUrl} onComplete={handleSetupComplete} />
{:else}
  <div class="flex h-screen w-screen bg-background overflow-hidden">
    <Sidebar bind:activeTab {serverUrl} />

    <!-- Scrollable content area -->
    <main class="flex-1 min-w-0 min-h-0 overflow-y-auto overflow-x-hidden max-w-full">
    <div class="p-6 md:p-8 lg:p-10 pb-16">
      {#if activeTab === "dashboard"}
        <Dashboard {serverUrl} onNavigateToTab={(t: string) => (activeTab = t)} />
      {:else if activeTab === "sessions"}
        <Sessions />
      {:else if activeTab === "policies"}
        <PolicyEditor />
      {:else if activeTab === "tripwire"}
        <TripwireView />
      {:else if activeTab === "metrics"}
        <MetricsView />
      {:else if activeTab === "testing"}
        <TestingView {serverUrl} />
      {:else if activeTab === "devhub"}
        <DevHub {serverUrl} />
      {:else if activeTab === "settings"}
        <Settings />
      {:else if activeTab === "tokens"}
        <TokensView />
      {:else if activeTab === "webhooks"}
        <WebhooksView />
      {:else if activeTab === "livedashboard"}
        <LiveDashboard {serverUrl} />
      {/if}
    </div>
    </main>
  </div>
{/if}
