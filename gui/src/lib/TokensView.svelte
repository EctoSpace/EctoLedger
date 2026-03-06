<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  interface ApiToken {
    token_hash: string;
    role: string;
    label: string;
    created_at: string;
    expires_at: string | null;
  }

  let tokens = $state<ApiToken[]>([]);
  let loading = $state(false);
  let error = $state("");
  let success = $state("");

  // Create form state
  let newLabel = $state("");
  let newRole = $state("auditor");
  let newExpiryDays = $state<number | null>(null);
  let creating = $state(false);
  let newTokenValue = $state(""); // revealed once after creation

  onMount(load);

  async function load() {
    if (!isTauri()) return;
    loading = true;
    error = "";
    try {
      const data = await invoke<unknown>("get_tokens");
      tokens = Array.isArray(data) ? (data as ApiToken[]) : [];
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function create() {
    if (!isTauri() || !newLabel.trim()) return;
    creating = true;
    error = "";
    success = "";
    newTokenValue = "";
    try {
      const result = await invoke<{ token: string }>("create_token", {
        label: newLabel.trim(),
        role: newRole,
        expiryDays: newExpiryDays,
      });
      if (!result?.token) {
        throw new Error("Unexpected server response: missing 'token' field");
      }
      newTokenValue = result.token;
      success = "Token created. Copy it now — it won't be shown again.";
      newLabel = "";
      newExpiryDays = null;
      await load();
    } catch (e) {
      error = String(e);
    } finally {
      creating = false;
    }
  }

  async function deleteToken(hash: string) {
    if (!isTauri() || !confirm("Revoke this token? This cannot be undone.")) return;
    error = "";
    success = "";
    try {
      await invoke("delete_token", { tokenHash: hash });
      success = "Token revoked.";
      await load();
    } catch (e) {
      error = String(e);
    }
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "Never";
    return new Date(iso).toLocaleString();
  }

  function roleClass(role: string): string {
    return { admin: "role-admin", auditor: "role-auditor", agent: "role-agent" }[role] ?? "role-default";
  }
</script>

<div class="flex flex-col gap-6 pb-6">
  <h2 class="text-xl font-bold text-text-primary m-0">API Tokens</h2>
  <p class="text-text-muted text-sm m-0">Manage RBAC bearer tokens for REST API and dashboard access.</p>

  {#if error}
    <div class="bg-danger-muted border border-danger/30 text-danger px-4 py-3 rounded-xl text-sm">{error}</div>
  {:else if success}
    <div class="bg-success-muted border border-success/30 text-success px-4 py-3 rounded-xl text-sm">{success}</div>
  {/if}

  {#if newTokenValue}
    <div class="bg-warning-muted border border-warning/30 rounded-xl p-4 flex flex-col gap-2">
      <span class="text-warning text-sm font-semibold">⚠ Save this token — it will not be shown again:</span>
      <code class="text-sm text-text-primary break-all">{newTokenValue}</code>
    </div>
  {/if}

  <!-- Create form -->
  <section class="bg-background rounded-2xl px-7 py-6 shadow-sm">
    <h3 class="text-base font-semibold text-text-primary mb-4 mt-0">Create New Token</h3>
    <div class="flex gap-4 flex-wrap mb-5">
      <div class="flex flex-col gap-1.5 flex-1 min-w-[140px]">
        <label for="label" class="text-xs text-text-muted uppercase tracking-wide">Label</label>
        <input id="label" type="text" bind:value={newLabel} placeholder="e.g. CI pipeline, auditor@corp" class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-inherit focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200" />
      </div>
      <div class="flex flex-col gap-1.5 flex-1 min-w-[140px]">
        <label for="role" class="text-xs text-text-muted uppercase tracking-wide">Role</label>
        <select id="role" bind:value={newRole} class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-inherit focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200">
          <option value="admin">admin</option>
          <option value="auditor">auditor</option>
          <option value="agent">agent</option>
        </select>
      </div>
      <div class="flex flex-col gap-1.5 flex-1 min-w-[140px]">
        <label for="expiry" class="text-xs text-text-muted uppercase tracking-wide">Expiry (days)</label>
        <input
          id="expiry"
          type="number"
          min="1"
          max="3650"
          bind:value={newExpiryDays}
          placeholder="Never"
          class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-inherit focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
        />
      </div>
    </div>
    <button class="px-6 py-3 border-none rounded-xl text-sm cursor-pointer font-inherit transition-all duration-200 bg-success hover:bg-success/80 text-white disabled:opacity-50 disabled:cursor-not-allowed active:scale-[0.98] shadow-sm hover:shadow-md" onclick={create} disabled={creating || !newLabel.trim()}>
      {creating ? "Creating…" : "Create Token"}
    </button>
  </section>

  <!-- Token list -->
  <section class="bg-surface rounded-2xl px-7 py-6 shadow-sm">
    <div class="flex justify-between items-center mb-5">
      <h3 class="text-base font-semibold text-text-primary m-0">Active Tokens</h3>
      <button class="px-4 py-2 border border-border-muted/30 rounded-xl text-xs cursor-pointer font-inherit transition-all duration-200 bg-transparent text-text-muted hover:text-text-primary hover:bg-surface-elevated" onclick={load}>↺ Refresh</button>
    </div>
    {#if loading}
      <p class="text-text-muted text-sm">Loading tokens…</p>
    {:else if tokens.length === 0}
      <p class="text-text-muted text-sm">No tokens yet. Create one above.</p>
    {:else}
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr>
            <th class="text-left text-text-muted text-xs uppercase tracking-wide px-4 py-2.5 border-b border-border-muted/15">Label</th>
            <th class="text-left text-text-muted text-xs uppercase tracking-wide px-4 py-2.5 border-b border-border-muted/15">Role</th>
            <th class="text-left text-text-muted text-xs uppercase tracking-wide px-4 py-2.5 border-b border-border-muted/15">Hash (truncated)</th>
            <th class="text-left text-text-muted text-xs uppercase tracking-wide px-4 py-2.5 border-b border-border-muted/15">Created</th>
            <th class="text-left text-text-muted text-xs uppercase tracking-wide px-4 py-2.5 border-b border-border-muted/15">Expires</th>
            <th class="text-left text-text-muted text-xs uppercase tracking-wide px-4 py-2.5 border-b border-border-muted/15"></th>
          </tr>
        </thead>
        <tbody>
          {#each tokens as t}
            <tr>
              <td class="px-4 py-3 border-b border-border-muted/10 text-text-primary">{t.label}</td>
              <td class="px-4 py-3 border-b border-border-muted/10 text-text-primary">
                <span class="px-3 py-1.5 rounded-full text-xs font-semibold uppercase {t.role === 'admin' ? 'bg-danger text-white' : t.role === 'auditor' ? 'bg-accent text-text-inverse' : t.role === 'agent' ? 'bg-success text-text-inverse' : 'bg-border text-text-primary'}">{t.role}</span>
              </td>
              <td class="px-4 py-3 border-b border-border-muted/10 text-text-primary"><code class="text-xs text-text-muted">{t.token_hash.slice(0, 12)}…</code></td>
              <td class="px-4 py-3 border-b border-border-muted/10 text-text-primary">{formatDate(t.created_at)}</td>
              <td class="px-4 py-3 border-b border-border-muted/10 text-text-primary">{formatDate(t.expires_at)}</td>
              <td class="px-4 py-3 border-b border-border-muted/10 text-text-primary">
                <button class="px-4 py-2 border-none rounded-xl text-xs cursor-pointer font-inherit transition-all duration-200 bg-danger hover:bg-danger/80 text-white disabled:opacity-50 disabled:cursor-not-allowed" onclick={() => deleteToken(t.token_hash)}>Revoke</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
</div>
