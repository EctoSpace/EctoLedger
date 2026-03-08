<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  let config = $state<{
    allowed_paths?: string[];
    allowed_domains?: string[];
    banned_command_patterns?: string[];
    min_justification_length?: number;
    require_https?: boolean;
  } | null>(null);
  let allowedPathsText = $state("");
  let allowedDomainsText = $state("");
  let bannedPatterns = $state<string[]>([]);
  let newPatternInput = $state("");
  let error = $state("");
  let saveError = $state("");
  let saving = $state(false);

  onMount(load);

  async function load() {
    if (!isTauri()) return;
    try {
      const data = await invoke<unknown>("get_tripwire_config");
      config = data && typeof data === "object" && !Array.isArray(data)
        ? (data as Record<string, unknown>) as { allowed_paths?: string[]; allowed_domains?: string[]; banned_command_patterns?: string[]; min_justification_length?: number; require_https?: boolean }
        : null;
      if (config) {
        allowedPathsText = (config.allowed_paths ?? []).join("\n");
        allowedDomainsText = (config.allowed_domains ?? []).join("\n");
        bannedPatterns = [...(config.banned_command_patterns ?? [])];
        if (config.min_justification_length == null) config.min_justification_length = 5;
        if (config.require_https == null) config.require_https = true;
      }
      error = "";
      saveError = "";
    } catch (e) {
      error = String(e);
    }
  }

  function fromLines(s: string): string[] {
    return s
      .split("\n")
      .map((x) => x.trim())
      .filter((x) => x.length > 0);
  }

  function addBannedPattern() {
    const trimmed = newPatternInput.trim();
    if (trimmed && !bannedPatterns.includes(trimmed)) {
      bannedPatterns = [...bannedPatterns, trimmed];
      newPatternInput = "";
    }
  }

  let editingIndex = $state<number | null>(null);
  let editingValue = $state("");
  let editInputRef = $state<HTMLInputElement | null>(null);

  $effect(() => {
    if (editingIndex !== null) {
      const timer = setTimeout(() => {
        editInputRef?.focus();
        editInputRef?.select();
      }, 0);
      return () => clearTimeout(timer);
    }
  });

  function startEdit(index: number) {
    editingIndex = index;
    editingValue = bannedPatterns[index] ?? "";
  }

  function commitEdit() {
    if (editingIndex === null) return;
    const trimmed = editingValue.trim();
    if (trimmed) {
      const next = [...bannedPatterns];
      next[editingIndex] = trimmed;
      bannedPatterns = next;
    }
    editingIndex = null;
    editingValue = "";
  }

  function cancelEdit() {
    editingIndex = null;
    editingValue = "";
  }

  async function removeBannedPattern(pattern: string) {
    if (!confirm(`Remove banned pattern "${pattern}"?`)) return;
    bannedPatterns = bannedPatterns.filter((p) => p !== pattern);
  }

  async function save() {
    if (!isTauri() || !config) return;
    saving = true;
    saveError = "";
    try {
      const minLen = Number(config.min_justification_length);
      const payload = {
        allowed_paths: fromLines(allowedPathsText),
        allowed_domains: fromLines(allowedDomainsText),
        banned_command_patterns: [...bannedPatterns],
        min_justification_length: Number.isNaN(minLen) || minLen < 0 ? 5 : Math.min(500, Math.floor(minLen)),
        require_https: config.require_https ?? true,
      };
      await invoke("save_tripwire_config", { payload });
      config = { ...config, ...payload };
    } catch (e) {
      saveError = String(e);
    } finally {
      saving = false;
    }
  }
</script>

<div class="flex flex-col gap-8 pb-6">
  <div class="bg-surface p-8 rounded-2xl max-w-2xl shadow-sm">
    <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-5">Tripwire Configuration</h2>
    <p class="text-text-muted text-sm">
      Tripwires restrict what the agent can do: allowed paths for file access, allowed domains for HTTP,
      and banned command patterns. Edit below and save to persist.
    </p>

    {#if error}
      <p class="text-danger text-sm">{error}</p>
    {:else if config}
      <form onsubmit={(e) => { e.preventDefault(); save(); }}>
        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">Allowed paths (file access)</h3>
          <textarea
            class="w-full bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-4 text-sm font-mono resize-y focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
            rows="3"
            placeholder="/path/to/workspace"
            bind:value={allowedPathsText}
          ></textarea>
          <p class="text-xs text-text-muted mt-1.5">One path per line</p>
        </section>

        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">Allowed domains (HTTP)</h3>
          <textarea
            class="w-full bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-4 text-sm font-mono resize-y focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
            rows="3"
            placeholder="example.com&#10;api.example.com"
            bind:value={allowedDomainsText}
          ></textarea>
          <p class="text-xs text-text-muted mt-1.5">One domain per line</p>
        </section>

        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">Validation rules</h3>
          <dl class="text-sm">
            <dt class="text-text-muted mt-3">Min justification length (chars)</dt>
            <dd class="mt-1">
              <input
                type="number"
                min="0"
                max="500"
                class="w-20 bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
                bind:value={config.min_justification_length}
                placeholder="5"
              />
              <span class="text-xs text-text-muted mt-1.5">Actions (except complete) require a justification of at least this many characters</span>
            </dd>
            <dt class="text-text-muted mt-3">Require HTTPS for HTTP requests</dt>
            <dd class="mt-1">
              <select class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-4 py-2.5 text-sm cursor-pointer focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
                value={config.require_https ? "true" : "false"}
                onchange={(e) => { if (config) config.require_https = (e.target as HTMLSelectElement).value === "true"; }}
              >
                <option value="true">Yes</option>
                <option value="false">No</option>
              </select>
            </dd>
          </dl>
        </section>

        <section class="my-6">
          <h3 class="text-sm text-text-muted mb-3">Banned command patterns</h3>
          <div class="flex gap-3 mb-4">
            <input
              type="text"
              class="flex-1 bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-5 py-3 text-sm font-mono focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
              placeholder="Add pattern (e.g. rm -rf, sudo)"
              bind:value={newPatternInput}
              onkeydown={(e) => e.key === "Enter" && (e.preventDefault(), addBannedPattern())}
            />
            <button class="bg-surface-elevated border border-border-muted/40 rounded-xl text-accent px-5 py-3 text-sm cursor-pointer hover:bg-border-muted transition-all duration-200" type="button" onclick={addBannedPattern}>Add</button>
          </div>
          <div class="flex flex-wrap gap-2.5">
            {#each bannedPatterns as pattern, i}
              <span class="inline-flex items-center gap-2 bg-black/20 rounded-xl px-4 py-2 text-sm border border-success/20">
                {#if editingIndex === i}
                  <input
                    type="text"
                    class="bg-black/30 border border-success/40 rounded-xl text-success px-3 py-1.5 text-sm font-mono min-w-20 focus:outline-none focus:border-success/80 transition-all duration-200"
                    bind:this={editInputRef}
                    bind:value={editingValue}
                    onblur={commitEdit}
                    onkeydown={(e) => {
                      if (e.key === "Enter") commitEdit();
                      if (e.key === "Escape") cancelEdit();
                    }}
                    onclick={(e) => e.stopPropagation()}
                  />
                {:else}
                  <span
                    class="cursor-pointer select-none"
                    role="button"
                    tabindex="0"
                    onclick={() => startEdit(i)}
                    onkeydown={(e) => e.key === "Enter" && startEdit(i)}
                  >
                    <code class="text-success hover:underline">{pattern}</code>
                  </span>
                {/if}
                <button
                  class="inline-flex items-center justify-center bg-transparent border-none rounded-sm text-danger p-0.5 cursor-pointer transition-colors hover:text-danger hover:bg-danger/20"
                  type="button"
                  title="Remove"
                  onclick={(e) => { e.stopPropagation(); removeBannedPattern(pattern); }}
                  aria-label="Remove {pattern}"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="3 6 5 6 21 6"></polyline>
                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    <line x1="10" y1="11" x2="10" y2="17"></line>
                    <line x1="14" y1="11" x2="14" y2="17"></line>
                  </svg>
                </button>
              </span>
            {/each}
          </div>
          <p class="text-xs text-text-muted mt-1.5">Commands matching any pattern are blocked</p>
        </section>

        {#if saveError}
          <p class="text-danger text-sm">{saveError}</p>
        {/if}

        <div class="flex gap-4 mt-8">
          <button class="bg-transparent border border-border-muted/30 rounded-xl text-accent px-5 py-3 text-sm cursor-pointer hover:bg-surface-elevated transition-all duration-200" type="button" onclick={load}>↻ Refresh</button>
          <button class="bg-accent border-none rounded-xl text-white px-6 py-3 text-sm cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed transition-all duration-200 active:scale-[0.98] shadow-sm shadow-accent/20 hover:shadow-md hover:bg-accent-hover" type="submit" disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    {:else}
      <p class="text-text-secondary text-sm">Loading…</p>
    {/if}
  </div>
</div>
