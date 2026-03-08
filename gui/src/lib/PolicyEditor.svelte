<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";

  let policies = $state<string[]>([]);
  let selected = $state("");
  let content = $state("");
  let original = $state("");
  let saving = $state(false);
  let saveMsg = $state("");
  let newPolicyName = $state("");
  let creating = $state(false);
  let createError = $state("");
  let loadError = $state("");
  let _loadSeq = 0;
  let _timers: ReturnType<typeof setTimeout>[] = [];

  onDestroy(() => {
    _timers.forEach(clearTimeout);
  });

  const DEFAULT_POLICY_TEMPLATE = `# New policy

name = "policy-name"
goal = "Describe the audit goal here."
max_steps = 20

allowed_actions = ["run_command", "read_file", "http_get", "complete"]
forbidden_actions = ["write_file", "delete_file"]
required_checks = []
`;

  onMount(load);

  async function load() {
    if (!isTauri()) return;
    loadError = "";
    try {
      const data = await invoke<unknown>("get_policies");
      policies = Array.isArray(data) ? (data as string[]) : [];
      if (policies.length > 0 && !selected) {
        selected = policies[0];
        await loadPolicyContent(policies[0]);
      }
    } catch (e) {
      loadError = `Failed to load policies: ${e}`;
    }
  }

  async function loadPolicyContent(name: string) {
    if (!isTauri()) return;
    const seq = ++_loadSeq;
    try {
      const data = await invoke<string>("get_policy_content", { name });
      if (seq !== _loadSeq) return; // stale response guard
      content = data;
      original = content;
    } catch (e) {
      if (seq !== _loadSeq) return;
      content = `# Policy: ${name}\n# (Failed to load: ${e})\n# Edit TOML controls here`;
      original = content;
    }
  }

  async function save() {
    saving = true;
    saveMsg = "";
    try {
      await invoke("save_policy", { name: selected, content });
      original = content;
      saveMsg = "Saved successfully.";
    } catch (e) {
      saveMsg = String(e);
    } finally {
      saving = false;
      _timers.push(setTimeout(() => (saveMsg = ""), 3000));
    }
  }

  async function selectPolicy(name: string) {
    if (dirty && !confirm("You have unsaved changes. Discard?")) return;
    selected = name;
    await loadPolicyContent(name);
  }

  function sanitizePolicyName(name: string): string {
    return name.trim().replace(/[^a-zA-Z0-9_-]/g, "-").toLowerCase() || "new-policy";
  }

  async function deletePolicy() {
    if (!isTauri() || !selected) return;
    if (!confirm(`Delete policy "${selected}"? This cannot be undone.`)) return;
    try {
      await invoke("delete_policy", { name: selected });
      selected = "";
      content = "";
      original = "";
      await load();
    } catch (e) {
      saveMsg = String(e);
      _timers.push(setTimeout(() => (saveMsg = ""), 3000));
    }
  }

  const BUILTIN_POLICIES = ["soc2-audit", "pci-dss-audit", "owasp-top10", "iso42001"];

  async function addPolicy() {
    if (!isTauri() || !newPolicyName.trim()) return;
    const name = sanitizePolicyName(newPolicyName);
    if (policies.includes(name)) {
      createError = `Policy "${name}" already exists.`;
      _timers.push(setTimeout(() => (createError = ""), 3000));
      return;
    }
    creating = true;
    createError = "";
    try {
      const template = DEFAULT_POLICY_TEMPLATE.replace(/policy-name/g, name);
      await invoke("save_policy", { name, content: template });
      await load();
      selected = name;
      await loadPolicyContent(name);
      newPolicyName = "";
    } catch (e) {
      createError = String(e);
    } finally {
      creating = false;
    }
  }

  const dirty = $derived(content !== original);
  const canDelete = $derived(selected && !dirty && !BUILTIN_POLICIES.includes(selected));

  const validationError = $derived.by(() => {
    try {
      const lines = content.split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[")) continue;
        if (trimmed === "]" || trimmed === "],") continue;
        if (trimmed.includes("=")) continue;
        if (trimmed.startsWith('"') || trimmed.startsWith("'")) continue;
        return `Unexpected line: "${trimmed}"`;
      }
      return null;
    } catch {
      return "Parse error";
    }
  });
</script>

<div class="flex gap-6 h-full overflow-hidden">
  <!-- Policy list -->
  <aside class="bg-surface rounded-2xl w-64 min-w-64 max-w-64 p-6 overflow-y-auto overflow-x-hidden flex flex-col gap-3 shrink-0 shadow-sm">
    <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Policies</h2>
    <div class="flex gap-2 mb-4 shrink-0 min-w-0">
      <input
        type="text"
        class="flex-1 min-w-0 bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-4 py-2.5 text-sm outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
        placeholder="New policy name…"
        bind:value={newPolicyName}
        onkeydown={(e) => e.key === "Enter" && addPolicy()}
      />
      <button
        type="button"
        class="bg-surface-elevated border border-border-muted/40 rounded-xl text-accent px-4 py-2.5 text-sm font-semibold cursor-pointer whitespace-nowrap hover:bg-border-muted disabled:opacity-50 disabled:cursor-default transition-all duration-200"
        onclick={addPolicy}
        disabled={creating || !newPolicyName.trim()}
      >
        {creating ? "…" : "+ Add"}
      </button>
    </div>
    {#if createError}
      <p class="text-xs text-danger mb-2">{createError}</p>
    {/if}
    {#if loadError}
      <p class="text-xs text-danger mb-2">{loadError}</p>
    {/if}
    <ul class="list-none m-0 p-0 flex-1 min-h-0 overflow-y-auto">
      {#each policies as p}
        <li>
          <button
            class="w-full text-left px-4 py-3 bg-transparent border-none rounded-xl text-text-secondary text-sm cursor-pointer transition-all duration-200 hover:bg-surface-elevated hover:text-text-primary {selected === p ? 'bg-surface-elevated text-accent font-semibold' : ''}"
            onclick={() => selectPolicy(p)}
          >
            {p}
          </button>
        </li>
      {/each}
    </ul>
  </aside>

  <!-- Editor pane -->
  <main class="bg-surface rounded-2xl flex-1 p-7 flex flex-col gap-5 overflow-hidden shadow-sm">
    {#if !selected}
      <p class="text-text-muted text-sm text-center mt-16">Select a policy to edit.</p>
    {:else}
      <div class="flex justify-between items-center">
        <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-2">{selected}</h2>
        <div class="flex items-center gap-4">
          {#if saveMsg}
            <span class="text-sm text-success">{saveMsg}</span>
          {/if}
          {#if dirty}
            <span class="text-xs px-2 py-0.5 rounded-full bg-warning-muted text-warning font-semibold">Unsaved</span>
          {/if}
          <button class="bg-accent text-white border-none rounded-xl px-6 py-3 text-sm font-semibold cursor-pointer disabled:opacity-50 disabled:cursor-default transition-all duration-200 active:scale-[0.98] shadow-sm shadow-accent/20 hover:shadow-md hover:bg-accent-hover" onclick={save} disabled={saving || !!validationError}>
            {saving ? "Saving…" : "Save"}
          </button>
          {#if canDelete}
            <button class="bg-danger-muted text-danger border border-danger/20 rounded-xl px-6 py-3 text-sm font-semibold cursor-pointer hover:bg-danger/20 transition-all duration-200" onclick={deletePolicy}>Delete</button>
          {/if}
        </div>
      </div>

      {#if validationError}
        <div class="bg-danger-muted border border-danger/20 rounded-xl px-5 py-4 text-sm text-danger">{validationError}</div>
      {/if}

      <textarea
        class="flex-1 w-full bg-background border border-border-muted/30 rounded-xl text-text-primary p-6 font-mono text-sm leading-relaxed resize-none outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200 {validationError ? 'border-danger' : ''}"
        bind:value={content}
        spellcheck="false"
      ></textarea>
    {/if}
  </main>
</div>
