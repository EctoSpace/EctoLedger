<!--
  DevHub — Developer Hub tab.

  Track 6: Shows SDK integration snippets, API reference, and quick-start
  guides for Python and TypeScript SDKs. Includes interactive "Run Test"
  buttons that spawn shell commands and stream output into the GUI.
-->
<script lang="ts">
  import { isTauri } from "@tauri-apps/api/core";
  import { Command, type Child } from "@tauri-apps/plugin-shell";
  import { onDestroy } from "svelte";
  import { Card, Badge, Button } from "./ui";

  interface Props {
    serverUrl: string;
  }

  let { serverUrl }: Props = $props();

  let activeSDK = $state<"python" | "typescript">("python");
  let _alive = true;
  let _activeChildren: Child[] = [];

  onDestroy(() => {
    _alive = false;
    for (const child of _activeChildren) {
      child.kill().catch(() => {});
    }
    _activeChildren = [];
  });

  // ── Run Test state ────────────────────────────────────────────────────────
  interface TestRun {
    output: string[];
    running: boolean;
    exitCode: number | null;
    error: string;
  }

  const emptyRun = (): TestRun => ({ output: [], running: false, exitCode: null, error: "" });
  let pyTest  = $state<TestRun>(emptyRun());
  let tsTest  = $state<TestRun>(emptyRun());

  /**
   * Run SDK tests via Tauri shell plugin and stream output into the GUI.
   *
   * @param sdk    - which SDK to test
   * @param cmd    - shell executable ("python" | "python3" | "npm")
   * @param args   - argument list passed to the executable
   */
  async function runTests(sdk: "python" | "typescript") {
    if (!isTauri()) return;

    const handle = sdk === "python" ? pyTest : tsTest;
    if (handle.running) return;

    if (sdk === "python") {
      pyTest = { output: [], running: true, exitCode: null, error: "" };
    } else {
      tsTest = { output: [], running: true, exitCode: null, error: "" };
    }

    const appendLine = (line: string, isErr = false) => {
      const prefix = isErr ? "[stderr] " : "";
      if (sdk === "python") {
        pyTest = { ...pyTest, output: [...pyTest.output, prefix + line] };
      } else {
        tsTest = { ...tsTest, output: [...tsTest.output, prefix + line] };
      }
    };

    try {
      // Python command (single line, verbatim per spec):
      // python -m pip install ectoledger_sdk[langchain,autogen] && python -m pytest tests/
      //
      // TypeScript command:
      // npm ci && npx vitest run
      const isWin = navigator.userAgent.includes("Windows");
      const shellExe  = isWin ? "cmd" : "sh";
      const shellFlag = isWin ? "/C"  : "-c";
      const cmdLine = sdk === "python"
        ? "python -m pip install ectoledger_sdk[langchain,autogen] && python -m pytest tests/"
        : "npm ci && npx vitest run";

      // Tauri v2 plugin-shell: register listeners on the Command object,
      // spawn the process, then await the close-event promise.
      const cmd = Command.create(shellExe, [shellFlag, cmdLine]);

      cmd.stdout.on("data", (line: string) => { if (_alive) appendLine(line); });
      cmd.stderr.on("data", (line: string) => { if (_alive) appendLine(line, true); });

      // Build the close-promise BEFORE spawn so the handler is registered.
      const closePromise = new Promise<number>((resolve) => {
        cmd.on("close", (data: { code: number | null }) => resolve(data.code ?? -1));
        cmd.on("error", (msg: string) => {
          if (_alive) appendLine(`[error] ${msg}`, true);
          resolve(-1);
        });
      });

      const child = await cmd.spawn(); // kick off the process
      _activeChildren.push(child);
      const code = await closePromise; // wait for it to finish
      _activeChildren = _activeChildren.filter(c => c !== child);

      if (sdk === "python") {
        pyTest = { ...pyTest, running: false, exitCode: code };
      } else {
        tsTest = { ...tsTest, running: false, exitCode: code };
      }
    } catch (e) {
      const msg = `Shell command failed: ${e}`;
      if (sdk === "python") {
        pyTest = { ...pyTest, running: false, exitCode: -1, error: msg };
      } else {
        tsTest = { ...tsTest, running: false, exitCode: -1, error: msg };
      }
    }
  }

  function exitBadgeVariant(code: number | null): "success" | "danger" | "default" {
    if (code === null) return "default";
    return code === 0 ? "success" : "danger";
  }
  function exitLabel(code: number | null): string {
    if (code === null) return "";
    return code === 0 ? "✓ Passed" : `✗ Exited ${code}`;
  }

  const pythonInstall = `pip install ectoledger-sdk`;
  const pythonQuickstart = $derived(`import asyncio
from ectoledger_sdk import LedgerClient

async def main():
    async with LedgerClient(
        base_url="${serverUrl}",
        bearer_token="your-api-token",
    ) as client:
        # Create a session and append events
        session = await client.create_session(
            goal="Audit the login endpoint for OWASP Top 10"
        )
        await client.append_event(session.session_id, {"step": "read", "file": "config.py"})

        # Verify the hash chain
        ok = await client.verify_chain(session.session_id)
        print(f"Chain intact: {ok}")

        # Get the Verifiable Credential
        vc = await client.get_session_vc(session.session_id)
        print(f"VC issued: {vc}")

        await client.seal_session(session.session_id)

asyncio.run(main())`);

  const tsInstall = `npm install ectoledger-sdk`;
  const tsQuickstart = $derived(`import { EctoLedgerClient } from "ectoledger-sdk";

const client = new EctoLedgerClient({
  baseUrl: "${serverUrl}",
  bearerToken: "your-api-token",
});

// Create a session and append events
const session = await client.createSession({
  goal: "Audit the login endpoint for OWASP Top 10",
});
await client.appendEvent(session.session_id, { step: "read", file: "config.ts" });

// Verify the hash chain
const ok = await client.verifyChain(session.session_id);
console.log(\`Chain intact: \${ok}\`);

// Get the Verifiable Credential
const vc = await client.getSessionVc(session.session_id);
console.log(\`VC issued:\`, vc);

await client.sealSession(session.session_id);`);

  const apiEndpoints = [
    { method: "GET",    path: "/api/sessions",              desc: "List all audit sessions" },
    { method: "POST",   path: "/api/sessions",              desc: "Create a new session" },
    { method: "GET",    path: "/api/events?session_id=:id", desc: "Get events for a session" },
    { method: "GET",    path: "/api/stream",                desc: "SSE event stream" },
    { method: "GET",    path: "/api/sessions/:id/vc",       desc: "Get session Verifiable Credential" },
    { method: "GET",    path: "/api/sessions/:id/vc/verify",desc: "Verify session VC" },
    { method: "GET",    path: "/api/certificates/:id",      desc: "Download audit certificate" },
    { method: "GET",    path: "/api/reports/:id",           desc: "Download audit report" },
    { method: "GET",    path: "/api/policies",              desc: "List audit policies" },
    { method: "GET",    path: "/api/config",                desc: "Get server configuration" },
    { method: "PUT",    path: "/api/config",                desc: "Update configuration" },
    { method: "GET",    path: "/api/tokens",                desc: "List API tokens (admin)" },
    { method: "POST",   path: "/api/tokens",                desc: "Create API token (admin)" },
    { method: "DELETE", path: "/api/tokens/:hash",          desc: "Delete API token (admin)" },
    { method: "GET",    path: "/api/webhooks",              desc: "List webhooks (admin)" },
    { method: "POST",   path: "/api/webhooks",              desc: "Create webhook (admin)" },
    { method: "GET",    path: "/metrics",                   desc: "Prometheus metrics" },
  ];

  const methodColors: Record<string, string> = {
    GET: "accent",
    POST: "success",
    PUT: "warning",
    DELETE: "danger",
  };
</script>

<div class="space-y-8 animate-fade-in">
  <div>
    <h1 class="text-xl font-bold text-text-primary">Developer Hub</h1>
    <p class="text-sm text-text-muted mt-1">SDK integration guides, API reference, and code snippets.</p>
  </div>

  <!-- SDK tabs -->
  <div class="flex gap-2">
    <Button
      variant={activeSDK === "python" ? "primary" : "ghost"}
      size="sm"
      onclick={() => activeSDK = "python"}
    >
      {#snippet children()}Python SDK{/snippet}
    </Button>
    <Button
      variant={activeSDK === "typescript" ? "primary" : "ghost"}
      size="sm"
      onclick={() => activeSDK = "typescript"}
    >
      {#snippet children()}TypeScript SDK{/snippet}
    </Button>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-7">
    <!-- Quick start -->
    <Card title={activeSDK === "python" ? "Python Quick Start" : "TypeScript Quick Start"}>
      {#snippet children()}
        <div class="space-y-4">
          <div>
            <h4 class="text-xs text-text-muted uppercase tracking-wider mb-2">Install</h4>
            <pre class="p-5 rounded-xl bg-surface-elevated border border-border-muted/15 text-sm font-mono text-accent overflow-x-auto">{activeSDK === "python" ? pythonInstall : tsInstall}</pre>
          </div>
          <div>
            <h4 class="text-xs text-text-muted uppercase tracking-wider mb-2">Quick Start</h4>
            <pre class="p-6 rounded-xl bg-surface-elevated border border-border-muted/15 text-xs font-mono text-text-secondary overflow-x-auto max-h-96 overflow-y-auto">{activeSDK === "python" ? pythonQuickstart : tsQuickstart}</pre>
          </div>
        </div>
      {/snippet}
    </Card>

    <!-- API Reference -->
    <Card title="API Reference" subtitle="All available endpoints">
      {#snippet children()}
        <div class="space-y-1 max-h-[500px] overflow-y-auto">
          {#each apiEndpoints as ep}
            <div class="flex items-start gap-3 py-3.5 px-4 rounded-xl hover:bg-surface-elevated transition-all duration-200">
              <Badge variant={methodColors[ep.method] as "accent" | "success" | "warning" | "danger" ?? "default"}>
                {#snippet children()}<span class="font-mono text-[10px] w-10 text-center inline-block">{ep.method}</span>{/snippet}
              </Badge>
              <div class="flex-1 min-w-0">
                <code class="text-xs font-mono text-text-primary">{ep.path}</code>
                <p class="text-xs text-text-muted mt-0.5">{ep.desc}</p>
              </div>
            </div>
          {/each}
        </div>
      {/snippet}
    </Card>
  </div>

  <!-- Connection info -->
  <Card title="Connection Details">
    {#snippet children()}
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div class="p-5 rounded-xl bg-surface-elevated border border-border-muted/15">
          <div class="text-xs text-text-muted uppercase tracking-wider mb-1">Server URL</div>
          <code class="text-sm text-accent font-mono">{serverUrl}</code>
        </div>
        <div class="p-5 rounded-xl bg-surface-elevated border border-border-muted/15">
          <div class="text-xs text-text-muted uppercase tracking-wider mb-1">Database</div>
          <span class="text-sm text-text-primary">SQLite (embedded)</span>
        </div>
        <div class="p-5 rounded-xl bg-surface-elevated border border-border-muted/15">
          <div class="text-xs text-text-muted uppercase tracking-wider mb-1">Authentication</div>
          <span class="text-sm text-text-primary">Bearer Token (RBAC)</span>
        </div>
      </div>
    {/snippet}
  </Card>

  <!-- Integration Tests -->
  <Card title="Integration Tests" subtitle="Run SDK test suites directly from this tab">
    {#snippet children()}
      <div class="space-y-6">

        <!-- Python SDK tests -->
        <div class="space-y-2">
          <div class="flex items-center justify-between gap-4">
            <div class="flex-1 min-w-0">
              <h4 class="text-sm font-semibold text-text-primary">Python SDK</h4>
              <code class="text-xs font-mono text-text-muted break-all">
                python -m pip install ectoledger_sdk[langchain,autogen] &amp;&amp; python -m pytest tests/
              </code>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              {#if pyTest.exitCode !== null}
                <Badge variant={exitBadgeVariant(pyTest.exitCode)}>
                  {#snippet children()}{exitLabel(pyTest.exitCode)}{/snippet}
                </Badge>
              {/if}
              <Button
                variant="primary"
                size="sm"
                disabled={pyTest.running}
                onclick={() => runTests("python")}
              >
                {#snippet children()}{pyTest.running ? "Running…" : "Run Tests"}{/snippet}
              </Button>
            </div>
          </div>
          {#if pyTest.error}
            <p class="text-xs text-danger">{pyTest.error}</p>
          {/if}
          {#if pyTest.output.length > 0}
            <pre class="h-44 overflow-y-auto rounded-xl border border-border-muted/15 bg-background p-5 text-xs font-mono text-text-secondary whitespace-pre-wrap">{pyTest.output.join("\n")}</pre>
          {/if}
        </div>

        <div class="border-t border-border-muted/15"></div>

        <!-- TypeScript SDK tests -->
        <div class="space-y-2">
          <div class="flex items-center justify-between gap-4">
            <div class="flex-1 min-w-0">
              <h4 class="text-sm font-semibold text-text-primary">TypeScript SDK</h4>
              <code class="text-xs font-mono text-text-muted">npm ci &amp;&amp; npx vitest run</code>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              {#if tsTest.exitCode !== null}
                <Badge variant={exitBadgeVariant(tsTest.exitCode)}>
                  {#snippet children()}{exitLabel(tsTest.exitCode)}{/snippet}
                </Badge>
              {/if}
              <Button
                variant="primary"
                size="sm"
                disabled={tsTest.running}
                onclick={() => runTests("typescript")}
              >
                {#snippet children()}{tsTest.running ? "Running…" : "Run Tests"}{/snippet}
              </Button>
            </div>
          </div>
          {#if tsTest.error}
            <p class="text-xs text-danger">{tsTest.error}</p>
          {/if}
          {#if tsTest.output.length > 0}
            <pre class="h-44 overflow-y-auto rounded-xl border border-border-muted/15 bg-background p-5 text-xs font-mono text-text-secondary whitespace-pre-wrap">{tsTest.output.join("\n")}</pre>
          {/if}
        </div>

      </div>
    {/snippet}
  </Card>

</div>
