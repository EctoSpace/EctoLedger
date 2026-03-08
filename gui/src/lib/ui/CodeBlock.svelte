<!--
  CodeBlock — scrollable <pre> with line numbers and an integrated CopyButton.
  Suitable for showing SDK snippets, shell commands, or terminal output.
-->
<script lang="ts">
  import CopyButton from "./CopyButton.svelte";

  interface Props {
    code: string;
    language?: string;
    showLineNumbers?: boolean;
    maxHeight?: string;
    class?: string;
  }

  let {
    code,
    language = "",
    showLineNumbers = true,
    maxHeight = "400px",
    class: cls = "",
  }: Props = $props();

  let lines = $derived(code.split("\n"));
</script>

<div class="relative rounded-xl border border-border-muted/40 overflow-hidden shadow-sm {cls}">
  {#if language}
    <div class="flex items-center justify-between px-5 py-2.5 bg-surface-elevated border-b border-border-muted/30">
      <span class="text-[10px] font-mono font-bold uppercase tracking-widest text-text-muted">{language}</span>
      <CopyButton text={code} />
    </div>
  {:else}
    <div class="absolute top-3 right-3 z-10">
      <CopyButton text={code} />
    </div>
  {/if}

  <div class="overflow-auto" style="max-height: {maxHeight}">
    <pre class="m-0 p-5 text-sm text-text-primary bg-background font-mono leading-relaxed"><code>{#if showLineNumbers}{#each lines as line, i}<span class="select-none text-text-muted mr-4 inline-block w-6 text-right text-xs">{i + 1}</span>{line}{"\n"}{/each}{:else}{code}{/if}</code></pre>
  </div>
</div>
