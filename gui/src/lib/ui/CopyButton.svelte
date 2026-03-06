<!--
  CopyButton — clipboard copy with visual success feedback.
  Swaps the icon to a checkmark for 2 seconds after copying.
-->
<script lang="ts">
  interface Props {
    text: string;
    class?: string;
    title?: string;
  }

  let { text, class: cls = "", title = "Copy to clipboard" }: Props = $props();

  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch (e) {
      console.error("Clipboard write failed:", e);
    }
  }
</script>

<button
  type="button"
  class="inline-flex items-center gap-1.5 bg-transparent border border-border-muted/50 rounded-lg px-2.5 py-1.5
         text-xs text-text-secondary hover:text-text-primary hover:bg-surface-elevated
         transition-all duration-150 cursor-pointer {cls}"
  onclick={copy}
  {title}
  aria-label={title}
>
  {#if copied}
    <span class="text-success">✓</span>
    <span class="text-success">Copied</span>
  {:else}
    <span>⧉</span>
    <span>Copy</span>
  {/if}
</button>
