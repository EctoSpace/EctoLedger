<!--
  Enterprise Card component — surface container with optional header.
  Usage:
    <Card title="Sessions" class="col-span-2">
      ...content...
    </Card>
-->
<script lang="ts">
  import { cn } from "../utils";
  import type { Snippet } from "svelte";

  interface Props {
    title?: string;
    subtitle?: string;
    class?: string;
    headerClass?: string;
    children: Snippet;
    actions?: Snippet;
  }

  let {
    title,
    subtitle,
    class: className = "",
    headerClass = "",
    children,
    actions,
  }: Props = $props();
</script>

<div class={cn(
  "rounded-2xl bg-surface shadow-sm animate-fade-in",
  className
)}>
  {#if title || actions}
    <div class={cn("flex items-center justify-between border-b border-border-muted/10 px-7 py-5", headerClass)}>
      <div>
        {#if title}
          <h3 class="text-base font-semibold text-text-primary leading-snug tracking-tight">{title}</h3>
        {/if}
        {#if subtitle}
          <p class="text-xs text-text-muted mt-1.5">{subtitle}</p>
        {/if}
      </div>
      {#if actions}
        <div class="flex items-center gap-3">
          {@render actions()}
        </div>
      {/if}
    </div>
  {/if}
  <div class="p-7">
    {@render children()}
  </div>
</div>
