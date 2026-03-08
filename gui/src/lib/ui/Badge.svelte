<!--
  Enterprise Badge component for status indicators.
  Usage:
    <Badge variant="success">Passed</Badge>
    <Badge variant="danger" dot>Failed</Badge>
-->
<script lang="ts">
  import { cn } from "../utils";
  import type { Snippet } from "svelte";

  type Variant = "default" | "success" | "warning" | "danger" | "info" | "accent";

  interface Props {
    variant?: Variant;
    dot?: boolean;
    class?: string;
    children: Snippet;
  }

  let {
    variant = "default",
    dot = false,
    class: className = "",
    children,
  }: Props = $props();

  const variants: Record<Variant, string> = {
    default: "bg-surface-elevated text-text-secondary border-border",
    success: "bg-success-muted text-success border-success/30",
    warning: "bg-warning-muted text-warning border-warning/30",
    danger:  "bg-danger-muted text-danger border-danger/30",
    info:    "bg-info-muted text-info border-info/30",
    accent:  "bg-accent-muted text-accent-text border-accent/30",
  };

  const dotColors: Record<Variant, string> = {
    default: "bg-text-muted",
    success: "bg-success",
    warning: "bg-warning",
    danger:  "bg-danger",
    info:    "bg-info",
    accent:  "bg-accent",
  };
</script>

<span class={cn(
  "inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-medium",
  variants[variant],
  className
)}>
  {#if dot}
    <span class={cn("h-2 w-2 rounded-full", dotColors[variant])}></span>
  {/if}
  {@render children()}
</span>
