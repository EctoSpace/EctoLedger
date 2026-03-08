<!--
  StatusDot — animated status indicator.
  Usage:
    <StatusDot status="running" />
    <StatusDot status="passed" label="Session passed" />
-->
<script lang="ts">
  import { cn } from "../utils";

  type Status = "running" | "passed" | "failed" | "idle" | "pending";

  interface Props {
    status: Status;
    label?: string;
    class?: string;
  }

  let {
    status,
    label,
    class: className = "",
  }: Props = $props();

  const colors: Record<Status, string> = {
    running: "bg-accent",
    passed:  "bg-success",
    failed:  "bg-danger",
    idle:    "bg-text-muted",
    pending: "bg-warning",
  };

  const pulseStates = new Set<Status>(["running", "pending"]);
</script>

<span class={cn("inline-flex items-center gap-1.5", className)} title={label}>
  <span class={cn(
    "relative h-2 w-2 rounded-full",
    colors[status],
  )}>
    {#if pulseStates.has(status)}
      <span class={cn(
        "absolute inset-0 rounded-full animate-ping opacity-75",
        colors[status],
      )}></span>
    {/if}
  </span>
  {#if label}
    <span class="text-xs text-text-secondary">{label}</span>
  {/if}
</span>
