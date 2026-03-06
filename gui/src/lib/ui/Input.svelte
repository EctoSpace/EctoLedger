<!--
  Enterprise Input component.
  Usage:
    <Input bind:value={goal} placeholder="Enter audit goal…" />
-->
<script lang="ts">
  import { cn } from "../utils";

  interface Props {
    value?: string;
    placeholder?: string;
    type?: string;
    disabled?: boolean;
    class?: string;
    id?: string;
    name?: string;
    oninput?: (e: Event) => void;
    onkeydown?: (e: KeyboardEvent) => void;
  }

  let {
    value = $bindable(""),
    placeholder = "",
    type = "text",
    disabled = false,
    class: className = "",
    id,
    name,
    oninput,
    onkeydown,
  }: Props = $props();
</script>

<input
  {type}
  {id}
  {name}
  {disabled}
  {placeholder}
  bind:value
  {oninput}
  {onkeydown}
  class={cn(
    "flex h-11 w-full rounded-xl border border-border-muted/40 bg-surface-elevated/40 px-5 py-2",
    "text-sm text-text-primary placeholder:text-text-muted",
    "focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent focus:shadow-sm focus:shadow-accent/10",
    "disabled:opacity-50 disabled:cursor-not-allowed",
    "transition-all duration-200",
    className
  )}
/>
