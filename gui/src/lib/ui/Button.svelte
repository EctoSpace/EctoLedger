<!--
  Enterprise Button component.
  Usage:
    <Button variant="primary" size="md" on:click={handler}>Label</Button>
-->
<script lang="ts">
  import { cn } from "../utils";
  import type { Snippet } from "svelte";

  type Variant = "primary" | "secondary" | "ghost" | "danger" | "success";
  type Size = "sm" | "md" | "lg" | "icon";

  interface Props {
    variant?: Variant;
    size?: Size;
    disabled?: boolean;
    loading?: boolean;
    class?: string;
    children: Snippet;
    onclick?: (e: MouseEvent) => void;
    type?: "button" | "submit" | "reset";
  }

  let {
    variant = "primary",
    size = "md",
    disabled = false,
    loading = false,
    class: className = "",
    children,
    onclick,
    type = "button",
  }: Props = $props();

  const base =
    "inline-flex items-center justify-center gap-2 font-medium transition-all duration-200 " +
    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent " +
    "disabled:pointer-events-none disabled:opacity-50 cursor-pointer select-none active:scale-[0.98]";

  const variants: Record<Variant, string> = {
    primary:
      "bg-accent text-white hover:bg-accent-hover hover:shadow-md shadow-sm shadow-accent/20",
    secondary:
      "bg-surface-elevated text-text-primary border border-border-muted/40 hover:bg-surface hover:border-text-muted shadow-xs",
    ghost:
      "text-text-secondary hover:bg-surface-elevated hover:text-text-primary",
    danger:
      "bg-danger text-white hover:bg-red-600 hover:shadow-md shadow-sm shadow-danger/20",
    success:
      "bg-success text-white hover:bg-green-600 hover:shadow-md shadow-sm shadow-success/20",
  };

  const sizes: Record<Size, string> = {
    sm: "h-9 px-4 text-xs rounded-xl",
    md: "h-11 px-6 text-sm rounded-xl",
    lg: "h-[52px] px-8 text-base rounded-xl",
    icon: "h-11 w-11 rounded-xl",
  };
</script>

<button
  {type}
  {disabled}
  class={cn(base, variants[variant], sizes[size], className)}
  onclick={onclick}
>
  {#if loading}
    <span class="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full"></span>
  {/if}
  {@render children()}
</button>
