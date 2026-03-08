<!--
  Select — accessible dropdown built on the native <select> element.
  Styled to match the Ecto Ledger enterprise design system.
-->
<script lang="ts">
  interface Option {
    value: string;
    label: string;
  }

  interface Props {
    value?: string;
    options: Option[];
    placeholder?: string;
    disabled?: boolean;
    id?: string;
    class?: string;
    onchange?: (value: string) => void;
  }

  let {
    value = $bindable(""),
    options,
    placeholder = "Select…",
    disabled = false,
    id,
    class: cls = "",
    onchange,
  }: Props = $props();

  function handleChange(e: Event) {
    const sel = e.currentTarget as HTMLSelectElement;
    value = sel.value;
    onchange?.(sel.value);
  }
</script>

<select
  {id}
  {disabled}
  class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl h-11 px-5 py-2 text-sm text-text-primary
         focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200 disabled:opacity-50
         disabled:cursor-not-allowed {cls}"
  value={value}
  onchange={handleChange}
>
  {#if placeholder}
    <option value="" disabled selected={!value}>{placeholder}</option>
  {/if}
  {#each options as opt}
    <option value={opt.value} selected={value === opt.value}>{opt.label}</option>
  {/each}
</select>
