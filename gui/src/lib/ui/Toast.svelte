<!--
  Toast — ephemeral notification component.
  Usage: bind a `messages: ToastMessage[]` array; push to show, auto-removes after timeout.
-->
<script lang="ts" module>
  export interface ToastMessage {
    id: string;
    message: string;
    variant: "success" | "danger" | "warning" | "info";
    duration?: number;
  }
</script>

<script lang="ts">
  interface Props {
    messages?: ToastMessage[];
  }

  let { messages = $bindable([]) }: Props = $props();

  function dismiss(id: string) {
    messages = messages.filter((m) => m.id !== id);
  }

  function scheduleRemoval(node: HTMLElement, { id, duration }: { id: string; duration: number }) {
    const timer = setTimeout(() => dismiss(id), duration);
    return { destroy() { clearTimeout(timer); } };
  }

  const variantClass: Record<ToastMessage["variant"], string> = {
    success: "bg-success/10 border-success/40 text-success",
    danger: "bg-danger/10 border-danger/40 text-danger",
    warning: "bg-warning/10 border-warning/40 text-warning",
    info: "bg-info/10 border-info/40 text-info",
  };

  const icon: Record<ToastMessage["variant"], string> = {
    success: "✓",
    danger: "✕",
    warning: "⚠",
    info: "ℹ",
  };
</script>

{#if messages.length > 0}
  <div class="fixed bottom-8 right-8 flex flex-col gap-3 z-50" role="region" aria-label="Notifications">
    {#each messages as msg (msg.id)}
      <div
        use:scheduleRemoval={{ id: msg.id, duration: msg.duration ?? 4000 }}
        class="flex items-start gap-3.5 rounded-2xl border px-6 py-5 text-sm shadow-xl
               backdrop-blur-md min-w-[320px] max-w-sm animate-fade-in {variantClass[msg.variant]}"
        role="alert"
      >
        <span class="text-base font-bold">{icon[msg.variant]}</span>
        <span class="flex-1 leading-snug">{msg.message}</span>
        <button
          class="bg-transparent border-none p-0 cursor-pointer text-inherit opacity-60 hover:opacity-100"
          onclick={() => dismiss(msg.id)}
          aria-label="Dismiss"
        >✕</button>
      </div>
    {/each}
  </div>
{/if}
