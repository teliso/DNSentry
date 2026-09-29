<script lang="ts">
  import { onMount } from 'svelte';

  /** In-page navigation for long settings pages; highlights the section in view. */
  let { sections }: { sections: { id: string; label: string }[] } = $props();

  let active = $state('');

  onMount(() => {
    active = sections[0]?.id ?? '';
    const visible = new Map<string, number>();
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) visible.set(entry.target.id, entry.isIntersecting ? entry.intersectionRatio : 0);
        const first = sections.find((section) => (visible.get(section.id) ?? 0) > 0);
        if (first) active = first.id;
      },
      { rootMargin: '-120px 0px -45% 0px', threshold: [0, 0.01] }
    );
    for (const section of sections) {
      const element = document.getElementById(section.id);
      if (element) observer.observe(element);
    }
    return () => observer.disconnect();
  });

  function jump(event: MouseEvent, id: string) {
    event.preventDefault();
    active = id;
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
</script>

<nav class="sections" aria-label="页面分区">
  {#each sections as section (section.id)}
    <a href="#{section.id}" class:active={active === section.id} onclick={(event) => jump(event, section.id)}>{section.label}</a>
  {/each}
</nav>

<style>
  .sections {
    position: sticky; top: var(--topbar-height); z-index: 20;
    display: flex; gap: 4px; overflow-x: auto; scrollbar-width: none;
    margin: -8px -8px 0; padding: 8px;
    background: var(--bg);
  }
  .sections::-webkit-scrollbar { display: none; }
  a {
    flex: none; padding: 5px 12px; border-radius: 999px;
    color: var(--ink-2); font-size: 13px; font-weight: 500; text-decoration: none;
    border: 1px solid var(--line); background: var(--surface);
  }
  a:hover { border-color: var(--line-strong); color: var(--ink); }
  a.active { background: var(--accent-soft); border-color: transparent; color: var(--accent); }
</style>
