<script setup lang="ts">
import { computed } from 'vue';
import type { ScoreVerdict } from '../types';

const props = defineProps<{
  verdict?: ScoreVerdict | null;
}>();

const bandClass = computed(() => {
  if (!props.verdict) return '';
  return `badge-${props.verdict.band}`;
});

// Native title attribute mirrors the tooltip convention already used elsewhere
// in the codebase (AlertRow.vue, ChatPanel.vue, AlertStats.vue) rather than
// inventing a new tooltip component. Browsers render \n as line breaks.
const tooltip = computed(() => {
  if (!props.verdict?.reasons?.length) return undefined;
  return props.verdict.reasons.join('\n');
});
</script>

<template>
  <span
    v-if="verdict"
    class="badge capitalize cursor-help"
    :class="bandClass"
    :title="tooltip"
  >
    {{ verdict.band }} &middot; {{ verdict.score }}
  </span>
</template>
