<script setup lang="ts">
/**
 * MutedPanel - the "N muted" strip above the feed.
 *
 * A mute you can't see is a mute you forget you set, which is how a SIEM goes
 * quiet without anyone deciding it should. This strip is always visible while
 * any mute is active, states exactly how many alerts are currently hidden, and
 * expands to a list where every mute can be lifted in one click.
 */
import { ref, computed } from 'vue';
import { BellOff, ChevronDown, ChevronRight, Undo2 } from 'lucide-vue-next';
import type { Mute } from '../types';
import { SRCIP_ANY } from '../types';

const props = defineProps<{
  mutes: Mute[];
  /** How many alerts currently in the feed are hidden by these mutes. */
  mutedCount: number;
}>();

const emit = defineEmits<{
  (e: 'unmute', ruleId: string, srcip: string): void;
}>();

const expanded = ref(false);

const hasMutes = computed(() => props.mutes.length > 0);

const summary = computed(() => {
  const n = props.mutes.length;
  const ruleWord = n === 1 ? 'mute' : 'mutes';
  if (props.mutedCount === 0) return `${n} ${ruleWord} active`;
  return `${props.mutedCount} alerts hidden by ${n} ${ruleWord}`;
});

const scopeLabel = (mute: Mute) => {
  if (mute.srcip === SRCIP_ANY) return 'any source';
  return mute.srcip || 'no source IP';
};

const expiryLabel = (mute: Mute) => {
  if (!mute.expiresAt) return 'never expires';
  const ms = new Date(mute.expiresAt).getTime() - Date.now();
  if (ms <= 0) return 'expired';
  const days = Math.ceil(ms / (24 * 60 * 60 * 1000));
  return days === 1 ? 'expires tomorrow' : `expires in ${days} days`;
};
</script>

<template>
  <div v-if="hasMutes" class="border-b border-amber-800/30 bg-amber-950/20 flex-shrink-0">
    <!-- Summary strip -->
    <button
      class="w-full flex items-center gap-2 px-4 py-1.5 text-xs text-amber-300/90 hover:bg-amber-900/20 transition-colors"
      @click="expanded = !expanded"
    >
      <BellOff class="w-3.5 h-3.5 flex-shrink-0" />
      <span>{{ summary }}</span>
      <span class="text-amber-400/50">— still reaching Wazuh, just not shown here</span>
      <ChevronDown v-if="expanded" class="w-3.5 h-3.5 ml-auto flex-shrink-0" />
      <ChevronRight v-else class="w-3.5 h-3.5 ml-auto flex-shrink-0" />
    </button>

    <!-- Expanded mute list -->
    <div v-if="expanded" class="px-4 pb-2 space-y-1">
      <div
        v-for="mute in mutes"
        :key="`${mute.ruleId}::${mute.srcip}`"
        class="flex items-center gap-2 text-xs py-1.5 border-t border-amber-800/20"
      >
        <span class="font-mono text-amber-300 flex-shrink-0">{{ mute.ruleId }}</span>
        <span class="text-text-tertiary flex-shrink-0">from {{ scopeLabel(mute) }}</span>
        <span class="text-text-secondary truncate flex-1 min-w-0">
          {{ mute.description || '(no description)' }}
          <span v-if="mute.reason" class="text-text-tertiary">— {{ mute.reason }}</span>
        </span>
        <span class="text-text-tertiary flex-shrink-0">{{ expiryLabel(mute) }}</span>
        <button
          class="flex items-center gap-1 px-2 py-0.5 rounded bg-bg-tertiary hover:bg-amber-800/40 text-text-secondary hover:text-amber-300 transition-colors flex-shrink-0"
          title="Unmute — these alerts reappear immediately"
          @click="emit('unmute', mute.ruleId, mute.srcip)"
        >
          <Undo2 class="w-3 h-3" />
          Unmute
        </button>
      </div>
    </div>
  </div>
</template>
