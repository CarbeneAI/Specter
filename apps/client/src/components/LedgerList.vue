<script setup lang="ts">
import { Inbox, Loader2 } from 'lucide-vue-next';
import type { InvestigationSummary } from '../types';
import ScorerBadge from './ScorerBadge.vue';

defineProps<{
  investigations: InvestigationSummary[];
  isLoading: boolean;
  error: string | null;
}>();

const emit = defineEmits<{
  (e: 'select', id: string): void;
}>();

const formattedTime = (iso: string) => {
  const date = new Date(iso);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
};

const statusClass = (status: InvestigationSummary['status']) => ({
  'text-accent-green': status === 'completed',
  'text-severity-critical': status === 'error',
  'text-accent-blue': status === 'running',
});
</script>

<template>
  <div class="h-full flex flex-col overflow-hidden">
    <!-- Loading (initial load only) -->
    <div
      v-if="isLoading && investigations.length === 0"
      class="flex-1 flex items-center justify-center text-text-tertiary text-sm"
    >
      <Loader2 class="w-5 h-5 animate-spin mr-2" />
      Loading investigations...
    </div>

    <!-- Error (no data to show) -->
    <div
      v-else-if="error && investigations.length === 0"
      class="flex-1 flex items-center justify-center text-severity-critical text-sm px-4 text-center"
    >
      {{ error }}
    </div>

    <!-- Empty state -->
    <div
      v-else-if="investigations.length === 0"
      class="flex-1 flex flex-col items-center justify-center text-text-tertiary"
    >
      <Inbox class="w-10 h-10 mb-2 opacity-50" />
      <p class="text-sm">No investigations yet.</p>
      <p class="text-xs mt-1">Ask the AI analyst about an alert to create one.</p>
    </div>

    <!-- Table -->
    <div v-else class="flex-1 overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-bg-primary border-b border-border-primary text-xs text-text-tertiary uppercase tracking-wide">
          <tr>
            <th class="text-left px-4 py-2 font-medium">Time</th>
            <th class="text-left px-4 py-2 font-medium">Alert</th>
            <th class="text-left px-4 py-2 font-medium">Verdict</th>
            <th class="text-left px-4 py-2 font-medium">Status</th>
            <th class="text-left px-4 py-2 font-medium">Model</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="inv in investigations"
            :key="inv.id"
            class="border-b border-border-primary hover:bg-bg-tertiary/30 cursor-pointer transition-colors"
            @click="emit('select', inv.id)"
          >
            <td class="px-4 py-2 text-text-tertiary whitespace-nowrap">{{ formattedTime(inv.createdAt) }}</td>
            <td class="px-4 py-2 text-text-primary max-w-xs truncate" :title="inv.alertSummary || undefined">
              {{ inv.alertSummary || '—' }}
            </td>
            <td class="px-4 py-2">
              <ScorerBadge v-if="inv.verdict" :verdict="inv.verdict" />
              <span v-else class="text-text-tertiary text-xs">—</span>
            </td>
            <td class="px-4 py-2 capitalize" :class="statusClass(inv.status)">{{ inv.status }}</td>
            <td class="px-4 py-2 text-text-tertiary font-mono text-xs">{{ inv.model }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
