<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { ShieldOff, Layers, List } from 'lucide-vue-next';
import AlertRow from './AlertRow.vue';
import AlertGroupRow from './AlertGroupRow.vue';
import FilterPanel from './FilterPanel.vue';
import { groupAlerts } from '../composables/useAlertGroups';
import type { WazuhAlert, SeverityLevel } from '../types';

const props = defineProps<{
  alerts: WazuhAlert[];
  selectedAlert: WazuhAlert | null;
  severityFilter: SeverityLevel | null;
}>();

const emit = defineEmits<{
  (e: 'select', alert: WazuhAlert): void;
  (e: 'filter', severities: SeverityLevel[], agents: string[], groups: string[]): void;
  (e: 'mute', ruleId: string, srcip: string, reason: string, description: string, ttlDays: number): void;
  (e: 'dismiss', alert: WazuhAlert): void;
}>();

// Grouping is ON by default: the feed is dominated by a handful of repeating
// signatures, and an ungrouped list buries the alerts that matter. The toggle
// below drops back to the flat stream when you want every row.
const grouped = ref(true);

// Extract filter options from alerts
const agents = computed(() => {
  const agentSet = new Set<string>();
  props.alerts.forEach(a => {
    if (a.agent?.name) agentSet.add(a.agent.name);
  });
  return Array.from(agentSet).sort();
});

const ruleGroups = computed(() => {
  const groupSet = new Set<string>();
  props.alerts.forEach(a => {
    a.rule.groups?.forEach(g => groupSet.add(g));
  });
  return Array.from(groupSet).sort();
});

// Filter state
const activeSeverities = ref<SeverityLevel[]>([]);
const activeAgents = ref<string[]>([]);
const activeGroups = ref<string[]>([]);

// Sync severity filter from stats bar badges
watch(() => props.severityFilter, (newFilter) => {
  if (newFilter === null) {
    activeSeverities.value = [];
  } else {
    activeSeverities.value = [newFilter];
  }
});

// Filtered alerts
const filteredAlerts = computed(() => {
  let filtered = props.alerts;

  if (activeSeverities.value.length > 0) {
    filtered = filtered.filter(a => {
      const level = a.rule.level;
      if (level >= 12) return activeSeverities.value.includes('critical');
      if (level >= 7) return activeSeverities.value.includes('high');
      if (level >= 3) return activeSeverities.value.includes('medium');
      return activeSeverities.value.includes('low');
    });
  }

  if (activeAgents.value.length > 0) {
    filtered = filtered.filter(a => activeAgents.value.includes(a.agent?.name));
  }

  if (activeGroups.value.length > 0) {
    filtered = filtered.filter(a =>
      a.rule.groups?.some(g => activeGroups.value.includes(g))
    );
  }

  return filtered;
});

// Collapsed rule+srcip groups, newest group first.
const alertGroups = computed(() => groupAlerts(filteredAlerts.value));

// How much the grouping actually collapsed, shown in the toggle bar.
const collapseLabel = computed(() => {
  const alertCount = filteredAlerts.value.length;
  const groupCount = alertGroups.value.length;
  if (!grouped.value || alertCount === groupCount) return `${alertCount} alerts`;
  return `${groupCount} groups · ${alertCount} alerts`;
});

const handleFilter = (severities: SeverityLevel[], agents: string[], groups: string[]) => {
  activeSeverities.value = severities;
  activeAgents.value = agents;
  activeGroups.value = groups;
  emit('filter', severities, agents, groups);
};

const handleClearFilters = () => {
  activeSeverities.value = [];
  activeAgents.value = [];
  activeGroups.value = [];
};
</script>

<template>
  <div class="h-full flex flex-col bg-bg-secondary">
    <!-- Filter panel -->
    <FilterPanel
      :agents="agents"
      :rule-groups="ruleGroups"
      :severity-filter="severityFilter"
      @filter="handleFilter"
      @clear="handleClearFilters"
    />

    <!-- Grouping toggle -->
    <div class="flex items-center justify-between px-4 py-1.5 border-b border-border-primary bg-bg-secondary flex-shrink-0">
      <span class="text-xs text-text-tertiary">{{ collapseLabel }}</span>
      <button
        class="flex items-center gap-1.5 px-2 py-1 text-xs rounded-full transition-colors"
        :class="grouped
          ? 'bg-accent-blue/20 text-accent-blue'
          : 'text-text-tertiary hover:text-text-primary hover:bg-bg-tertiary'"
        :title="grouped
          ? 'Grouped by rule + source. Click for the flat stream.'
          : 'Showing every alert. Click to group by rule + source.'"
        @click="grouped = !grouped"
      >
        <Layers v-if="grouped" class="w-3.5 h-3.5" />
        <List v-else class="w-3.5 h-3.5" />
        {{ grouped ? 'Grouped' : 'Flat' }}
      </button>
    </div>

    <!-- Alert list -->
    <div class="flex-1 overflow-y-auto">
      <template v-if="filteredAlerts.length > 0">
        <!-- Grouped view (default) -->
        <template v-if="grouped">
          <AlertGroupRow
            v-for="group in alertGroups"
            :key="group.key"
            :group="group"
            :selected-alert="selectedAlert"
            @select="emit('select', $event)"
            @mute="(ruleId: string, srcip: string, reason: string, description: string, ttlDays: number) => emit('mute', ruleId, srcip, reason, description, ttlDays)"
            @dismiss="emit('dismiss', $event)"
          />
        </template>

        <!-- Flat view -->
        <template v-else>
          <AlertRow
            v-for="alert in filteredAlerts"
            :key="alert.id ?? alert.timestamp"
            :alert="alert"
            :is-selected="selectedAlert?.id === alert.id"
            @select="emit('select', $event)"
            @mute="(ruleId: string, srcip: string, reason: string, description: string, ttlDays: number) => emit('mute', ruleId, srcip, reason, description, ttlDays)"
            @dismiss="emit('dismiss', $event)"
          />
        </template>
      </template>
      <div v-else class="flex flex-col items-center justify-center h-full text-text-tertiary">
        <ShieldOff class="w-12 h-12 mb-3 opacity-50" />
        <p class="text-sm">No alerts to display</p>
        <p class="text-xs mt-1">Waiting for security events...</p>
      </div>
    </div>
  </div>
</template>
