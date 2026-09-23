<script setup lang="ts">
/**
 * AlertGroupRow - one collapsed rule+srcip group in the feed.
 *
 * Collapsed by default: shows the newest member, a count badge, and the
 * first/last-seen span. Expanding renders every member as a normal AlertRow.
 * A group of one renders as a plain AlertRow with no group chrome, so single
 * alerts don't grow a pointless expander.
 *
 * The Mute button here mutes the whole group -- which is the same rule+srcip
 * key the group is built on, so "mute this group" is exactly what it says.
 */
import { ref, computed } from 'vue';
import { ChevronDown, ChevronRight, Server, Clock, Layers, BellOff } from 'lucide-vue-next';
import AlertRow from './AlertRow.vue';
import ScorerBadge from './ScorerBadge.vue';
import type { AlertGroup, WazuhAlert } from '../types';
import { getSeverityLevel, getSeverityLabel, DEFAULT_MUTE_TTL_DAYS, SRCIP_ANY } from '../types';

const props = defineProps<{
  group: AlertGroup;
  selectedAlert: WazuhAlert | null;
}>();

const emit = defineEmits<{
  (e: 'select', alert: WazuhAlert): void;
  (e: 'mute', ruleId: string, srcip: string, reason: string, description: string, ttlDays: number): void;
  (e: 'dismiss', alert: WazuhAlert): void;
}>();

const expanded = ref(false);
const showMuteConfirm = ref(false);
const muteReason = ref('');
const muteScopeAllSources = ref(false);
const muteTtlDays = ref(DEFAULT_MUTE_TTL_DAYS);

const isSingle = computed(() => props.group.count === 1);
const severity = computed(() => getSeverityLevel(props.group.maxLevel));
const severityLabel = computed(() => getSeverityLabel(props.group.maxLevel));

const formatTime = (iso: string) => {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
};

const formatDate = (iso: string) => {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
};

const spanLabel = computed(() => {
  const first = props.group.firstSeen;
  const last = props.group.lastSeen;
  if (first === last) return `${formatDate(last)} ${formatTime(last)}`;
  return `${formatDate(first)} ${formatTime(first)} → ${formatDate(last)} ${formatTime(last)}`;
});

const sourceLabel = computed(() => props.group.srcip || 'no source IP');

const muteScopeLabel = computed(() =>
  muteScopeAllSources.value
    ? `rule ${props.group.ruleId} from ANY source`
    : `rule ${props.group.ruleId} from ${sourceLabel.value}`
);

const ttlLabel = computed(() =>
  muteTtlDays.value === 0 ? 'until I unmute it' : `for ${muteTtlDays.value} days`
);

const toggleExpanded = () => { expanded.value = !expanded.value; };

const handleMuteClick = (event: Event) => {
  event.stopPropagation();
  showMuteConfirm.value = true;
};

const handleConfirmMute = (event: Event) => {
  event.stopPropagation();
  emit(
    'mute',
    props.group.ruleId,
    muteScopeAllSources.value ? SRCIP_ANY : props.group.srcip,
    muteReason.value,
    props.group.description,
    muteTtlDays.value,
  );
  showMuteConfirm.value = false;
  muteReason.value = '';
  muteScopeAllSources.value = false;
  muteTtlDays.value = DEFAULT_MUTE_TTL_DAYS;
};

const handleCancelMute = (event: Event) => {
  event.stopPropagation();
  showMuteConfirm.value = false;
  muteReason.value = '';
};
</script>

<template>
  <!-- A group of one is just an alert. No expander, no count badge. -->
  <AlertRow
    v-if="isSingle"
    :alert="group.latest"
    :is-selected="selectedAlert?.id === group.latest.id"
    @select="emit('select', $event)"
    @mute="(ruleId: string, srcip: string, reason: string, description: string, ttlDays: number) => emit('mute', ruleId, srcip, reason, description, ttlDays)"
    @dismiss="emit('dismiss', $event)"
  />

  <div v-else>
    <!-- Collapsed group header -->
    <div
      class="group px-4 py-3 border-b border-border-primary hover:bg-bg-tertiary/30 cursor-pointer transition-colors"
      @click="toggleExpanded"
    >
      <div class="flex items-start gap-3">
        <!-- Severity indicator (worst member in the group) -->
        <div
          class="w-1 h-full min-h-[3rem] rounded-full flex-shrink-0"
          :class="{
            'bg-severity-critical': severity === 'critical',
            'bg-severity-high': severity === 'high',
            'bg-severity-medium': severity === 'medium',
            'bg-severity-low': severity === 'low',
          }"
        ></div>

        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1">
            <span class="badge flex-shrink-0" :class="`badge-${severity}`">
              Level {{ group.maxLevel }} - {{ severityLabel }}
            </span>
            <span class="text-xs text-text-tertiary font-mono">{{ group.ruleId }}</span>
            <ScorerBadge :verdict="group.latest.verdict" />
            <!-- Count badge: the reason this row exists -->
            <span
              class="text-xs font-mono bg-accent-blue/20 text-accent-blue px-1.5 py-0.5 rounded flex items-center gap-1"
              :title="`${group.count} alerts collapsed into this group`"
            >
              <Layers class="w-3 h-3" />
              &times;{{ group.count }}
            </span>
          </div>

          <p class="text-sm text-text-primary mb-2 line-clamp-2">
            {{ group.description }}
          </p>

          <div class="flex items-center gap-4 text-xs text-text-tertiary">
            <div class="flex items-center gap-1">
              <Server class="w-3 h-3" />
              <span>{{ sourceLabel }}</span>
            </div>
            <div class="flex items-center gap-1">
              <Clock class="w-3 h-3" />
              <span>{{ spanLabel }}</span>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-1 flex-shrink-0">
          <!-- Mute the whole group -->
          <button
            class="p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity hover:bg-amber-900/40 text-text-tertiary hover:text-amber-400"
            :title="`Mute rule ${group.ruleId} from ${sourceLabel} (hides in Specter only)`"
            @click="handleMuteClick"
          >
            <BellOff class="w-4 h-4" />
          </button>

          <ChevronDown v-if="expanded" class="w-5 h-5 text-text-tertiary" />
          <ChevronRight v-else class="w-5 h-5 text-text-tertiary group-hover:text-text-secondary transition-colors" />
        </div>
      </div>
    </div>

    <!-- Inline mute confirmation -->
    <div
      v-if="showMuteConfirm"
      class="px-4 py-3 bg-amber-950/30 border-b border-amber-800/30"
      @click.stop
    >
      <p class="text-xs text-amber-300 mb-2">
        Mute {{ muteScopeLabel }} {{ ttlLabel }}?
        Hides it in Specter only — the alert still reaches Wazuh and stays searchable.
      </p>
      <div class="flex items-center gap-2 mb-2">
        <label class="flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer">
          <input v-model="muteScopeAllSources" type="checkbox" class="accent-amber-600" />
          Any source, not just {{ sourceLabel }}
        </label>
        <label class="flex items-center gap-1.5 text-xs text-text-secondary ml-3">
          Expires
          <select
            v-model.number="muteTtlDays"
            class="bg-bg-primary border border-border-primary rounded px-1.5 py-1 text-xs text-text-primary focus:outline-none focus:border-amber-600"
          >
            <option :value="7">7 days</option>
            <option :value="30">30 days</option>
            <option :value="90">90 days</option>
            <option :value="0">never</option>
          </select>
        </label>
      </div>
      <div class="flex items-center gap-2">
        <input
          v-model="muteReason"
          type="text"
          placeholder="Reason (e.g. my phone, known good)"
          class="flex-1 text-xs bg-bg-primary border border-border-primary rounded px-2 py-1.5 text-text-primary placeholder-text-tertiary focus:outline-none focus:border-amber-600"
          @keydown.enter="handleConfirmMute"
          @keydown.escape="handleCancelMute"
        />
        <button
          class="text-xs px-3 py-1.5 rounded bg-amber-700 hover:bg-amber-600 text-white transition-colors"
          @click="handleConfirmMute"
        >
          Mute
        </button>
        <button
          class="text-xs px-3 py-1.5 rounded bg-bg-tertiary hover:bg-bg-tertiary/80 text-text-secondary transition-colors"
          @click="handleCancelMute"
        >
          Cancel
        </button>
      </div>
    </div>

    <!-- Expanded members -->
    <div v-if="expanded" class="border-l-2 border-accent-blue/30 ml-4">
      <AlertRow
        v-for="alert in group.alerts"
        :key="alert.id ?? alert.timestamp"
        :alert="alert"
        :is-selected="selectedAlert?.id === alert.id"
        @select="emit('select', $event)"
        @mute="(ruleId: string, srcip: string, reason: string, description: string, ttlDays: number) => emit('mute', ruleId, srcip, reason, description, ttlDays)"
        @dismiss="emit('dismiss', $event)"
      />
    </div>
  </div>
</template>
