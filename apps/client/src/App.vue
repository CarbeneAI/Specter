<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { LayoutDashboard, History } from 'lucide-vue-next';
import AlertStats from './components/AlertStats.vue';
import AlertFeed from './components/AlertFeed.vue';
import MutedPanel from './components/MutedPanel.vue';
import ChatPanel from './components/ChatPanel.vue';
import ToastContainer from './components/Toast.vue';
import LedgerView from './components/LedgerView.vue';
import { useWebSocket } from './composables/useWebSocket';
import { usePAIChat } from './composables/usePAIChat';
import { useToast } from './composables/useToast';
import type { WazuhAlert, AlertStats as AlertStatsType, SeverityLevel, QuickPrompts, AIProvider, Mute } from './types';
import { isMutedClient } from './composables/useMutes';

// View toggle (Live Dashboard <-> Ledger). Purely additive: the WebSocket
// connection and chat composable below are set up unconditionally regardless
// of which view is active, and the Live Dashboard markup is hidden with
// v-show (not v-if) so it never unmounts/reconnects when toggling away and back.
type DashboardView = 'live' | 'ledger';
const currentView = ref<DashboardView>('live');

// WebSocket connection for alerts
const { alerts, isConnected, requestFilter } = useWebSocket();

// Toast notifications
const toast = useToast();

// API URL for suppress calls
function getApiUrl(): string {
  if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    return 'http://localhost:4001';
  }
  // Served from a non-localhost origin with no VITE_API_URL set: assume the API
  // is reachable on the same host, port 4001. Set VITE_API_URL at build time to
  // point at a different origin (e.g. behind a reverse proxy).
  return `${window.location.protocol}//${window.location.hostname}:4001`;
}
const API_URL = getApiUrl();

// Suppressed rule IDs - fetched on mount, updated after each suppress
const suppressedWazuhIds = ref<Set<string>>(new Set());
const suppressedSuricataIds = ref<Set<string>>(new Set());

// Active mutes (Specter-side only — the alert still reaches Wazuh, we just
// don't render it). Fetched on mount and polled alongside the suppressed list.
const mutes = ref<Mute[]>([]);

async function fetchMutes() {
  try {
    const response = await fetch(`${API_URL}/alerts/mutes`, {
      credentials: 'include',
    });
    const data = await response.json();
    if (Array.isArray(data.mutes)) {
      mutes.value = data.mutes as Mute[];
    }
  } catch {
    // Silently fail - alerts just won't be muted
  }
}

// Fetch suppressed rules from server
async function fetchSuppressedRules() {
  try {
    const response = await fetch(`${API_URL}/alerts/suppressed`, {
      credentials: 'include',
    });
    const data = await response.json();
    if (data.sids) {
      const wazuh = new Set<string>();
      const suricata = new Set<string>();
      for (const entry of data.sids) {
        if (entry.type === 'suricata') {
          suricata.add(entry.id);
        } else {
          wazuh.add(entry.id);
        }
      }
      suppressedWazuhIds.value = wazuh;
      suppressedSuricataIds.value = suricata;
    }
  } catch {
    // Silently fail - alerts just won't be filtered
  }
}

// Refresh suppressed rules every 15 seconds so server-side suppressions appear without reload
let suppressionPollTimer: ReturnType<typeof setInterval> | undefined;

onMounted(() => {
  fetchSuppressedRules();
  fetchMutes();
  suppressionPollTimer = setInterval(() => {
    fetchSuppressedRules();
    fetchMutes();
  }, 15000);
});

onUnmounted(() => {
  if (suppressionPollTimer) clearInterval(suppressionPollTimer);
});

// Dismissed individual alert IDs (client-side only, resets on refresh)
const dismissedAlertIds = ref<Set<number>>(new Set());

// Filter out suppressed, muted, and dismissed alerts
const visibleAlerts = computed(() => {
  return alerts.value.filter(a => {
    // Check individually dismissed
    if (a.id !== undefined && dismissedAlertIds.value.has(a.id)) return false;
    // Check Wazuh rule ID suppression
    if (suppressedWazuhIds.value.has(a.rule.id)) return false;
    // Check Suricata SID suppression
    const sid = a.data?.alert?.signature_id;
    if (sid && suppressedSuricataIds.value.has(String(sid))) return false;
    // Check Specter-side mute (rule + srcip)
    if (isMutedClient(a, mutes.value)) return false;
    return true;
  });
});

// Count of alerts hidden by suppression rules (not including dismissed)
const suppressedCount = computed(() => {
  let count = 0;
  for (const a of alerts.value) {
    if (a.id !== undefined && dismissedAlertIds.value.has(a.id)) continue;
    if (suppressedWazuhIds.value.has(a.rule.id)) { count++; continue; }
    const sid = a.data?.alert?.signature_id;
    if (sid && suppressedSuricataIds.value.has(String(sid))) { count++; }
  }
  return count;
});

// Count of alerts hidden by a Specter-side mute. Counted separately from
// suppression because the two mean different things: a muted alert is still in
// Wazuh, a suppressed one was never written.
const mutedCount = computed(() => {
  if (mutes.value.length === 0) return 0;
  let count = 0;
  for (const a of alerts.value) {
    if (a.id !== undefined && dismissedAlertIds.value.has(a.id)) continue;
    if (suppressedWazuhIds.value.has(a.rule.id)) continue;
    const sid = a.data?.alert?.signature_id;
    if (sid && suppressedSuricataIds.value.has(String(sid))) continue;
    if (isMutedClient(a, mutes.value)) count++;
  }
  return count;
});

// Count of individually dismissed alerts
const dismissedCount = computed(() => dismissedAlertIds.value.size);

// Recompute stats from visible alerts so counts match the filtered feed
const visibleStats = computed<AlertStatsType>(() => {
  const s: AlertStatsType = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of visibleAlerts.value) {
    s.total++;
    const level = a.rule.level;
    if (level >= 12) s.critical++;
    else if (level >= 7) s.high++;
    else if (level >= 3) s.medium++;
    else s.low++;
  }
  return s;
});

// PAI chat
const {
  messages,
  isLoading,
  error,
  quickPrompts,
  sendMessage,
  quickAction,
  clearChat,
  provider,
  providerConfig,
  setProvider,
  setOllamaConfig,
  loadOllamaModels,
} = usePAIChat();

// Handle provider change
const handleSetProvider = (p: AIProvider) => {
  setProvider(p);
};

// Handle Ollama config change
const handleSetOllamaConfig = (url: string, model: string) => {
  setOllamaConfig(url, model);
  loadOllamaModels();
};

// Selected alert for context
const selectedAlert = ref<WazuhAlert | null>(null);

// Severity filter from stats bar (single-select toggle)
const activeSeverityFilter = ref<SeverityLevel | null>(null);

// Resizable panel - left panel width percentage (30-80%)
const leftPanelPercent = ref(60);
const isResizing = ref(false);

const leftPanelStyle = computed(() => ({ width: `${leftPanelPercent.value}%` }));
const rightPanelStyle = computed(() => ({ width: `${100 - leftPanelPercent.value}%` }));

const startResize = (e: MouseEvent) => {
  isResizing.value = true;
  const container = (e.target as HTMLElement).parentElement!;

  const onMouseMove = (moveEvent: MouseEvent) => {
    const rect = container.getBoundingClientRect();
    const percent = ((moveEvent.clientX - rect.left) / rect.width) * 100;
    leftPanelPercent.value = Math.min(80, Math.max(30, percent));
  };

  const onMouseUp = () => {
    isResizing.value = false;
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  };

  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mouseup', onMouseUp);
};

// Computed selected alerts array (for chat context)
const selectedAlerts = computed(() =>
  selectedAlert.value ? [selectedAlert.value] : []
);

// Handle alert selection
const handleSelectAlert = (alert: WazuhAlert) => {
  selectedAlert.value = alert;
};

// Handle severity toggle from stats bar badges
const handleToggleSeverity = (severity: SeverityLevel) => {
  if (activeSeverityFilter.value === severity) {
    // Same badge clicked again — clear filter
    activeSeverityFilter.value = null;
  } else {
    activeSeverityFilter.value = severity;
  }
};

// Handle filter change from filter panel
const handleFilter = (severities: SeverityLevel[], agents: string[], groups: string[]) => {
  // Sync: if filter panel changes severity, clear the stats bar toggle
  if (severities.length !== 1 || severities[0] !== activeSeverityFilter.value) {
    activeSeverityFilter.value = severities.length === 1 ? severities[0] : null;
  }
  requestFilter(severities, agents, groups);
};

// Handle chat send
const handleSendMessage = (message: string) => {
  sendMessage(message, selectedAlerts.value);
};

// Handle quick action
const handleQuickAction = (action: keyof QuickPrompts) => {
  quickAction(action, selectedAlerts.value);
};

// Handle individual alert dismissal
const handleDismiss = (alert: WazuhAlert) => {
  if (alert.id !== undefined) {
    dismissedAlertIds.value = new Set([...dismissedAlertIds.value, alert.id]);
    // Clear selection if dismissed alert was selected
    if (selectedAlert.value?.id === alert.id) {
      selectedAlert.value = null;
    }
  }
};

// Handle a mute: hide this rule+srcip in Specter only. The alert keeps flowing
// into Wazuh, keeps being scored, and stays searchable — this is deliberately
// NOT the upstream suppress path, which disables the signature at the sensor.
const handleMute = async (
  ruleId: string,
  srcip: string,
  reason: string,
  description: string,
  ttlDays: number,
) => {
  const scope = srcip === '*' ? 'any source' : (srcip || 'no source IP');
  const ttlLabel = ttlDays === 0 ? 'indefinitely' : `for ${ttlDays} days`;

  // Optimistically hide immediately. Uses a synthetic id/createdAt; the next
  // poll replaces this with the server's authoritative row.
  const optimistic: Mute = {
    id: -1,
    ruleId,
    srcip,
    description,
    reason,
    createdAt: new Date().toISOString(),
    expiresAt: ttlDays === 0
      ? null
      : new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000).toISOString(),
    createdBy: 'you',
  };
  const previous = mutes.value;
  mutes.value = [...previous, optimistic];
  toast.success(`Muted rule ${ruleId} from ${scope} ${ttlLabel}`);

  try {
    const response = await fetch(`${API_URL}/alerts/mutes`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ruleId, srcip, reason, description, ttlDays }),
    });
    const data = await response.json();
    if (!data.success) {
      mutes.value = previous; // roll back
      toast.error(data.error || 'Failed to mute');
      return;
    }
    fetchMutes();
  } catch {
    mutes.value = previous; // roll back
    toast.error('Failed to connect to server');
  }
};

// Handle an unmute: alerts for this rule+srcip resurface immediately.
const handleUnmute = async (ruleId: string, srcip: string) => {
  const previous = mutes.value;
  mutes.value = previous.filter((m: Mute) => !(m.ruleId === ruleId && m.srcip === srcip));

  try {
    const response = await fetch(`${API_URL}/alerts/mutes`, {
      method: 'DELETE',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ruleId, srcip }),
    });
    const data = await response.json();
    if (!data.success) {
      mutes.value = previous; // roll back
      toast.error(data.error || 'Failed to unmute');
      return;
    }
    toast.success(`Unmuted rule ${ruleId}`);
    fetchMutes();
  } catch {
    mutes.value = previous; // roll back
    toast.error('Failed to connect to server');
  }
};

// NOTE: upstream suppression (POST /alerts/suppress) is intentionally NOT wired
// to any button. That path SSHes into the Suricata sensor and the Wazuh manager
// to disable the signature at the source, which deletes the alert from Wazuh
// entirely. With no SSH grant configured it fails with
// "SURICATA_SSH_HOST environment variable not configured".
// Every quieting action in the UI is a MUTE (handleMute above): the alert still
// ingests, still scores, still reaches Wazuh, and is reversible in one click.
// The server endpoint remains available for an operator who deliberately
// configures SURICATA_SSH_HOST / WAZUH_SSH_HOST and calls it directly.

</script>

<template>
  <div class="h-screen flex flex-col bg-bg-primary">
    <!-- View toggle: Live Dashboard <-> Ledger -->
    <div class="flex items-center gap-1 px-4 py-1.5 border-b border-border-primary bg-bg-secondary flex-shrink-0">
      <button
        class="flex items-center gap-1.5 px-3 py-1 text-xs rounded-full transition-colors"
        :class="currentView === 'live'
          ? 'bg-accent-blue/20 text-accent-blue'
          : 'text-text-tertiary hover:text-text-primary hover:bg-bg-tertiary'"
        @click="currentView = 'live'"
      >
        <LayoutDashboard class="w-3.5 h-3.5" />
        Live Dashboard
      </button>
      <button
        class="flex items-center gap-1.5 px-3 py-1 text-xs rounded-full transition-colors"
        :class="currentView === 'ledger'
          ? 'bg-accent-blue/20 text-accent-blue'
          : 'text-text-tertiary hover:text-text-primary hover:bg-bg-tertiary'"
        @click="currentView = 'ledger'"
      >
        <History class="w-3.5 h-3.5" />
        Ledger
      </button>
    </div>

    <!-- Live Dashboard view -->
    <div v-show="currentView === 'live'" class="contents">
    <!-- Top stats bar -->
    <AlertStats
      :stats="visibleStats"
      :is-connected="isConnected"
      :active-severity="activeSeverityFilter"
      :suppressed-count="suppressedCount"
      :dismissed-count="dismissedCount"
      @toggle-severity="handleToggleSeverity"
    />

    <!-- Main content area - split screen -->
    <div class="flex-1 flex overflow-hidden" :class="{ 'select-none': isResizing }">
      <!-- Left panel - Alert feed (resizable) -->
      <div class="overflow-hidden flex flex-col" :style="leftPanelStyle">
        <!-- Muted rules strip — always visible while any mute is active -->
        <MutedPanel
          :mutes="mutes"
          :muted-count="mutedCount"
          @unmute="handleUnmute"
        />
        <AlertFeed
          class="flex-1 min-h-0"
          :alerts="visibleAlerts"
          :selected-alert="selectedAlert"
          :severity-filter="activeSeverityFilter"
          @select="handleSelectAlert"
          @filter="handleFilter"
          @mute="handleMute"
          @dismiss="handleDismiss"
        />
      </div>

      <!-- Resize handle -->
      <div
        class="w-1 flex-shrink-0 bg-border-primary hover:bg-accent-blue cursor-col-resize transition-colors relative group"
        :class="{ 'bg-accent-blue': isResizing }"
        @mousedown="startResize"
      >
        <div class="absolute inset-y-0 -left-1 -right-1" />
      </div>

      <!-- Right panel - PAI Chat -->
      <div class="overflow-hidden" :style="rightPanelStyle">
        <ChatPanel
          :messages="messages"
          :is-loading="isLoading"
          :error="error"
          :quick-prompts="quickPrompts"
          :selected-alerts="selectedAlerts"
          :provider="provider"
          :provider-config="providerConfig"
          @send="handleSendMessage"
          @quick-action="handleQuickAction"
          @clear="clearChat"
          @set-provider="handleSetProvider"
          @set-ollama-config="handleSetOllamaConfig"
        />
      </div>
    </div>
    </div>

    <!-- Ledger view (mounted only while active; fetches its own data via useLedger) -->
    <LedgerView v-if="currentView === 'ledger'" class="flex-1 overflow-hidden" />

    <!-- Toast notifications -->
    <ToastContainer />
  </div>
</template>
