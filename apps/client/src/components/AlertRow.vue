<script setup lang="ts">
import { ref, computed } from 'vue';
import { ChevronRight, Server, Clock, Tag, ExternalLink, BellOff, X, FileDown, Copy, Check } from 'lucide-vue-next';
import type { WazuhAlert } from '../types';
import { getSeverityLevel, getSeverityLabel } from '../types';

// Suricata host that runs pcap-log with conditional:alerts. Override with VITE_PCAP_SSH if needed.
const PCAP_SSH_TARGET = (import.meta.env.VITE_PCAP_SSH as string) || 'cgarrison@192.168.2.92';
const PCAP_LOG_DIR = '~/homelab-deploy/suricata/logs';

const props = defineProps<{
  alert: WazuhAlert;
  isSelected: boolean;
}>();

const emit = defineEmits<{
  (e: 'select', alert: WazuhAlert): void;
  (e: 'suppress', ruleId: string, reason: string, description: string, suricataSid?: string): void;
  (e: 'dismiss', alert: WazuhAlert): void;
}>();

const handleDismiss = (event: Event) => {
  event.stopPropagation();
  emit('dismiss', props.alert);
};

const severity = computed(() => getSeverityLevel(props.alert.rule.level));
const severityLabel = computed(() => getSeverityLabel(props.alert.rule.level));

// Suricata IDS detection
const suricataSid = computed(() => props.alert.data?.alert?.signature_id);
const isSuricata = computed(() => !!suricataSid.value);

// Suppress confirmation state
const showSuppressConfirm = ref(false);
const suppressReason = ref('');

const formattedTime = computed(() => {
  const date = new Date(props.alert.timestamp);
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
});

const formattedDate = computed(() => {
  const date = new Date(props.alert.timestamp);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
  });
});

const suppressLabel = computed(() => {
  if (isSuricata.value) {
    return `Suppress Suricata SID ${suricataSid.value}`;
  }
  return `Suppress Wazuh rule ${props.alert.rule.id}`;
});

const confirmLabel = computed(() => {
  if (isSuricata.value) {
    return `Suppress SID ${suricataSid.value}? This will disable the Suricata rule via suricata-update.`;
  }
  return `Suppress rule ${props.alert.rule.id}? This will set level=0 in Wazuh local_rules.xml and restart the manager.`;
});

const handleSuppressClick = (event: Event) => {
  event.stopPropagation();
  showSuppressConfirm.value = true;
};

const handleConfirmSuppress = (event: Event) => {
  event.stopPropagation();
  emit(
    'suppress',
    props.alert.rule.id,
    suppressReason.value,
    props.alert.rule.description,
    isSuricata.value ? String(suricataSid.value) : undefined,
  );
  showSuppressConfirm.value = false;
  suppressReason.value = '';
};

const handleCancelSuppress = (event: Event) => {
  event.stopPropagation();
  showSuppressConfirm.value = false;
  suppressReason.value = '';
};

// PCAP extraction panel ----------------------------------------------------
// Suricata's pcap-log (conditional: alerts) writes per-flow PCAPs to disk.
// We generate a one-liner that finds the right file, carves the alert's
// 5-tuple, and streams the resulting .pcap back to the analyst's laptop —
// ready to drop into OhMyPCAP at https://pcap.home.carbeneai.com
const showPcapPanel = ref(false);
const pcapCopied = ref(false);

const srcIp = computed(() => props.alert.srcip || (props.alert.data as any)?.src_ip || '');
const dstIp = computed(() => props.alert.dstip || (props.alert.data as any)?.dest_ip || '');
const flowId = computed(() => (props.alert.data as any)?.flow_id || '');

const canExtractPcap = computed(() => isSuricata.value && !!srcIp.value && !!dstIp.value);

const pcapCommand = computed(() => {
  const ts = Math.floor(new Date(props.alert.timestamp).getTime() / 1000);
  const filename = flowId.value ? `alert-${flowId.value}.pcap` : `alert-${ts}.pcap`;
  // Single line so analysts can paste into any shell. Inner `awk` script uses
  // single quotes which we escape because the whole command is wrapped in ".
  return `ssh ${PCAP_SSH_TARGET} "cd ${PCAP_LOG_DIR} && P=\\$(ls -1 log.pcap.* 2>/dev/null | awk -F. -v ts=${ts} '\\$3<=ts' | sort -t. -k3 -n | tail -1) && cat \\"\\$P\\" | tcpdump -r - -w - 'host ${srcIp.value} and host ${dstIp.value}' 2>/dev/null" > ~/Downloads/${filename}`;
});

const handlePcapClick = (event: Event) => {
  event.stopPropagation();
  showPcapPanel.value = !showPcapPanel.value;
  pcapCopied.value = false;
};

const handleCopyPcap = async (event: Event) => {
  event.stopPropagation();
  try {
    await navigator.clipboard.writeText(pcapCommand.value);
    pcapCopied.value = true;
    setTimeout(() => { pcapCopied.value = false; }, 2000);
  } catch {
    // navigator.clipboard fails on http:// — silent fail, user can select+copy manually
  }
};

const handleClosePcap = (event: Event) => {
  event.stopPropagation();
  showPcapPanel.value = false;
};
</script>

<template>
  <div>
    <div
      class="group px-4 py-3 border-b border-border-primary hover:bg-bg-tertiary/30 cursor-pointer transition-colors"
      :class="{ 'bg-bg-tertiary/50': isSelected }"
      @click="emit('select', alert)"
    >
      <div class="flex items-start gap-3">
        <!-- Severity indicator -->
        <div
          class="w-1 h-full min-h-[3rem] rounded-full flex-shrink-0"
          :class="{
            'bg-severity-critical': severity === 'critical',
            'bg-severity-high': severity === 'high',
            'bg-severity-medium': severity === 'medium',
            'bg-severity-low': severity === 'low',
          }"
        ></div>

        <!-- Main content -->
        <div class="flex-1 min-w-0">
          <!-- Header row -->
          <div class="flex items-center gap-2 mb-1">
            <span
              class="badge flex-shrink-0"
              :class="`badge-${severity}`"
            >
              Level {{ alert.rule.level }} - {{ severityLabel }}
            </span>
            <span class="text-xs text-text-tertiary font-mono">{{ alert.rule.id }}</span>
            <!-- Suricata SID badge -->
            <span
              v-if="isSuricata"
              class="text-xs text-amber-400/80 font-mono bg-amber-900/30 px-1.5 py-0.5 rounded"
            >
              SID {{ suricataSid }}
            </span>
          </div>

          <!-- Description -->
          <p class="text-sm text-text-primary mb-2 line-clamp-2">
            {{ alert.rule.description }}
          </p>

          <!-- Metadata row -->
          <div class="flex items-center gap-4 text-xs text-text-tertiary">
            <!-- Agent -->
            <div class="flex items-center gap-1">
              <Server class="w-3 h-3" />
              <span>{{ alert.agent?.name || 'Unknown' }}</span>
            </div>

            <!-- Time -->
            <div class="flex items-center gap-1">
              <Clock class="w-3 h-3" />
              <span>{{ formattedDate }} {{ formattedTime }}</span>
            </div>

            <!-- Groups -->
            <div v-if="alert.rule.groups?.length" class="flex items-center gap-1">
              <Tag class="w-3 h-3" />
              <span>{{ alert.rule.groups.slice(0, 2).join(', ') }}</span>
            </div>

            <!-- MITRE -->
            <div v-if="alert.rule.mitre?.id?.length" class="flex items-center gap-1">
              <ExternalLink class="w-3 h-3" />
              <span>{{ alert.rule.mitre.id[0] }}</span>
            </div>
          </div>
        </div>

        <!-- Action buttons -->
        <div class="flex items-center gap-1 flex-shrink-0">
          <!-- Dismiss button (this alert only) -->
          <button
            class="p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity hover:bg-bg-tertiary text-text-tertiary hover:text-text-primary"
            title="Dismiss this alert (rule stays active)"
            @click="handleDismiss"
          >
            <X class="w-4 h-4" />
          </button>

          <!-- PCAP extract button (Suricata alerts with src+dst IPs) -->
          <button
            v-if="canExtractPcap"
            class="p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity hover:bg-blue-900/40 text-text-tertiary hover:text-blue-400"
            title="Generate command to download this flow's PCAP"
            @click="handlePcapClick"
          >
            <FileDown class="w-4 h-4" />
          </button>

          <!-- Suppress button (all alerts with this rule) -->
          <button
            class="p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity hover:bg-amber-900/40 text-text-tertiary hover:text-amber-400"
            :title="suppressLabel"
            @click="handleSuppressClick"
          >
            <BellOff class="w-4 h-4" />
          </button>

          <!-- Chevron -->
          <ChevronRight
            class="w-5 h-5 text-text-tertiary group-hover:text-text-secondary transition-colors"
            :class="{ 'text-accent-blue': isSelected }"
          />
        </div>
      </div>
    </div>

    <!-- Inline PCAP extraction panel -->
    <div
      v-if="showPcapPanel"
      class="px-4 py-3 bg-blue-950/30 border-b border-blue-800/30"
      @click.stop
    >
      <p class="text-xs text-blue-300 mb-2">
        Run this in your terminal to download the PCAP for this flow, then drop it into
        <a href="https://pcap.home.carbeneai.com" target="_blank" rel="noopener" class="underline hover:text-blue-200">OhMyPCAP</a>:
      </p>
      <div class="flex items-start gap-2">
        <pre class="flex-1 text-xs bg-bg-primary border border-border-primary rounded p-2 text-text-primary font-mono overflow-x-auto whitespace-pre-wrap break-all select-all">{{ pcapCommand }}</pre>
        <div class="flex flex-col gap-1 flex-shrink-0">
          <button
            class="text-xs px-3 py-1.5 rounded bg-blue-700 hover:bg-blue-600 text-white transition-colors flex items-center gap-1"
            :title="pcapCopied ? 'Copied!' : 'Copy command'"
            @click="handleCopyPcap"
          >
            <Check v-if="pcapCopied" class="w-3 h-3" />
            <Copy v-else class="w-3 h-3" />
            {{ pcapCopied ? 'Copied' : 'Copy' }}
          </button>
          <button
            class="text-xs px-3 py-1.5 rounded bg-bg-tertiary hover:bg-bg-tertiary/80 text-text-secondary transition-colors"
            @click="handleClosePcap"
          >
            Close
          </button>
        </div>
      </div>
    </div>

    <!-- Inline suppress confirmation -->
    <div
      v-if="showSuppressConfirm"
      class="px-4 py-3 bg-amber-950/30 border-b border-amber-800/30"
      @click.stop
    >
      <p class="text-xs text-amber-300 mb-2">
        {{ confirmLabel }}
      </p>
      <div class="flex items-center gap-2">
        <input
          v-model="suppressReason"
          type="text"
          placeholder="Reason (optional)"
          class="flex-1 text-xs bg-bg-primary border border-border-primary rounded px-2 py-1.5 text-text-primary placeholder-text-tertiary focus:outline-none focus:border-amber-600"
          @keydown.enter="handleConfirmSuppress"
          @keydown.escape="handleCancelSuppress"
        />
        <button
          class="text-xs px-3 py-1.5 rounded bg-amber-700 hover:bg-amber-600 text-white transition-colors"
          @click="handleConfirmSuppress"
        >
          Confirm
        </button>
        <button
          class="text-xs px-3 py-1.5 rounded bg-bg-tertiary hover:bg-bg-tertiary/80 text-text-secondary transition-colors"
          @click="handleCancelSuppress"
        >
          Cancel
        </button>
      </div>
    </div>
  </div>
</template>
