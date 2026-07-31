<script setup lang="ts">
import { computed } from 'vue';
import { ArrowLeft, Bot, Wrench, FileText, Clock, Hash, Loader2 } from 'lucide-vue-next';
import type {
  InvestigationDetail,
  InvestigationStep,
  LlmStepPayload,
  ToolCallStepPayload,
  ToolResultStepPayload,
} from '../types';
import ScorerBadge from './ScorerBadge.vue';

const props = defineProps<{
  investigation: InvestigationDetail | null;
  isLoading: boolean;
  error: string | null;
}>();

const emit = defineEmits<{
  (e: 'back'): void;
}>();

const formattedTime = (iso: string) =>
  new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

// Replay in seq order, per docs/architecture-scorer-ledger.md section 3 ("ORDER BY seq reconstructs
// the exact sequence Claude experienced"). The server already returns steps in
// seq order, but sort defensively so the view never depends on that ordering.
const sortedSteps = computed<InvestigationStep[]>(() => {
  if (!props.investigation) return [];
  return [...props.investigation.steps].sort((a, b) => a.seq - b.seq);
});

function asLlm(step: InvestigationStep): LlmStepPayload {
  return step.payload as LlmStepPayload;
}
function asToolCall(step: InvestigationStep): ToolCallStepPayload {
  return step.payload as ToolCallStepPayload;
}
function asToolResult(step: InvestigationStep): ToolResultStepPayload {
  return step.payload as ToolResultStepPayload;
}

// LlmStepPayload.content is the raw Anthropic content-block array (typed
// `unknown` on the wire, see types.ts). Pull out any text blocks for display;
// tool_use blocks are already shown via the following tool_call step.
function llmText(step: InvestigationStep): string {
  const content = asLlm(step).content;
  if (!Array.isArray(content)) return '';
  return content
    .filter((b: any) => b?.type === 'text' && typeof b.text === 'string')
    .map((b: any) => b.text)
    .join('\n');
}

const durationLabel = computed(() => {
  const ms = props.investigation?.durationMs;
  if (ms == null) return '—';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
});
</script>

<template>
  <div class="h-full flex flex-col overflow-hidden">
    <!-- Header -->
    <div class="px-4 py-3 border-b border-border-primary flex items-center gap-2 flex-shrink-0">
      <button class="btn-ghost p-1.5 rounded" title="Back to list" @click="emit('back')">
        <ArrowLeft class="w-4 h-4" />
      </button>
      <h2 class="font-medium text-text-primary text-sm">Investigation Replay</h2>
    </div>

    <div v-if="isLoading" class="flex-1 flex items-center justify-center text-text-tertiary text-sm">
      <Loader2 class="w-5 h-5 animate-spin mr-2" />
      Loading investigation...
    </div>

    <div v-else-if="error || !investigation" class="flex-1 flex items-center justify-center text-severity-critical text-sm">
      {{ error || 'Investigation not found' }}
    </div>

    <div v-else class="flex-1 overflow-y-auto px-4 py-4 space-y-4">
      <!-- Alert context -->
      <div v-if="investigation.alertContext?.length" class="card p-3">
        <h3 class="text-xs uppercase tracking-wide text-text-tertiary mb-2">Alert Context</h3>
        <div v-for="(alert, i) in investigation.alertContext" :key="i" class="text-sm text-text-primary mb-1">
          {{ alert.rule.description }}
          <span class="text-text-tertiary text-xs">(Level {{ alert.rule.level }})</span>
        </div>
      </div>

      <!-- Scorer verdict(s) -->
      <div v-if="investigation.verdicts?.some((v) => v)" class="card p-3">
        <h3 class="text-xs uppercase tracking-wide text-text-tertiary mb-2">Scorer Verdict</h3>
        <div class="flex flex-wrap gap-2">
          <ScorerBadge v-for="(v, i) in investigation.verdicts" :key="i" :verdict="v" />
        </div>
      </div>

      <!-- Step timeline -->
      <div>
        <h3 class="text-xs uppercase tracking-wide text-text-tertiary mb-2">Steps</h3>
        <div class="space-y-2">
          <div
            v-for="step in sortedSteps"
            :key="step.id"
            class="card p-3 border-l-2"
            :class="{
              'border-accent-blue': step.type === 'llm',
              'border-accent-magenta': step.type === 'tool_call',
              'border-accent-cyan': step.type === 'tool_result',
            }"
          >
            <div class="flex items-center gap-2 mb-1.5 text-xs text-text-tertiary">
              <Bot v-if="step.type === 'llm'" class="w-3.5 h-3.5 text-accent-blue" />
              <Wrench v-else-if="step.type === 'tool_call'" class="w-3.5 h-3.5 text-accent-magenta" />
              <FileText v-else class="w-3.5 h-3.5 text-accent-cyan" />
              <span class="uppercase font-medium">{{ step.type.replace('_', ' ') }}</span>
              <span>&middot; seq {{ step.seq }}</span>
            </div>

            <template v-if="step.type === 'llm'">
              <p v-if="llmText(step)" class="text-sm text-text-primary whitespace-pre-wrap">{{ llmText(step) }}</p>
              <p class="text-xs text-text-tertiary mt-1">
                stop: {{ asLlm(step).stopReason }}
                <span v-if="asLlm(step).usage">
                  &middot; {{ asLlm(step).usage!.input_tokens }} in / {{ asLlm(step).usage!.output_tokens }} out
                </span>
              </p>
            </template>

            <template v-else-if="step.type === 'tool_call'">
              <p class="text-sm text-text-primary font-mono">{{ asToolCall(step).name }}</p>
              <pre class="text-xs text-text-tertiary mt-1 overflow-x-auto">{{ JSON.stringify(asToolCall(step).input, null, 2) }}</pre>
            </template>

            <template v-else>
              <pre class="text-xs text-text-secondary whitespace-pre-wrap">{{ asToolResult(step).resultText }}</pre>
            </template>
          </div>

          <p v-if="sortedSteps.length === 0" class="text-xs text-text-tertiary italic">No steps recorded.</p>
        </div>
      </div>

      <!-- Final analysis -->
      <div class="card p-3">
        <h3 class="text-xs uppercase tracking-wide text-text-tertiary mb-2">Final Analysis</h3>
        <p v-if="investigation.finalAnalysis" class="text-sm text-text-primary whitespace-pre-wrap">{{ investigation.finalAnalysis }}</p>
        <p v-else-if="investigation.status === 'running'" class="text-sm text-text-tertiary italic">Still running…</p>
        <p v-else-if="investigation.status === 'error'" class="text-sm text-severity-critical">
          Investigation ended in an error with no final analysis.
        </p>
        <p v-else class="text-sm text-text-tertiary italic">No analysis recorded.</p>
      </div>

      <!-- Token + duration footer -->
      <div class="flex items-center gap-4 text-xs text-text-tertiary pt-2 border-t border-border-primary">
        <div class="flex items-center gap-1">
          <Hash class="w-3 h-3" />
          {{ investigation.inputTokens ?? 0 }} in / {{ investigation.outputTokens ?? 0 }} out tokens
        </div>
        <div class="flex items-center gap-1">
          <Clock class="w-3 h-3" />
          {{ durationLabel }}
        </div>
        <div class="text-text-tertiary">{{ formattedTime(investigation.createdAt) }}</div>
      </div>
    </div>
  </div>
</template>
