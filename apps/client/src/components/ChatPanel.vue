<script setup lang="ts">
import { ref, computed, nextTick, watch } from 'vue';
import { marked } from 'marked';
import {
  Send,
  Trash2,
  Loader2,
  Bot,
  User,
  Zap,
  Shield,
  Search,
  Target,
  Map,
  Cloud,
  Server,
  Settings,
  Save,
  Check,
} from 'lucide-vue-next';
import type { WazuhAlert, ChatMessage, QuickPrompts, AIProvider, AIProviderConfig } from '../types';

// Configure marked for security analyst output
marked.setOptions({
  breaks: true,
  gfm: true,
});

const renderMarkdown = (content: string): string => {
  return marked.parse(content) as string;
};

const props = defineProps<{
  messages: ChatMessage[];
  isLoading: boolean;
  error: string | null;
  quickPrompts: QuickPrompts | null;
  selectedAlerts: WazuhAlert[];
  provider: AIProvider;
  providerConfig: AIProviderConfig;
}>();

const emit = defineEmits<{
  (e: 'send', message: string): void;
  (e: 'quickAction', action: keyof QuickPrompts): void;
  (e: 'clear'): void;
  (e: 'setProvider', provider: AIProvider): void;
  (e: 'setOllamaConfig', url: string, model: string): void;
}>();

const showSettings = ref(false);
const editOllamaUrl = ref(props.providerConfig.ollamaUrl);
const editOllamaModel = ref(props.providerConfig.ollamaModel);
const settingsSaved = ref(false);

// Sync local edits when props change (e.g. model list loaded)
watch(() => props.providerConfig.ollamaModel, (v) => { editOllamaModel.value = v; });
watch(() => props.providerConfig.ollamaUrl, (v) => { editOllamaUrl.value = v; });

const saveSettings = () => {
  emit('setOllamaConfig', editOllamaUrl.value, editOllamaModel.value);
  settingsSaved.value = true;
  setTimeout(() => { settingsSaved.value = false; }, 2000);
};

const inputRef = ref<HTMLTextAreaElement | null>(null);
const messagesRef = ref<HTMLDivElement | null>(null);
const inputText = ref('');

// Auto-scroll to bottom when new messages arrive
watch(() => props.messages.length, async () => {
  await nextTick();
  if (messagesRef.value) {
    messagesRef.value.scrollTop = messagesRef.value.scrollHeight;
  }
});

const selectedAlertSummary = computed(() => {
  if (props.selectedAlerts.length === 0) return null;
  if (props.selectedAlerts.length === 1) {
    const alert = props.selectedAlerts[0];
    return `${alert.rule.description} (Level ${alert.rule.level})`;
  }
  return `${props.selectedAlerts.length} alerts selected`;
});

const handleSend = () => {
  const message = inputText.value.trim();
  if (message && !props.isLoading) {
    emit('send', message);
    inputText.value = '';
  }
};

const handleKeyDown = (e: KeyboardEvent) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    handleSend();
  }
};

const formatTime = (timestamp: number) => {
  return new Date(timestamp).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
  });
};

const quickActions = [
  { key: 'analyze' as const, label: 'Analyze', icon: Search },
  { key: 'remediation' as const, label: 'Remediation', icon: Shield },
  { key: 'related' as const, label: 'Related?', icon: Target },
  { key: 'ioc' as const, label: 'IOCs', icon: Zap },
  { key: 'mitre' as const, label: 'MITRE', icon: Map },
];
</script>

<template>
  <div class="h-full flex flex-col bg-bg-primary">
    <!-- Header -->
    <div class="px-4 py-3 border-b border-border-primary">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <Bot class="w-5 h-5 text-accent-blue" />
          <h2 class="font-medium text-text-primary">PAI Security Analyst</h2>
        </div>
        <div class="flex items-center gap-2">
          <!-- AI Provider Toggle -->
          <div class="flex items-center gap-1 bg-bg-secondary rounded-full p-0.5">
            <button
              class="flex items-center gap-1 px-2 py-1 rounded-full text-xs transition-colors"
              :class="provider === 'anthropic'
                ? 'bg-accent-blue text-white'
                : 'text-text-tertiary hover:text-text-secondary'"
              title="Cloud AI (Anthropic Claude)"
              @click="emit('setProvider', 'anthropic')"
            >
              <Cloud class="w-3 h-3" />
              <span>Cloud</span>
            </button>
            <button
              class="flex items-center gap-1 px-2 py-1 rounded-full text-xs transition-colors"
              :class="provider === 'ollama'
                ? 'bg-accent-green text-bg-primary'
                : 'text-text-tertiary hover:text-text-secondary'"
              title="Local AI (Ollama)"
              @click="emit('setProvider', 'ollama')"
            >
              <Server class="w-3 h-3" />
              <span>Local</span>
            </button>
          </div>
          <!-- Settings gear (for Ollama config) -->
          <button
            v-if="provider === 'ollama'"
            class="btn-ghost p-1 rounded"
            title="Ollama settings"
            @click="showSettings = !showSettings"
          >
            <Settings class="w-4 h-4" />
          </button>
          <button
            v-if="messages.length > 0"
            class="btn-ghost p-1 rounded"
            title="Clear chat"
            @click="emit('clear')"
          >
            <Trash2 class="w-4 h-4" />
          </button>
        </div>
      </div>

      <!-- Ollama Settings Panel -->
      <div v-if="showSettings && provider === 'ollama'" class="mt-2 p-3 bg-bg-secondary rounded border border-border-primary space-y-2">
        <div>
          <label class="text-xs text-text-tertiary block mb-1">Ollama URL</label>
          <input
            type="text"
            class="input text-xs w-full"
            v-model="editOllamaUrl"
            placeholder="http://localhost:11434"
          />
        </div>
        <div>
          <label class="text-xs text-text-tertiary block mb-1">Model</label>
          <select
            v-if="providerConfig.availableModels.length > 0"
            class="input text-xs w-full"
            v-model="editOllamaModel"
          >
            <option v-for="model in providerConfig.availableModels" :key="model" :value="model">
              {{ model }}
            </option>
          </select>
          <input
            v-else
            type="text"
            class="input text-xs w-full"
            v-model="editOllamaModel"
            placeholder="llama3.1, qwen2.5, etc."
          />
        </div>
        <div class="flex items-center justify-between">
          <p class="text-xs text-text-tertiary">
            <Server class="w-3 h-3 inline" /> Data stays on your network
          </p>
          <button
            class="flex items-center gap-1 px-3 py-1.5 text-xs rounded border transition-colors"
            :class="settingsSaved
              ? 'border-accent-green text-accent-green'
              : 'border-accent-blue text-accent-blue hover:bg-accent-blue/10'"
            @click="saveSettings"
          >
            <Check v-if="settingsSaved" class="w-3 h-3" />
            <Save v-else class="w-3 h-3" />
            {{ settingsSaved ? 'Saved' : 'Save' }}
          </button>
        </div>
      </div>

      <!-- Selected alert context -->
      <div v-if="selectedAlertSummary" class="mt-2 px-2 py-1.5 bg-bg-secondary rounded text-xs text-text-secondary">
        <span class="text-accent-blue">Context:</span> {{ selectedAlertSummary }}
      </div>
    </div>

    <!-- Quick actions -->
    <div class="px-4 py-2 border-b border-border-primary flex gap-2 overflow-x-auto">
      <button
        v-for="action in quickActions"
        :key="action.key"
        class="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-full border border-border-primary
               text-text-secondary hover:text-text-primary hover:border-accent-blue hover:bg-accent-blue/10
               transition-colors whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed"
        :disabled="isLoading || selectedAlerts.length === 0"
        :title="selectedAlerts.length === 0 ? 'Select an alert first' : action.label"
        @click="emit('quickAction', action.key)"
      >
        <component :is="action.icon" class="w-3 h-3" />
        {{ action.label }}
      </button>
    </div>

    <!-- Messages -->
    <div ref="messagesRef" class="flex-1 overflow-y-auto px-4 py-4 space-y-4">
      <template v-if="messages.length > 0">
        <div
          v-for="(msg, index) in messages"
          :key="index"
          class="flex gap-3"
          :class="msg.role === 'user' ? 'justify-end' : 'justify-start'"
        >
          <!-- Avatar -->
          <div
            v-if="msg.role === 'assistant'"
            class="w-8 h-8 rounded-full bg-accent-blue/20 flex items-center justify-center flex-shrink-0"
          >
            <Bot class="w-4 h-4 text-accent-blue" />
          </div>

          <!-- Message bubble -->
          <div
            class="max-w-[80%] px-3 py-2 rounded-lg"
            :class="msg.role === 'user'
              ? 'bg-accent-blue text-white'
              : 'bg-bg-secondary text-text-primary'"
          >
            <!-- Markdown rendering for assistant, plain text for user -->
            <div
              v-if="msg.role === 'assistant'"
              class="text-sm prose prose-invert prose-sm max-w-none"
              v-html="renderMarkdown(msg.content)"
            />
            <p v-else class="text-sm whitespace-pre-wrap">{{ msg.content }}</p>
            <span class="text-xs opacity-60 mt-1 block">
              {{ formatTime(msg.timestamp) }}
            </span>
          </div>

          <!-- User avatar -->
          <div
            v-if="msg.role === 'user'"
            class="w-8 h-8 rounded-full bg-bg-tertiary flex items-center justify-center flex-shrink-0"
          >
            <User class="w-4 h-4 text-text-secondary" />
          </div>
        </div>
      </template>

      <!-- Empty state -->
      <div v-else class="h-full flex flex-col items-center justify-center text-text-tertiary">
        <Bot class="w-12 h-12 mb-3 opacity-50" />
        <p class="text-sm text-center">Select an alert and ask about it,<br>or use the quick actions above.</p>
      </div>

      <!-- Loading indicator -->
      <div v-if="isLoading" class="flex gap-3">
        <div class="w-8 h-8 rounded-full bg-accent-blue/20 flex items-center justify-center">
          <Loader2 class="w-4 h-4 text-accent-blue animate-spin" />
        </div>
        <div class="px-3 py-2 bg-bg-secondary rounded-lg">
          <p class="text-sm text-text-tertiary">Analyzing...</p>
        </div>
      </div>

      <!-- Error message -->
      <div v-if="error" class="px-3 py-2 bg-severity-critical-bg text-severity-critical rounded-lg text-sm">
        {{ error }}
      </div>
    </div>

    <!-- Input area -->
    <div class="p-4 border-t border-border-primary">
      <div class="flex gap-2">
        <textarea
          ref="inputRef"
          v-model="inputText"
          class="input resize-none"
          rows="2"
          placeholder="Ask about the selected alert..."
          :disabled="isLoading"
          @keydown="handleKeyDown"
        ></textarea>
        <button
          class="btn btn-primary px-3 self-end"
          :disabled="!inputText.trim() || isLoading"
          @click="handleSend"
        >
          <Send class="w-4 h-4" />
        </button>
      </div>
    </div>
  </div>
</template>
