<script setup lang="ts">
import { ref } from 'vue';
import { useLedger } from '../composables/useLedger';
import LedgerList from './LedgerList.vue';
import LedgerReplay from './LedgerReplay.vue';

const { investigations, selected, isLoading, error, fetchList, fetchDetail } = useLedger();

const view = ref<'list' | 'detail'>('list');

fetchList();

const handleSelect = (id: string) => {
  view.value = 'detail';
  fetchDetail(id);
};

const handleBack = () => {
  view.value = 'list';
  selected.value = null;
  // Refresh in case new investigations landed while a detail was open.
  fetchList();
};
</script>

<template>
  <div class="h-full overflow-hidden">
    <LedgerList
      v-if="view === 'list'"
      :investigations="investigations"
      :is-loading="isLoading"
      :error="error"
      @select="handleSelect"
    />
    <LedgerReplay
      v-else
      :investigation="selected"
      :is-loading="isLoading"
      :error="error"
      @back="handleBack"
    />
  </div>
</template>
