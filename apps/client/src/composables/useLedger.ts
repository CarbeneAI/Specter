import { ref } from 'vue';
import type { InvestigationSummary, InvestigationDetail } from '../types';

// Mirrors the getApiUrl()/API_URL pattern already used by usePAIChat.ts and
// useWebSocket.ts -- same env var, same localhost fallback.
function getApiUrl(): string {
  if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
  return 'http://localhost:4001';
}

const API_URL = getApiUrl();

export function useLedger() {
  const investigations = ref<InvestigationSummary[]>([]);
  const selected = ref<InvestigationDetail | null>(null);
  const isLoading = ref(false);
  const error = ref<string | null>(null);

  // GET /ledger?limit= -- list recent investigations, most-recent-first.
  const fetchList = async (limit?: number): Promise<InvestigationSummary[]> => {
    isLoading.value = true;
    error.value = null;

    try {
      const url = new URL(`${API_URL}/ledger`);
      if (limit) url.searchParams.set('limit', String(limit));

      const response = await fetch(url.toString());
      if (!response.ok) {
        error.value = `Failed to load investigations (${response.status})`;
        return [];
      }

      const data = await response.json() as { investigations: InvestigationSummary[] };
      investigations.value = data.investigations ?? [];
      return investigations.value;
    } catch (err) {
      console.error('Ledger fetchList error:', err);
      error.value = 'Failed to connect to server';
      return [];
    } finally {
      isLoading.value = false;
    }
  };

  // GET /ledger/:id -- full replay detail for one investigation. Returns null
  // on 404 (or any other failure) rather than throwing, per usePAIChat.ts's
  // existing convention of surfacing failures through `error` instead.
  const fetchDetail = async (id: string): Promise<InvestigationDetail | null> => {
    isLoading.value = true;
    error.value = null;

    try {
      const response = await fetch(`${API_URL}/ledger/${id}`);

      if (response.status === 404) {
        error.value = 'Investigation not found';
        selected.value = null;
        return null;
      }

      if (!response.ok) {
        error.value = `Failed to load investigation (${response.status})`;
        return null;
      }

      const data = await response.json() as { investigation: InvestigationDetail };
      selected.value = data.investigation;
      return data.investigation;
    } catch (err) {
      console.error('Ledger fetchDetail error:', err);
      error.value = 'Failed to connect to server';
      return null;
    } finally {
      isLoading.value = false;
    }
  };

  return {
    investigations,
    selected,
    isLoading,
    error,
    fetchList,
    fetchDetail,
  };
}
