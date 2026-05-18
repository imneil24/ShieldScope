/// <reference types="chrome"/>

window.addEventListener(
  'message',
  (event: MessageEvent) => {
    if (event.source !== window) return;
    const data = event.data as
      | { __SEC_INSP?: string; url?: string; method?: string; sourceType?: string; jquery?: string; keys?: Record<string, boolean> }
      | undefined;
    if (!data || !data.__SEC_INSP) return;
    if (data.__SEC_INSP === 'api') {
      void chrome.runtime.sendMessage({
        type: 'API_HIT',
        url: data.url,
        method: data.method,
        sourceType: data.sourceType,
      });
      return;
    }
    if (data.__SEC_INSP === 'globals') {
      void chrome.runtime.sendMessage({
        type: 'GLOBAL_HINTS',
        payload: { jquery: data.jquery, keys: data.keys ?? {} },
      });
    }
  },
  true,
);

void chrome.runtime.sendMessage({ type: 'INJECT_EARLY' });
