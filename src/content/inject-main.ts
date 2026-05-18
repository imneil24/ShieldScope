type GlobalsMessage = {
  __SEC_INSP: 'globals';
  jquery?: string;
  keys: Record<string, boolean>;
};

const keysToCheck = [
  'jQuery',
  'React',
  'angular',
  'Vue',
  '__NEXT_DATA__',
  'Shopify',
  'webpackChunkName',
] as const;

function readGlobals(): GlobalsMessage {
  const w = window as unknown as Record<string, unknown>;
  const keys: Record<string, boolean> = {};
  for (const k of keysToCheck) {
    try {
      keys[k] = typeof w[k] !== 'undefined';
    } catch {
      keys[k] = false;
    }
  }
  let jq: string | undefined;
  try {
    const j = w.jQuery as { fn?: { jquery?: string } } | undefined;
    if (j?.fn?.jquery) jq = j.fn.jquery;
  } catch {
    /* ignore */
  }
  return { __SEC_INSP: 'globals', jquery: jq, keys };
}

function hookNetwork(): void {
  const post = (url: unknown, method: string, sourceType: string) => {
    try {
      window.postMessage({ __SEC_INSP: 'api', url: String(url), method, sourceType }, '*');
    } catch {
      /* ignore */
    }
  };

  const origFetch = window.fetch;
  window.fetch = function fetchHook(input: RequestInfo | URL, ...args: unknown[]) {
    try {
      let method = 'GET';
      let url: string | URL = input as string | URL;
      if (typeof input === 'string' || input instanceof URL) {
        url = input;
      } else {
        url = (input as Request).url;
        method = (input as Request).method || 'GET';
      }
      post(url, method, 'fetch');
    } catch {
      /* ignore */
    }
    return origFetch.call(this, input, ...(args as [RequestInit?]));
  };

  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function openHook(
    this: XMLHttpRequest,
    method: string,
    url: string | URL,
    async?: boolean,
    username?: string | null,
    password?: string | null,
  ) {
    post(url, method, 'xhr');
    return origOpen.call(this, method, url, async ?? true, username ?? null, password ?? null);
  };
}

hookNetwork();
window.postMessage(readGlobals(), '*');
