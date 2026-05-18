/// <reference types="chrome"/>

import type { ApiCall, ContentScanPayload, FormSummary } from '../shared/types';

function scanForms(isHttps: boolean): FormSummary[] {
  return Array.from(document.forms).map((form, index) => {
    const method = (form.method || 'get').toUpperCase();
    const action = form.action || location.href;
    const hasPassword = Array.from(form.elements).some((e) => e instanceof HTMLInputElement && e.type === 'password');
    const hiddenFieldCount = Array.from(form.elements).filter(
      (e) => e instanceof HTMLInputElement && e.type === 'hidden',
    ).length;
    const issues: string[] = [];
    if (hasPassword && !isHttps) issues.push('password on non-https');
    return { index, method, action, hasPassword, hiddenFieldCount, issues };
  });
}

function gatherPayload(): ContentScanPayload {
  const url = location.href;
  const isHttps = location.protocol === 'https:';
  const scriptSrcs = Array.from(document.scripts)
    .map((s) => s.src)
    .filter(Boolean);
  let inlineScriptDigest = '';
  for (const s of Array.from(document.scripts)) {
    if (!s.src && s.textContent) {
      inlineScriptDigest += s.textContent.slice(0, 24_000);
    }
    if (inlineScriptDigest.length > 120_000) break;
  }
  const meta: Record<string, string> = {};
  for (const m of Array.from(document.querySelectorAll('meta'))) {
    const name = m.getAttribute('name') || m.getAttribute('property');
    const content = m.getAttribute('content');
    if (name && content) meta[name.toLowerCase()] = content;
  }
  const linkHints = Array.from(document.querySelectorAll('link[rel="stylesheet"][href]')).map(
    (l) => (l as HTMLLinkElement).href,
  );
  const htmlSample = document.documentElement.outerHTML.slice(0, 220_000);

  const apisFromPage: ApiCall[] = [];

  return {
    url,
    title: document.title,
    isHttps,
    documentCookie: document.cookie,
    htmlSample,
    scriptSrcs,
    inlineScriptDigest,
    meta,
    linkHints,
    globals: {},
    forms: scanForms(isHttps),
    apisFromPage,
  };
}

function sendScan(): void {
  const payload = gatherPayload();
  chrome.runtime.sendMessage({ type: 'CONTENT_SCAN', payload }, () => void chrome.runtime.lastError);
}

sendScan();

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === 'REFRESH_SCAN') sendScan();
});

let debounce: number | undefined;
const schedule = () => {
  window.clearTimeout(debounce);
  debounce = window.setTimeout(sendScan, 800);
};

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') sendScan();
});
window.addEventListener('popstate', schedule);
window.addEventListener('hashchange', schedule);
