/// <reference types="chrome"/>

import { buildSecurityReport } from '../analysis/analyze-report';
import type { ApiCall, ContentScanPayload, MainWorldGlobals, SecurityReport } from '../shared/types';
import type { VulnerabilityDatabase } from '../analysis/libs';

const tabMain = new Map<number, { url: string; headers: Record<string, string> }>();
const tabSetCookies = new Map<number, string[]>();
const tabApis = new Map<number, ApiCall[]>();
const tabGlobals = new Map<number, { jquery?: string; keys: Record<string, boolean> }>();

let vulnDb: VulnerabilityDatabase | null = null;

async function ensureDb(): Promise<VulnerabilityDatabase> {
  if (vulnDb) return vulnDb;
  const res = await fetch(chrome.runtime.getURL('data/vulnerabilities.json'));
  vulnDb = (await res.json()) as VulnerabilityDatabase;
  return vulnDb;
}

void ensureDb();
chrome.runtime.onInstalled.addListener(() => void ensureDb());
chrome.runtime.onStartup.addListener(() => void ensureDb());

function normalize(details: chrome.webRequest.HttpHeader[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!details) return out;
  for (const h of details) {
    const name = (h.name || '').toLowerCase();
    if (!name) continue;
    const value = h.value || '';
    out[name] = out[name] ? `${out[name]}, ${value}` : value;
  }
  return out;
}

function isStaticAsset(url: string): boolean {
  try {
    return /\.(png|jpe?g|gif|webp|svg|ico|css|woff2?|ttf|eot|map|mp4|webm|mp3)$/i.test(new URL(url).pathname);
  } catch {
    return true;
  }
}

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const headers = normalize(details.responseHeaders);
    if (details.type === 'main_frame') {
      tabMain.set(details.tabId, { url: details.url, headers });
      tabApis.set(details.tabId, []);
      tabSetCookies.set(details.tabId, []);
    }
    const setCookies =
      details.responseHeaders
        ?.filter((h) => (h.name || '').toLowerCase() === 'set-cookie')
        .map((h) => h.value || '')
        .filter(Boolean) ?? [];
    if (setCookies.length) {
      const bag = tabSetCookies.get(details.tabId) ?? [];
      bag.push(...setCookies);
      tabSetCookies.set(details.tabId, bag.slice(-160));
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders', 'extraHeaders'],
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const t = details.type;
    if (t !== 'xmlhttprequest' && t !== 'other') return;
    if (isStaticAsset(details.url)) return;
    const list = tabApis.get(details.tabId) ?? [];
    list.push({
      url: details.url,
      method: details.method || 'GET',
      type: t,
      timestamp: Date.now(),
    });
    tabApis.set(details.tabId, list.slice(-240));
  },
  { urls: ['<all_urls>'] },
);

async function persistHistory(report: SecurityReport): Promise<void> {
  const key = 'scanHistory';
  const prev = (await chrome.storage.local.get(key))[key] as SecurityReport[] | undefined;
  const next = [{ ...report, findings: report.findings.slice(0, 40) }, ...(prev ?? [])].slice(0, 12);
  await chrome.storage.local.set({ [key]: next });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  void (async () => {
    try {
      if (message.type === 'INJECT_EARLY') {
        const tabId = sender.tab?.id;
        if (tabId === undefined) return;
        try {
          const frameId = sender.frameId ?? 0;
          await chrome.scripting.executeScript({
            target: { tabId, frameIds: [frameId] },
            world: 'MAIN',
            files: ['inject.js'],
          });
        } catch {
          /* Some frames disallow injection */
        }
        return;
      }

      if (message.type === 'GLOBAL_HINTS' && sender.tab?.id !== undefined) {
        tabGlobals.set(sender.tab.id, message.payload);
        return;
      }

      if (message.type === 'API_HIT' && sender.tab?.id !== undefined) {
        const list = tabApis.get(sender.tab.id) ?? [];
        list.push({
          url: message.url,
          method: message.method || 'GET',
          type: message.sourceType || 'page',
          timestamp: Date.now(),
        });
        tabApis.set(sender.tab.id, list.slice(-240));
        return;
      }

      if (message.type === 'CONTENT_SCAN' && sender.tab?.id !== undefined) {
        const tabId = sender.tab.id;
        const payload = { ...(message.payload as ContentScanPayload) };
        const hints = tabGlobals.get(tabId);
        const globals: Record<string, unknown> = { ...payload.globals };
        if (hints?.jquery) globals.jQuery = hints.jquery;
        if (hints?.keys) {
          for (const [k, v] of Object.entries(hints.keys)) {
            if (v) globals[k] = true;
          }
        }
        payload.globals = globals as MainWorldGlobals;

        const db = await ensureDb();
        const report = await buildSecurityReport({
          tabId,
          payload,
          mainHeaders: tabMain.get(tabId),
          setCookieLines: tabSetCookies.get(tabId) ?? [],
          apiCalls: tabApis.get(tabId) ?? [],
          vulnDb: db,
        });
        await chrome.storage.local.set({ [`report:${tabId}`]: report });
        await persistHistory(report);
        sendResponse({ ok: true, report });
        return;
      }

      if (message.type === 'GET_REPORT') {
        const tabId = message.tabId as number;
        const hit = await chrome.storage.local.get(`report:${tabId}`);
        sendResponse({ report: hit[`report:${tabId}`] as SecurityReport | undefined });
        return;
      }

      if (message.type === 'REFRESH_SCAN' && sender.tab?.id !== undefined) {
        sendResponse({ ok: true });
        return;
      }
    } catch (err) {
      sendResponse({ error: String(err) });
    }
  })();

  return true;
});
