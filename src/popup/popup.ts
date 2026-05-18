/// <reference types="chrome"/>

import { mountReportUi } from '../ui/report-view';

const app = document.getElementById('app')!;

mountReportUi(app, {
  refresh: async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return undefined;
    await chrome.tabs.sendMessage(tab.id, { type: 'REFRESH_SCAN' }).catch(() => undefined);
    const res = (await chrome.runtime.sendMessage({ type: 'GET_REPORT', tabId: tab.id })) as { report?: import('../shared/types').SecurityReport };
    return res.report;
  },
});
