/// <reference types="chrome"/>

import { mountReportUi } from '../ui/report-view';

const root = document.getElementById('root')!;

mountReportUi(root, {
  liveIntervalMs: 2000,
  refresh: async () => {
    const tabId = chrome.devtools.inspectedWindow.tabId;
    await chrome.tabs.sendMessage(tabId, { type: 'REFRESH_SCAN' }).catch(() => undefined);
    const res = (await chrome.runtime.sendMessage({ type: 'GET_REPORT', tabId })) as { report?: import('../shared/types').SecurityReport };
    return res.report;
  },
});
