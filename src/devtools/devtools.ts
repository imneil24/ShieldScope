/// <reference types="chrome"/>

chrome.devtools.panels.create('Security Inspector', '', chrome.runtime.getURL('panel.html'), () => undefined);
