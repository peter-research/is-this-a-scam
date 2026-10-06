const { contextBridge, ipcRenderer } = require('electron');

/**
 * The only bridge the page gets: one HTTP GET, restricted in the main
 * process to an allow-list of reputation hosts. No Node, no filesystem.
 */
contextBridge.exposeInMainWorld('__net', {
  fetch: (url) => ipcRenderer.invoke('net:fetch', url),
});
