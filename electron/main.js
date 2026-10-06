const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');

/**
 * Is This A Scam? — single window, single input.
 *
 * The renderer runs the shared HTML/CSS/JS in app/. Because that page is
 * loaded from file://, fetch() to ScamAdviser and OpenPhish is blocked by
 * CORS, so the renderer asks the main process to do the request instead.
 * The main process has no origin and no CORS restrictions.
 */

const ALLOWED_HOSTS = new Set([
  'www.scamadviser.com', 'scamadviser.com',
  'rdap.org', 'dns.google',
  'openphish.com', 'www.openphish.com',
  'archive.org', 'web.archive.org',
]);

async function nativeFetch(url) {
  let u;
  try { u = new URL(url); } catch { return { ok: false, status: 0, text: 'bad url' }; }
  if (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname)) {
    return { ok: false, status: 0, text: 'host not allowed: ' + u.hostname };
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000);
  try {
    const r = await fetch(url, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; IsThisAScam/1.0)' },
    });
    return { ok: r.ok, status: r.status, text: await r.text() };
  } catch (e) {
    return { ok: false, status: 0, text: String(e && e.message || e) };
  } finally {
    clearTimeout(timer);
  }
}

ipcMain.handle('net:fetch', async (_ev, url) => nativeFetch(url));

function createWindow() {
  const win = new BrowserWindow({
    width: 760,
    height: 940,
    minWidth: 420,
    minHeight: 560,
    backgroundColor: '#0e1117',
    title: 'Is This A Scam?',
    autoHideMenuBar: true,
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  win.loadFile(path.join(__dirname, 'app', 'index.html'));

  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
