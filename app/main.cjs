'use strict';
const {app, BrowserWindow, ipcMain} = require('electron');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {AuthClient} = require('./auth.cjs');
let win, client, busy = false;
const entry = path.join(__dirname, 'index.html');
app.setName('M Chip VPN Login');
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(() => {
    win = new BrowserWindow({width: 1040, height: 750, minWidth: 820, minHeight: 690, backgroundColor: '#f5f6f8', title: 'M Chip VPN Login · 测试版', webPreferences: {preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true}});
    win.removeMenu(); win.loadFile(entry);
    win.webContents.setWindowOpenHandler(() => ({action: 'deny'}));
    win.webContents.on('will-navigate', e => e.preventDefault());
    win.on('closed', () => { win = null; client?.close(); });
  });
  ipcMain.handle('auth:call', async (event, {action, data} = {}) => {
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    if (busy) return {ok: false, error: '上一项操作尚未结束。'};
    busy = true;
    try {
      let value;
      switch (action) {
        case 'initialize': client?.close(); client = new AuthClient(data?.server); value = await client.initialize(); break;
        case 'captcha': if (!client) throw new Error('请先连接服务器。'); value = {captchaImage: await client.captcha()}; break;
        case 'login': if (!client) throw new Error('请先连接服务器。'); value = await client.login(data || {}); break;
        case 'challenge': if (!client) throw new Error('请先连接服务器。'); value = await client.submitChallenge(data?.value); break;
        case 'logout': value = client ? await client.logout() : {phase: 'idle'}; client = null; break;
        default: throw new Error('操作无效。');
      }
      return {ok: true, value};
    } catch (error) { return {ok: false, error: error.message || '请求失败。'}; }
    finally { busy = false; }
  });
  app.on('window-all-closed', () => { client?.close(); app.quit(); });
}
