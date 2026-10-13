'use strict';
const {app, BrowserWindow, ipcMain, shell, dialog} = require('electron');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {Preferences} = require('./preferences.cjs');
const {AuthClient} = require('./auth.cjs');
const {spawnTun, recoverTun, recoveryPending} = require('./tun-launcher.cjs');
const {VpnSupervisor} = require('./vpn.cjs');
const vpn = new VpnSupervisor({spawnTunChild: spawnTun, helperPath: path.join(app.isPackaged ? process.resourcesPath : __dirname, 'bin', 'mchip-vpn-helper')});
vpn.on('status', status => { if (win && !win.isDestroyed()) win.webContents.send('vpn:status', status); });
let win, client, busy = false;
const entry = path.join(__dirname, 'index.html');
app.setName('M Chip VPN Login');
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(() => {
    win = new BrowserWindow({width: 1040, height: 800, minWidth: 900, minHeight: 800, titleBarStyle: 'hiddenInset', trafficLightPosition: {x: 18, y: 18}, backgroundColor: '#f5f6f8', title: 'M Chip VPN Login · 测试版', webPreferences: {preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true}});
    win.removeMenu(); win.loadFile(entry);
    win.webContents.setWindowOpenHandler(() => ({action: 'deny'}));
    win.webContents.on('will-navigate', e => e.preventDefault());
    win.on('closed', () => { win = null; client?.close(); client = null; void vpn.stop().catch(() => {}); });
  });
  ipcMain.handle('auth:call', async (event, {action, data} = {}) => {
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    if (busy) return {ok: false, error: '上一项操作尚未结束。'};
    busy = true;
    try {
      let value;
      switch (action) {
        case 'initialize': { const server = await new Preferences(app.getPath('userData')).saveServer(data?.server); await vpn.stop(); client?.close(); client = new AuthClient(server); value = await client.initialize(); break; }
        case 'captcha': if (!client) throw new Error('请先连接服务器。'); value = {captchaImage: await client.captcha()}; break;
        case 'login': if (!client) throw new Error('请先连接服务器。'); value = await client.login(data || {}); break;
        case 'challenge': if (!client) throw new Error('请先连接服务器。'); value = await client.submitChallenge(data?.value); break;
        case 'logout': await vpn.stop(); value = client ? await client.logout() : {phase: 'idle'}; client = null; break;
        default: throw new Error('操作无效。');
      }
      return {ok: true, value};
    } catch (error) { return {ok: false, error: error.message || '请求失败。'}; }
    finally { busy = false; }
  });
  ipcMain.handle('preferences:server', async event => {
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    return {ok: true, value: {server: await new Preferences(app.getPath('userData')).readServer(), recoveryRequired: await recoveryPending()}};
  });
  ipcMain.handle('vpn:call', async (event, {action, data} = {}) => {
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    if (action === 'recover') {
      if (busy || vpn.active) return {ok:false,error:'请先结束当前操作或断开 VPN。'};
      busy=true;try {await recoverTun(vpn.helperPath);return {ok:true,value:{recovered:true}};}catch(error){return {ok:false,error:error.message};}finally{busy=false;}
    }
    if (action === 'status') return {ok: true, value: vpn.status};
    if (action === 'stop') { try { await vpn.stop(); return {ok: true, value: vpn.status}; } catch (error) { return {ok: false, error: error.message}; } }
    if (action === 'license') { await shell.openExternal('https://github.com/FV4004/m-chip-vpn-login/blob/main/app/THIRD_PARTY_NOTICES.md'); return {ok: true}; }
    if (action !== 'start') return {ok: false, error: '操作无效。'};
    if (busy) return {ok: false, error: '上一项操作尚未结束。'};
    busy = true;
    try {
      if (!client?.authenticated || !client.twfid) throw new Error('请先完成账号认证。');
      const value = await vpn.start({hostname: client.base.hostname, sessionId: client.twfid, tunnelPort: data?.tunnelPort, socksPort: data?.socksPort, httpPort: data?.httpPort, mode: data?.mode});
      if (vpn.status.state !== 'connected') throw new Error(vpn.status.message || 'VPN 连接已断开。');
      return {ok: true, value};
    } catch (error) { return {ok: false, error: error.message || 'VPN 连接失败。'}; }
    finally { busy = false; }
  });
  let quitting = false;
  app.on('before-quit', event => {
    if (quitting) return;
    event.preventDefault(); client?.close(); client = null;
    vpn.stop().catch(() => { dialog.showErrorBox('VPN 网络配置恢复待确认', '未能确认路由和内网 DNS 已恢复。请检查系统网络配置后再连接 VPN。'); }).finally(() => { quitting = true; app.quit(); });
  });
  app.on('window-all-closed', () => { app.quit(); });
}
