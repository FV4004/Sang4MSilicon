'use strict';
const {app, BrowserWindow, ipcMain, shell, dialog, safeStorage, session} = require('electron');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {Preferences} = require('./preferences.cjs');
const {Credentials}=require('./credentials.cjs');
let credentials;
const accounts=()=>credentials||(credentials=new Credentials(app.getPath('userData'),safeStorage));
const {AuthClient} = require('./auth.cjs');
const {ResourceCatalog}=require('./resources.cjs');
const {ResourceBrowser}=require('./resource-browser.cjs');
const {ClosePreferences,Shutdown}=require('./lifecycle.cjs');
const resourceBrowser=new ResourceBrowser({BrowserWindow,session,openExternal:url=>shell.openExternal(url)});
let catalog=null,catalogOwner=null,authDone=Promise.resolve(),shuttingDown=false,quitting=false,prompting=false;
const closePreferences=()=>new ClosePreferences(app.getPath('userData'));
async function closeResources(){catalog?.close();catalog=null;catalogOwner=null;await resourceBrowser.close()}
const shutdown=new Shutdown({stopVPN:()=>vpn.stop(),getClient:()=>client,closeResources,drainAuth:()=>authDone,clearClient:()=>{client=null},flushPreferences:async()=>{await credentials?.queue}});
async function requestQuit(){
 if(shuttingDown)return;shuttingDown=true;
 const errors=await shutdown.run();if(errors.length)dialog.showErrorBox('退出清理提示',errors.join('\n'));
 quitting=true;app.quit();
}
async function chooseClose(settingsOnly=false){
 if(prompting||shuttingDown)return;prompting=true;
 try{
  const preference=await closePreferences().read();let choice=preference;
  if(!choice||settingsOnly){const result=await dialog.showMessageBox(win,{type:'question',title:'关闭方式',message:'关闭窗口时如何处理？',detail:'退出程序将断开 VPN 并注销认证；最小化将保持连接。',buttons:['退出程序','最小化','取消'],defaultId:1,cancelId:2,checkboxLabel:'记住此选择',checkboxChecked:!!preference});
   if(result.response===2)return;choice=result.response===0?'quit':'minimize';
   try{await closePreferences().save(result.checkboxChecked?choice:'')}catch{dialog.showErrorBox('设置未保存','此次选择会生效，下次关闭时仍会询问。')}
  }
  if(!settingsOnly){if(choice==='minimize')win?.minimize();else void requestQuit()}
 }finally{prompting=false}
}
async function getCatalog(port){
 if(!client?.authenticated||!client.twfid)throw Error('请先完成账号认证。');
 if(!Number.isInteger(port)||port<1||port>65535)throw Error('隧道端口无效。');
 const owner=client,origin=new URL('https://'+owner.base.hostname+':'+port+'/').origin;
 if(catalog&&catalogOwner===owner&&catalog.transport.base.origin===origin)return catalog;
 await closeResources();if(shuttingDown||client!==owner||!owner.authenticated)throw Error('登录会话已变更。');
 const tls=require('node:tls');const ca=process.platform==='darwin'&&tls.getCACertificates?[...tls.getCACertificates('default'),...tls.getCACertificates('system')]:undefined;
 const transport=new AuthClient(origin,ca?{tlsCA:ca}:{});transport.jar=owner.jar;transport.twfid=owner.twfid;
 catalogOwner=owner;catalog=new ResourceCatalog(transport);return catalog;
}

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
    win.on('close',event=>{if(!quitting){event.preventDefault();if(!shuttingDown)void chooseClose().catch(()=>{if(!shuttingDown)dialog.showErrorBox('关闭方式不可用','请使用退出程序按钮关闭应用。')})}});
    win.on('closed',()=>{win=null});
  });
  ipcMain.handle('auth:call', async (event, {action, data} = {}) => {
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    if (shuttingDown) return {ok:false,error:'程序正在退出。'};
    if (busy) return {ok: false, error: '上一项操作尚未结束。'};
    busy = true;let finishAuth;authDone=new Promise(resolve=>{finishAuth=resolve});
    try {
      let value;
      switch (action) {
        case 'initialize': { const server = await new Preferences(app.getPath('userData')).saveServer(data?.server); await closeResources();await vpn.stop();if(shuttingDown)throw Error('程序正在退出。');client?.close(); client = new AuthClient(server); value = await client.initialize(); break; }
        case 'captcha': if (!client) throw new Error('请先连接服务器。'); value = {captchaImage: await client.captcha()}; break;
        case 'login': {
          if (!client) throw new Error('请先连接服务器。');
          let memoryWarning='';
          try {await accounts().save(client.base.origin,{username:data?.username,rememberPassword:data?.rememberPassword===true,password:data?.rememberPassword===true?data?.password:undefined})}
          catch {try{await accounts().save(client.base.origin,{username:data?.username,rememberPassword:false})}catch{};memoryWarning='账号记忆设置未能保存，本次认证继续进行。'}
          value=await client.login(data||{});if(memoryWarning)value.memoryWarning=memoryWarning;break;
        }
        case 'challenge': if (!client) throw new Error('请先连接服务器。'); value = await client.submitChallenge(data?.value); break;
        case 'logout': {
          let failure;try{await closeResources()}catch(error){failure=error}
          try{await vpn.stop()}catch(error){failure=error}
          try{value=client?await client.logout():{phase:'idle'}}finally{client?.close();client=null}
          if(failure)throw failure;break;
        }
        default: throw new Error('操作无效。');
      }
      return {ok: true, value};
    } catch (error) { return {ok: false, error: error.message || '请求失败。'}; }
    finally { busy = false;finishAuth(); }
  });
  ipcMain.handle('preferences:account', async (event,{action,server,data}={})=>{
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    try{if(action==='read')return {ok:true,value:await accounts().read(server)};
     if(action==='save'){await accounts().save(server,{username:data?.username,rememberPassword:data?.rememberPassword===true});return {ok:true}}
     throw Error('操作无效。');
    }catch{return {ok:false,error:'账号记忆设置未能保存，请重试。'}}
  });
  ipcMain.handle('preferences:server', async event => {
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    return {ok: true, value: {server: await new Preferences(app.getPath('userData')).readServer(), recoveryRequired: await recoveryPending()}};
  });
  ipcMain.handle('vpn:call', async (event, {action, data} = {}) => {
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    if(shuttingDown&&action!=='status')return {ok:false,error:'程序正在退出。'};
    if (action === 'recover') {
      if (busy || vpn.active) return {ok:false,error:'请先结束当前操作或断开 VPN。'};
      busy=true;try {await recoverTun(vpn.helperPath);return {ok:true,value:{recovered:true}};}catch(error){return {ok:false,error:error.message};}finally{busy=false;}
    }
    if(shuttingDown&&action!=='status')return {ok:false,error:'程序正在退出。'};
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
  ipcMain.handle('resources:call',async(event,{action,data}={})=>{
    if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('请求来源无效。');
    if(shuttingDown||busy)return {ok:false,error:'请等待当前操作结束。'};
    try{
     if(action==='list'){const current=await getCatalog(data?.tunnelPort);const value=await current.refresh();if(catalog!==current||!client?.authenticated)throw Error('登录会话已变更。');return {ok:true,value}}
     if(action==='open'){if(!catalog||catalogOwner!==client||!client?.authenticated)throw Error('请先刷新资源列表。');const current=catalog,owner=client;
      const value=await resourceBrowser.open(current,data?.key,Number(data?.index??0),{tunnelConnected:vpn.status.state==='connected'&&vpn.status.mode==='tun',isCurrent:()=>!shuttingDown&&catalog===current&&client===owner&&owner.authenticated});return {ok:true,value}}
     if(action==='close-settings'){await chooseClose(true);return {ok:true}}
     if(action==='quit'){void requestQuit();return {ok:true}}
     throw Error('操作无效。');
    }catch(error){return {ok:false,error:error.message||'资源操作失败。'}}
  });
  app.on('activate',()=>{if(win){if(win.isMinimized())win.restore();win.show();win.focus()}});
  app.on('before-quit',event=>{if(!quitting){event.preventDefault();void requestQuit()}});
  app.on('window-all-closed',()=>{if(!quitting)void requestQuit()});
}
