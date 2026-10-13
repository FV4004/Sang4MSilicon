'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),{EventEmitter}=require('node:events'),{pathToFileURL}=require('node:url');
const tick=()=>new Promise(r=>setImmediate(r));
test('first close offers remembered minimize; explicit quit stops VPN and revokes login',async t=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'close-integration-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));const handlers=new Map(),events=new Map(),calls=[];let window,quits=0,prompts=0;
 const appDirectory=path.resolve(__dirname,'../app');
 class Win{constructor(){window=this;this.events=new Map();this.minimized=0;this.webContents={mainFrame:{url:pathToFileURL(path.join(appDirectory,'index.html')).href},on(){},setWindowOpenHandler(){},send(){}}}on(n,f){this.events.set(n,f)}removeMenu(){}loadFile(){}minimize(){this.minimized++}}
 class Vpn extends EventEmitter{constructor(){super();this.status={state:'disconnected'}}async stop(){calls.push('stop-vpn')}}
 class Auth{constructor(server){this.base=new URL(server);this.twfid='session';this.authenticated=true}async initialize(){return {}}cancelPending(){calls.push('cancel-auth')}async logout(){calls.push('logout')}close(){calls.push('clear-auth')}}
 class Browser{async close(){calls.push('close-resources')}}
 const electron={app:{isPackaged:false,setName(){},requestSingleInstanceLock:()=>true,whenReady:async()=>{},on:(n,f)=>events.set(n,f),getPath:()=>dir,quit(){quits++}},BrowserWindow:Win,ipcMain:{handle:(n,f)=>handlers.set(n,f)},shell:{},dialog:{async showMessageBox(){prompts++;return {response:1,checkboxChecked:true}},showErrorBox(){throw Error('unexpected cleanup failure')}},safeStorage:{isEncryptionAvailable:()=>false}};
 vm.runInNewContext(await fs.readFile(path.join(appDirectory,'main.cjs'),'utf8'),{__dirname:appDirectory,require(n){if(n==='electron')return electron;if(n==='./vpn.cjs')return {VpnSupervisor:Vpn};if(n==='./auth.cjs')return {AuthClient:Auth};if(n==='./resource-browser.cjs')return {ResourceBrowser:Browser};if(n==='./tun-launcher.cjs')return {spawnTun(){},recoveryPending:async()=>false};if(n.startsWith('./'))return require(path.join(appDirectory,n));return require(n)}});await tick();
 const origin={sender:window.webContents,senderFrame:window.webContents.mainFrame};await handlers.get('auth:call')(origin,{action:'initialize',data:{server:'http://vpn.example.com'}});calls.length=0;
 let prevented=0;window.events.get('close')({preventDefault(){prevented++}});
 for(let i=0;i<100&&window.minimized===0;i++)await new Promise(resolve=>setTimeout(resolve,5));assert.equal(window.minimized,1);assert.equal(prompts,1);assert.equal(quits,0);assert.deepEqual(calls,[]);
 window.events.get('close')({preventDefault(){prevented++}});for(let i=0;i<100&&window.minimized<2;i++)await new Promise(resolve=>setTimeout(resolve,5));assert.equal(window.minimized,2);assert.equal(prompts,1);
 events.get('before-quit')({preventDefault(){prevented++}});for(let i=0;i<100&&quits===0;i++)await new Promise(resolve=>setTimeout(resolve,5));assert.equal(quits,1);assert.ok(calls.indexOf('stop-vpn')<calls.indexOf('logout'));assert.ok(calls.includes('clear-auth'));assert.equal(prevented,3);
});
