'use strict';
const {randomBytes}=require('node:crypto');
class ResourceBrowser{
 constructor({BrowserWindow,session,openExternal}){Object.assign(this,{BrowserWindow,session,openExternal});this.windows=new Set();this.browserSession=null;this.generation=0}
 async open(catalog,key,index,{tunnelConnected,isCurrent}){
  const g=this.generation,target=catalog.target(key,index);
  if(target.kind==='direct'){if(!tunnelConnected)throw Error('请先连接系统 TUN，再打开内网资源。');if(!isCurrent())throw Error('登录会话已变更。');await this.openExternal(target.url);return {opened:true,kind:'direct'}}
  if(!this.browserSession)this.browserSession=this.session.fromPartition('mchip-resource-'+randomBytes(16).toString('hex'),{cache:false});
  const state=this.browserSession,origin=catalog.transport.base.origin;
  state.webRequest?.onBeforeSendHeaders((details,callback)=>{const headers={...details.requestHeaders};for(const key of Object.keys(headers)){if(key.toLowerCase()==='referer'&&/[?&]twfid=/i.test(headers[key]))delete headers[key]}callback({requestHeaders:headers})});
  const cookies=await catalog.transport.jar.getCookies(origin+'/');
  for(const cookie of cookies){if(cookie.key==='TWFID')continue;await state.cookies.set({url:origin,name:cookie.key,value:cookie.value,path:cookie.path||'/',httpOnly:!!cookie.httpOnly,secure:!!cookie.secure})}
  await state.cookies.set({url:origin,name:'TWFID',value:catalog.transport.twfid,path:'/',httpOnly:true,secure:true});
  if(g!==this.generation||!isCurrent())throw Error('登录会话已变更。');
  const win=new this.BrowserWindow({width:1100,height:780,title:target.name+' · 内网资源',webPreferences:{session:state,contextIsolation:true,nodeIntegration:false,sandbox:true}});
  if(this.windows.size>=16){win.destroy();throw Error('资源窗口数量已达上限，请先关闭部分窗口。')}
  // No privileged preload is attached. External protocols cannot invoke local programs.
  const safe=url=>{try{const u=new URL(url);return ['http:','https:'].includes(u.protocol)&&!u.username&&!u.password}catch{return false}};
  const attach=window=>{
   this.windows.add(window);window.removeMenu();window.on('closed',()=>this.windows.delete(window));
   window.webContents.setWindowOpenHandler(({url})=>safe(url)&&this.windows.size<16?{action:'allow',overrideBrowserWindowOptions:{title:'内网资源',webPreferences:{session:state,contextIsolation:true,nodeIntegration:false,sandbox:true}}}:{action:'deny'});
   window.webContents.on('did-create-window',child=>attach(child));
   window.webContents.on('will-navigate',(event,url)=>{if(!safe(url))event.preventDefault()});window.webContents.on('will-redirect',(event,url)=>{if(!safe(url))event.preventDefault()});
  };attach(win);
  const start=new URL('/portal/shortcut.html',origin);start.searchParams.set('twfid',catalog.transport.twfid);start.searchParams.set('url',target.path);start.searchParams.set('lang','zh_CN');
  try{await win.loadURL(start.href)}catch{if(!win.isDestroyed())win.destroy();throw Error('网关 Web 资源加载失败，请检查会话和网关策略。')}
  if(g!==this.generation||!isCurrent()){if(!win.isDestroyed())win.destroy();throw Error('资源打开已取消。')}
  return {opened:true,kind:'gateway'};
 }
 async close(){this.generation++;for(const w of this.windows)if(!w.isDestroyed())w.destroy();this.windows.clear();const state=this.browserSession;this.browserSession=null;if(state){const r=await Promise.allSettled([state.clearStorageData(),state.clearCache()]);if(r.some(x=>x.status==='rejected'))throw Error('资源浏览会话清理失败。')}}
}
module.exports={ResourceBrowser};
