'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),{randomBytes}=require('node:crypto');
class ClosePreferences{
 constructor(directory){this.directory=directory;this.file=path.join(directory,'window.json')}
 async read(){try{const s=await fs.lstat(this.file);if(!s.isFile()||s.isSymbolicLink()||s.size>1024)return '';const choice=JSON.parse(await fs.readFile(this.file,'utf8')).closeAction;return ['quit','minimize'].includes(choice)?choice:''}catch{return ''}}
 async save(choice){if(!['','quit','minimize'].includes(choice))throw Error('关闭选项无效。');await fs.mkdir(this.directory,{recursive:true,mode:0o700});const temp=path.join(this.directory,'.window-'+randomBytes(16).toString('hex'));try{await fs.writeFile(temp,JSON.stringify({closeAction:choice})+'\n',{flag:'wx',mode:0o600});await fs.rename(temp,this.file)}finally{await fs.rm(temp,{force:true})}}
}
class Shutdown{
 constructor({stopVPN,getClient,closeResources,drainAuth,clearClient,flushPreferences}){Object.assign(this,{stopVPN,getClient,closeResources,drainAuth,clearClient,flushPreferences});this.promise=null;this.running=false}
 run(){if(this.promise)return this.promise;this.running=true;this.promise=this.execute();return this.promise}
 async execute(){const errors=[];const current=this.getClient();current?.cancelPending?.();try{await this.closeResources()}catch{errors.push('资源浏览窗口未能完整清理。')}
  try{await this.stopVPN()}catch{errors.push('TUN 路由与 DNS 恢复未能确认；再次启动后请恢复网络配置。')}
  try{await this.drainAuth()}catch{errors.push('未能确认进行中的认证操作已结束。')}const client=this.getClient();
  try{if(client)await client.logout()}catch{errors.push('网关注销未能确认，本地认证会话已清理。')}
  finally{client?.close();this.clearClient()}
  try{await this.flushPreferences()}catch{errors.push('偏好设置未能完整保存。')}
  return errors;
 }
}
module.exports={ClosePreferences,Shutdown};
