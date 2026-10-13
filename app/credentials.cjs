'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),{randomBytes}=require('node:crypto');
const {serverURL}=require('./auth.cjs');
class Credentials {
 constructor(directory,secure){this.directory=directory;this.file=path.join(directory,'account.json');this.secure=secure;this.queue=Promise.resolve()}
 available(){try{return !!this.secure?.isEncryptionAvailable()&&!(process.platform==='linux'&&this.secure.getSelectedStorageBackend?.()==='basic_text')}catch{return false}}
 async record(){try{const stat=await fs.lstat(this.file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>65536)return null;const r=JSON.parse(await fs.readFile(this.file,'utf8'));if(serverURL(r.server).origin!==r.server||typeof r.username!=='string'||r.username.length>256||/[\x00-\x1f]/.test(r.username))return null;return r}catch{return null}}
 async read(server){const origin=serverURL(server).origin,available=this.available();const r=await this.record();const out={username:'',password:'',rememberPassword:false,canRememberPassword:available};if(!r||r.server!==origin)return out;out.username=r.username;out.rememberPassword=r.rememberPassword===true&&available;if(out.rememberPassword&&typeof r.encryptedPassword==='string'){try{const stored=JSON.parse(this.secure.decryptString(Buffer.from(r.encryptedPassword,'base64')));if(stored.server===origin&&stored.username===r.username&&typeof stored.password==='string'&&stored.password.length<=4096)out.password=stored.password}catch{out.password=''}}return out}
 save(server,{username='',rememberPassword=false,password}={}){
  const task=this.queue.then(()=>this.write(server,{username,rememberPassword,password}));this.queue=task.catch(()=>{});return task;
 }
 async write(server,{username,rememberPassword,password}){
  const origin=serverURL(server).origin;
  if(typeof username!=='string'||username.length>256||/[\x00-\x1f]/.test(username))throw Error('用户 ID 无效。');
  const old=await this.record(),next={server:origin,username,rememberPassword:rememberPassword===true};
  if(next.rememberPassword&&typeof password==='string'){
   if(!password||password.length>4096||!this.available())throw Error('系统安全存储不可用，密码未记忆。');
   next.encryptedPassword=this.secure.encryptString(JSON.stringify({server:origin,username,password})).toString('base64');
  }else if(next.rememberPassword&&old?.server===origin&&old.username===username&&typeof old.encryptedPassword==='string')next.encryptedPassword=old.encryptedPassword;
  await fs.mkdir(this.directory,{recursive:true,mode:0o700});const temporary=path.join(this.directory,'.account-'+randomBytes(16).toString('hex'));
  try{await fs.writeFile(temporary,JSON.stringify(next)+'\n',{flag:'wx',mode:0o600});await fs.rename(temporary,this.file)}finally{await fs.rm(temporary,{force:true})}
 }
}
module.exports={Credentials};
