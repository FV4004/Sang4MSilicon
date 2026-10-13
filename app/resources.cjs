'use strict';
const {XMLParser,XMLValidator}=require('fast-xml-parser');
const parser=new XMLParser({ignoreAttributes:false,attributeNamePrefix:'',parseTagValue:false,parseAttributeValue:false,processEntities:true,trimValues:true});
const array=x=>x===undefined||x===null?[]:Array.isArray(x)?x:[x];
const text=(x,max=512)=>typeof x==='string'||typeof x==='number'?String(x).slice(0,max):'';
function webURL(input,service='http',port){
 if(typeof input!=='string')return null;input=input.trim();
 if(!input||input.length>4096||/[\x00-\x1f\x7f\\]/.test(input)||input.includes('~')||input.includes('*'))return null;
 try{const explicit=/^[a-z][a-z0-9+.-]*:\/\//i.test(input);if(!explicit&&/^(?:javascript|data|file|mailto|ftp):/i.test(input))return null;
 const u=new URL(explicit?input:`${service==='https'?'https':'http'}://${input}`);if(!['http:','https:'].includes(u.protocol)||u.username||u.password||!u.hostname)return null;if(port&&!u.port)u.port=String(port);return u.href}catch{return null}
}
function proxyPath(target,disguise=false){
 const u=new URL(target);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw Error('资源地址无效。');
 const ext=u.pathname.toLowerCase(),filter=ext.endsWith('.css')?2:ext.endsWith('.js')?3:ext.endsWith('.vbs')?4:1;
 return `${disguise?'/safeurl':''}/web/${filter}/${u.protocol.slice(0,-1)}/0/${u.host}${u.pathname}${u.search}${u.hash}`;
}
function parseResources(body){
 const xml=Buffer.isBuffer(body)?body.toString('utf8'):String(body);
 if(Buffer.byteLength(xml)>2*1024*1024||/<!DOCTYPE|<!ENTITY/i.test(xml)||XMLValidator.validate(xml)!==true)throw Error('网关资源列表格式无效。');
 const doc=parser.parse(xml),root=doc.Resource;if(!root||typeof root!=='object')throw Error('网关未返回资源列表，请重新登录。');
 const groups=new Map();for(const g of array(root.RcGroups?.Group)){const id=text(g.id,64);groups.set(id,{id,name:text(g.name,256)||'未命名分组',items:[]})}
 const items=new Map();let ordinal=0;
 const ssoIDs=new Set(array(root.WebSsoInfos?.webssoinfo).map(x=>text(x.rcid,64)));
 for(const rc of array(root.Rcs?.Rc)){
  if(!rc||typeof rc!=='object'||(Number(rc.attr||0)&1))continue;
  const type=Number(rc.type);if(![0,1,2].includes(type))continue;
  if(items.size>=20000)throw Error('资源列表过大，请联系网关管理员。');
  const key='resource-'+(++ordinal),groupId=text(rc.rc_grp_id,64)||'ungrouped';
  if(!groups.has(groupId))groups.set(groupId,{id:groupId,name:'未分组资源',items:[]});
  const service=text(rc.svc,128).toLowerCase();const hosts=text(rc.host,4096).split(';').filter(Boolean),ports=text(rc.port,4096).split(';');
  const sso=ssoIDs.has(text(rc.id,64))||!!text(rc.sso_type,32)&&Number(rc.sso_type)!==0||array(root.Sso?.data?.split?.(';')).some(x=>String(x).split(':')[0]===String(rc.id));
  const supportedService=service==='http'||service==='https'||type===0&&!service;
  const targets=[];
  for(let i=0;i<hosts.length;i++){
   const range=ports[i]||ports[0]||'',parts=range.split('~');let port;
   const original=supportedService?webURL(hosts[i],service):null;if(!original)continue;
   if(type!==0&&range){const min=Number(parts[0]),max=Number(parts[1]??parts[0]);if(!Number.isInteger(min)||!Number.isInteger(max)||min<0||max>65535||min>max)continue;
    const parsed=new URL(original),preferred=parsed.protocol==='https:'?443:80;
    if(parsed.port){const explicit=Number(parsed.port);if(explicit<min||explicit>max)continue}
    else if(min===max&&min>0)port=min;else if(min<=preferred&&preferred<=max)port=preferred;else continue;
   }
   const url=webURL(hosts[i],service,port);
   if(url&&!sso&&!['remoteapp','terminal service'].includes(service))targets.push({index:i,url});
  }
  const displayHosts=hosts.map(host=>{try{const u=new URL(host);if(['http:','https:'].includes(u.protocol))return u.host}catch{}return host.split(/[?#]/)[0]});
  const item={key,name:text(rc.name,256)||'未命名资源',type,service,hosts:displayHosts,ports:ports.filter(Boolean),groupId,kind:type===0?'gateway':'direct',targets:targets.map(t=>({index:t.index,label:displayHosts[t.index]})),reason:sso?'需要单点登录，本版暂不支持':!supportedService?'该资源仅展示地址与端口':targets.length?'':'地址范围或地址格式不支持直接打开'};
  items.set(key,{...item,targets,disguise:Number(rc.enable_disguise)===1});groups.get(groupId).items.push(item);
 }
 return {groups:[...groups.values()].filter(g=>g.items.length),items};
}
class ResourceCatalog{
 constructor(transport){this.transport=transport;this.groups=[];this.items=new Map();this.closed=false;this.generation=0}
 async refresh(){const g=++this.generation;const r=await this.transport.request('/por/rclist.csp',{headers:{TWFID:this.transport.twfid,Cookie:'TWFID='+this.transport.twfid}});if(this.closed||g!==this.generation)throw Error('资源加载已取消。');const parsed=parseResources(r.body);this.groups=parsed.groups;this.items=parsed.items;return {groups:this.groups,count:this.items.size}}
 target(key,index=0){if(this.closed)throw Error('资源会话已关闭。');const item=this.items.get(key);const target=item?.targets.find(t=>t.index===index);if(!target)throw Error('该资源不能直接打开，请检查地址和资源类型。');return {kind:item.kind,name:item.name,url:target.url,path:item.kind==='gateway'?proxyPath(target.url,item.disguise):null}}
 close(){this.closed=true;this.generation++;this.groups=[];this.items.clear();this.transport.close()}
}
module.exports={ResourceCatalog,parseResources,proxyPath,webURL};
