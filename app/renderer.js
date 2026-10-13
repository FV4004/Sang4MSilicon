'use strict';
const $ = id => document.getElementById(id);
let accountOrigin='',accountRequest=0,canRememberPassword=true,autoFilledPassword=false;
let recoveryPending = false;
let phase = 'idle', busy = false, preparedServer = '', required = false, vpnState = {state: 'disconnected'};
function message(text, kind = '') { $('feedback').textContent = text; $('feedback').className = 'feedback ' + kind; }
function controls() {
  $('remember-password').disabled=busy||phase==='authenticated'||!canRememberPassword;
  $('recover-network').hidden = !recoveryPending && vpnState.code !== 'CLEANUP_FAILED';
  $('recover-network').disabled = busy;
  $('login-form').hidden = phase === 'authenticated';
  $('panel-title').textContent = phase === 'authenticated' ? '连接你的网络' : '登录 VPN 网关';
  $('transport-notice').hidden = phase === 'authenticated' || !/^http:\/\//i.test($('server').value.trim());
  $('prepare').disabled = busy || recoveryPending || phase === 'authenticated';
  $('server').disabled = busy || ['challenge', 'unsupported', 'authenticated'].includes(phase);
  for (const id of ['username', 'password', 'captcha']) $(id).disabled = busy || phase === 'authenticated' || phase === 'challenge';
  $('refresh').disabled = busy || phase !== 'ready';
  $('submit').disabled = busy || recoveryPending || !['ready', 'challenge'].includes(phase);
  $('submit').textContent = busy ? '正在处理…' : phase === 'challenge' ? '提交后续认证' : '登录';
  $('challenge').disabled = busy;
  $('challenge-area').hidden = phase !== 'challenge';
  $('logout').hidden = !['authenticated', 'challenge', 'unsupported'].includes(phase);
  $('logout').disabled = busy;
  $('badge').textContent = phase === 'authenticated' ? '认证成功' : phase === 'challenge' ? '待进一步认证' : '未认证';
  $('badge').className = 'badge' + (phase === 'authenticated' ? ' success' : '');
  $('vpn-area').hidden = phase !== 'authenticated';
  const vpnActive = ['connecting', 'connected', 'stopping', 'error'].includes(vpnState.state);
  $('vpn-connect').disabled = busy || vpnActive || phase !== 'authenticated';
  $('vpn-connect').hidden = vpnActive;
  $('vpn-disconnect').hidden = !vpnActive;
  $('vpn-disconnect').disabled = vpnState.state === 'stopping';
  const tun = $('vpn-mode').value === 'tun';
  $('vpn-mode').disabled = busy || vpnActive;
  $('tun-notice').hidden = !tun;
  $('socks-port-area').hidden = tun; $('http-port-area').hidden = tun;
  document.querySelector('.port-grid').classList.toggle('tun', tun);
  $('mode-hint').textContent = tun ? 'TUN 模式无需单独配置应用代理；断开后恢复本次添加的路由与内网 DNS。' : '当前为本地代理模式，不修改系统路由。仅使用代理的应用流量进入 VPN；SOCKS5 暂不支持 UDP。';
  const connectedTun = vpnState.mode === 'tun';
  for (const id of ['socks-label', 'vpn-socks', 'http-label', 'vpn-http']) $(id).hidden = connectedTun;
  for (const id of ['interface-label', 'vpn-interface', 'route-label', 'vpn-routes', 'dns-label', 'vpn-dns']) $(id).hidden = !connectedTun;
  for (const id of ['tunnel-port', 'socks-port', 'http-port']) $(id).disabled = busy || vpnActive;
  $('vpn-addresses').hidden = vpnState.state !== 'connected';
  $('vpn-badge').textContent = ({connecting: '正在连接', connected: '已连接', stopping: '正在断开', error: '连接失败'})[vpnState.state] || '未连接';
  $('vpn-badge').className = 'badge' + (vpnState.state === 'connected' ? ' success' : '');
}
async function operation(fn) {
  if (busy) return; busy = true; controls();
  try { await fn(); } catch (e) { message(e.message || '操作失败，请重试。', 'error'); }
  finally { busy = false; controls(); }
}
function unpack(r) { if (!r.ok) throw new Error(r.error); return r.value; }
async function prepare() {
  await loadAccount($('server').value);
  $('captcha-image').removeAttribute('src'); $('captcha-area').hidden = true; $('captcha').value = '';
  phase = 'idle'; $('password').required = true; $('captcha').required = false; message('正在读取服务器登录配置…');
  const r = unpack(await window.vpnAuth.initialize($('server').value));
  preparedServer = $('server').value.trim(); required = r.captchaRequired;
  const address = new URL(r.server || preparedServer);
  $('tunnel-port').value = address.protocol === 'https:' && address.port ? address.port : '443';
  $('captcha-area').hidden = !required; $('captcha').required = required;
  if (r.captchaImage) $('captcha-image').src = r.captchaImage;
  phase = 'ready'; message(required ? '已获取验证码，请输入账号和图片中的字符。' : '该服务器当前不要求图片验证码，可以提交登录。');
}
$('prepare').addEventListener('click', () => operation(prepare));
$('refresh').addEventListener('click', () => operation(async () => {
  const r = unpack(await window.vpnAuth.captcha()); $('captcha-image').src = r.captchaImage; $('captcha').value = ''; message('验证码已刷新。');
}));
$('server').addEventListener('input', () => { accountRequest++;accountOrigin='';autoFilledPassword=false;$('username').value='';$('password').value='';$('remember-password').checked=false; phase = 'idle'; $('captcha-area').hidden = true; $('captcha-image').removeAttribute('src'); controls(); });
$('login-form').addEventListener('submit', e => {
  e.preventDefault(); operation(async () => {
    let r;
    if (phase === 'challenge') r = unpack(await window.vpnAuth.challenge($('challenge').value));
    else {
      if ($('server').value.trim() !== preparedServer) throw new Error('服务器地址已变更，请重新获取验证码。');
      const password = $('password').value;
      const rememberPassword=$('remember-password').checked===true;
      try { r = unpack(await window.vpnAuth.login({username: $('username').value, password, rememberPassword, captcha: $('captcha').value})); }
      catch (err) { phase = 'idle'; $('captcha-area').hidden = true; throw err; }

    }
    phase = r.phase; $('challenge').value = '';
    if (phase === 'authenticated') $('password').value = '';
    if (phase === 'challenge') { $('captcha-area').hidden = true; $('captcha').required = false; $('password').required = false; $('challenge-name').textContent = r.nextService; }
    message((phase === 'authenticated' ? '认证成功，可以连接 VPN。' : r.message)+(r.memoryWarning?' '+r.memoryWarning:''), phase === 'authenticated' ? 'success' : phase === 'unsupported' ? 'error' : '');
  });
});
$('logout').addEventListener('click', () => operation(async () => {
  $('password').value = '';
  unpack(await window.vpnAuth.logout()); phase = 'idle'; $('password').required = true; $('captcha').required = false; $('captcha-area').hidden = true; $('captcha-image').removeAttribute('src'); $('password').value = ''; message('登录会话已清除。');
}));
controls();

function updateVpn(status) {
  vpnState = status;
  const stages = {token: '正在获取隧道会话…', ip: '正在读取 VPN 资源与虚拟地址…', tunnel: '正在建立数据隧道…', routes: '正在配置内网路由与 DNS…'};
  const area = $('vpn-feedback');
  area.className = 'feedback' + (status.code || status.state === 'error' ? ' error' : status.state === 'connected' ? ' success' : '');
  area.textContent = status.message || (status.state === 'connecting' ? stages[status.stage] || '正在连接 VPN…' : status.state === 'connected' ? status.mode === 'tcp' ? 'TCP 代理已启动（按需建连）。' : status.mode === 'tun' ? '系统 TUN 已连接，内网资源可直接访问。' : 'VPN 数据隧道已建立，本地代理可用。' : status.state === 'stopping' ? '正在关闭数据隧道…' : 'VPN 已断开。');
  if(status.state==='connected'&&status.warnings?.length)area.textContent+=' '+status.warnings.join(' ');
  $('vpn-ip').textContent = status.ip || (status.mode === 'tcp' ? '按需 TCP 连接' : '—');
  $('vpn-socks').textContent = status.socksAddress || '';
  $('vpn-http').textContent = status.httpAddress || '';
  $('vpn-interface').textContent = status.interface || '';
  $('vpn-routes').textContent = status.routeCount === undefined ? '' : String(status.routeCount);
  $('vpn-dns').textContent = status.dnsCount === undefined ? '' : String(status.dnsCount);
  controls();
}
window.vpnAuth.onVpnStatus(updateVpn);
window.vpnAuth.vpnStatus().then(result => { if (result.ok) updateVpn(result.value); });
$('vpn-connect').addEventListener('click', () => operation(async () => {
  const data = {mode: $('vpn-mode').value, tunnelPort: Number($('tunnel-port').value), socksPort: Number($('socks-port').value), httpPort: Number($('http-port').value)};
  const result = await window.vpnAuth.connectVpn(data);
  if (!result.ok) { $('vpn-feedback').textContent = result.error; $('vpn-feedback').className = 'feedback error'; return; }
  // Live status events own connection state, including exits racing this response.
}));
$('vpn-disconnect').addEventListener('click', async () => {
  try { unpack(await window.vpnAuth.disconnectVpn()); } catch (error) { $('vpn-feedback').textContent = error.message; }
});
$('licenses').addEventListener('click', () => window.vpnAuth.openLicenses());

$('vpn-mode').addEventListener('change', controls);
function canAutoPrepare(value) {
  try { const u = new URL(value); return ['http:', 'https:'].includes(u.protocol) && !!u.hostname && !u.username && !u.password && !u.search && !u.hash && u.pathname === '/'; } catch { return false; }
}
$('server').addEventListener('blur', () => {
  const value = $('server').value.trim();
  if (!busy && !recoveryPending && phase === 'idle' && canAutoPrepare(value)) void operation(prepare);
});
window.vpnAuth.readSavedServer().then(result => {
  if (!result.ok || !$('server')) return;
  recoveryPending = !!result.value.recoveryRequired;
  const value = result.value.server;
  if(recoveryPending){if(!$('server').value)$('server').value=value||'';void loadAccount($('server').value);message('上次连接未完整退出，请先恢复网络配置。','error');controls();return;}
  if ($('server').value || busy || phase !== 'idle') return;
  if (canAutoPrepare(value)) { $('server').value = value; void operation(prepare); }
}).catch(() => {});

$('recover-network').addEventListener('click',()=>operation(async()=>{
 unpack(await window.vpnAuth.recoverNetwork());recoveryPending=false;vpnState={state:'disconnected'};
 if(canAutoPrepare($('server').value.trim()))await prepare();else message('网络配置已恢复，可以重新登录。');
}));

async function loadAccount(server){
 if(!canAutoPrepare(server)||!window.vpnAuth.readSavedAccount)return;
 const origin=new URL(server).origin;if(accountOrigin===origin)return;
 const request=++accountRequest,username=$('username').value;
 let r;try{r=await window.vpnAuth.readSavedAccount(server)}catch{return}
 if(!r.ok||request!==accountRequest||!canAutoPrepare($('server').value)||new URL($('server').value).origin!==origin||phase==='authenticated')return;
 accountOrigin=origin;const saved=r.value;canRememberPassword=saved.canRememberPassword!==false;
 if($('username').value===username&&!username)$('username').value=saved.username||'';
 const sameUser=$('username').value===(saved.username||'');
 $('remember-password').checked=sameUser&&saved.rememberPassword===true&&canRememberPassword;
 if(sameUser&&!$('password').value&&saved.password){$('password').value=saved.password;autoFilledPassword=true}
 $('memory-hint').textContent=canRememberPassword?'默认记忆用户 ID；密码可选加密保存。':'系统安全存储不可用，本次不记忆密码。';controls();
}
async function saveAccountSettings(){
 if(!canAutoPrepare($('server').value)||!window.vpnAuth.saveAccount)return;
 try{const r=await window.vpnAuth.saveAccount($('server').value,{username:$('username').value,rememberPassword:$('remember-password').checked===true});if(!r.ok)$('memory-hint').textContent=r.error}catch{$('memory-hint').textContent='账号记忆设置未能保存。'}
}
$('username').addEventListener('input',()=>{if(autoFilledPassword){$('password').value='';autoFilledPassword=false;$('remember-password').checked=false}});
$('username').addEventListener('blur',()=>void saveAccountSettings());
$('password').addEventListener('input',()=>{autoFilledPassword=false});
$('remember-password').addEventListener('change',()=>void saveAccountSettings());
