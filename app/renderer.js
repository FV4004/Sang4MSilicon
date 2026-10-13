'use strict';
const $ = id => document.getElementById(id);
let phase = 'idle', busy = false, preparedServer = '', required = false;
function message(text, kind = '') { $('feedback').textContent = text; $('feedback').className = 'feedback ' + kind; }
function controls() {
  $('prepare').disabled = busy || phase === 'authenticated';
  $('server').disabled = busy || ['challenge', 'unsupported', 'authenticated'].includes(phase);
  for (const id of ['username', 'password', 'captcha']) $(id).disabled = busy || phase === 'authenticated' || phase === 'challenge';
  $('refresh').disabled = busy || phase !== 'ready';
  $('submit').disabled = busy || !['ready', 'challenge'].includes(phase);
  $('submit').textContent = busy ? '正在处理…' : phase === 'challenge' ? '提交后续认证' : '登录';
  $('challenge').disabled = busy;
  $('challenge-area').hidden = phase !== 'challenge';
  $('logout').hidden = !['authenticated', 'challenge', 'unsupported'].includes(phase);
  $('logout').disabled = busy;
  $('badge').textContent = phase === 'authenticated' ? '认证成功' : phase === 'challenge' ? '待进一步认证' : '未认证';
  $('badge').className = 'badge' + (phase === 'authenticated' ? ' success' : '');
}
async function operation(fn) {
  if (busy) return; busy = true; controls();
  try { await fn(); } catch (e) { message(e.message || '操作失败，请重试。', 'error'); }
  finally { busy = false; controls(); }
}
function unpack(r) { if (!r.ok) throw new Error(r.error); return r.value; }
async function prepare() {
  $('captcha-image').removeAttribute('src'); $('captcha-area').hidden = true; $('captcha').value = '';
  phase = 'idle'; $('password').required = true; $('captcha').required = false; message('正在读取服务器登录配置…');
  const r = unpack(await window.vpnAuth.initialize($('server').value));
  preparedServer = $('server').value.trim(); required = r.captchaRequired;
  $('captcha-area').hidden = !required; $('captcha').required = required;
  if (r.captchaImage) $('captcha-image').src = r.captchaImage;
  phase = 'ready'; message(required ? '已获取验证码，请输入账号和图片中的字符。' : '该服务器当前不要求图片验证码，可以提交登录。');
}
$('prepare').addEventListener('click', () => operation(prepare));
$('refresh').addEventListener('click', () => operation(async () => {
  const r = unpack(await window.vpnAuth.captcha()); $('captcha-image').src = r.captchaImage; $('captcha').value = ''; message('验证码已刷新。');
}));
$('server').addEventListener('input', () => { phase = 'idle'; $('captcha-area').hidden = true; $('captcha-image').removeAttribute('src'); controls(); });
$('login-form').addEventListener('submit', e => {
  e.preventDefault(); operation(async () => {
    let r;
    if (phase === 'challenge') r = unpack(await window.vpnAuth.challenge($('challenge').value));
    else {
      if ($('server').value.trim() !== preparedServer) throw new Error('服务器地址已变更，请重新获取验证码。');
      const password = $('password').value;
      try { r = unpack(await window.vpnAuth.login({username: $('username').value, password, captcha: $('captcha').value})); }
      catch (err) { phase = 'idle'; $('captcha-area').hidden = true; throw err; }
      finally { $('password').value = ''; }
    }
    phase = r.phase; $('challenge').value = '';
    if (phase === 'challenge') { $('captcha-area').hidden = true; $('captcha').required = false; $('password').required = false; $('challenge-name').textContent = r.nextService; }
    message(r.message, phase === 'authenticated' ? 'success' : phase === 'unsupported' ? 'error' : '');
  });
});
$('logout').addEventListener('click', () => operation(async () => {
  unpack(await window.vpnAuth.logout()); phase = 'idle'; $('password').required = true; $('captcha').required = false; $('captcha-area').hidden = true; $('captcha-image').removeAttribute('src'); $('password').value = ''; message('登录会话已清除。');
}));
controls();
