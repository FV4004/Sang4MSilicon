'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const script = fs.readFileSync(path.join(__dirname, '../app/renderer.js'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
function page({saved = '', login = {ok: false, error: '认证失败（20004）'}, initialize} = {}) {
  const elements = new Map();
  function get(id) { if (!elements.has(id)) elements.set(id, {value: id === 'vpn-mode' ? 'tun' : '', hidden: false, disabled: false, textContent: '', className: '', required: false, classList: {toggle() {}}, listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; }, removeAttribute(name) { delete this[name]; }}); return elements.get(id); }
  const calls = {initialize: [], login: []};
  const api = {readSavedServer: async () => ({ok: true, value: {server: saved}}), initialize: async value => { calls.initialize.push(value); return initialize || {ok: true, value: {server: value, captchaRequired: true, captchaImage: 'data:image/png;base64,real'}}; }, login: async value => { calls.login.push(value); return login; }, onVpnStatus() {}, vpnStatus: async () => ({ok: true, value: {state: 'disconnected'}}), logout: async () => ({ok: true}), captcha: async () => ({ok: true, value: {captchaImage: 'data:image/png;base64,refresh'}})};
  vm.runInNewContext(script, {document: {getElementById: get, querySelector: () => ({classList: {toggle() {}}})}, window: {vpnAuth: api}, URL});
  return {get, calls, api};
}
test('saved valid server auto-fetches real captcha after password; blank server makes no request', async () => {
  const x = page({saved: 'https://vpn.example.com'}); await tick(); await tick();
  assert.equal(x.get('server').value, 'https://vpn.example.com'); assert.deepEqual(x.calls.initialize, ['https://vpn.example.com']); assert.equal(x.get('captcha-image').src, 'data:image/png;base64,real');
  const empty = page(); await tick(); assert.equal(empty.calls.initialize.length, 0);
  const html = fs.readFileSync(path.join(__dirname, '../app/index.html'), 'utf8'); assert.ok(html.indexOf('id="prepare"') > html.indexOf('id="password"')); assert.ok(html.indexOf('id="prepare"') < html.indexOf('id="captcha-area"'));
});
test('blur prepares changed valid address; initialization failure allows retry without fake captcha', async () => {
  const x = page({initialize: {ok: false, error: '连接超时'}}); await tick(); x.get('server').value = 'http://vpn.example.com:8080';
  x.get('server').listeners.blur(); await tick(); await tick();
  assert.equal(x.get('prepare').disabled, false); assert.equal(x.get('captcha-image').src, undefined); assert.equal(x.get('captcha-area').hidden, true);
  await x.get('prepare').listeners.click(); assert.equal(x.calls.initialize.length, 2);
  x.get('server').value = 'https://user:secret@vpn.example.com'; x.get('server').listeners.blur(); await tick(); assert.equal(x.calls.initialize.length, 2);
});
test('authentication rejection preserves username/password and retry captcha does not erase them', async () => {
  const x = page({saved: 'http://vpn.example.com'}); await tick(); await tick(); x.get('username').value = 'account'; x.get('password').value = 'keep-secret'; x.get('captcha').value = 'ABCD';
  x.get('login-form').listeners.submit({preventDefault() {}}); await tick(); await tick();
  assert.equal(x.get('username').value, 'account'); assert.equal(x.get('password').value, 'keep-secret'); assert.match(x.get('feedback').textContent, /20004/);
  await x.get('prepare').listeners.click(); assert.equal(x.get('password').value, 'keep-secret');
});
test('successful final authentication and explicit logout erase password only in memory', async () => {
  const x = page({saved: 'https://vpn.example.com', login: {ok: true, value: {phase: 'authenticated', message: 'OK'}}}); await tick(); await tick();
  x.get('username').value = 'account'; x.get('password').value = 'temporary'; x.get('login-form').listeners.submit({preventDefault() {}}); await tick(); await tick(); assert.equal(x.get('password').value, ''); assert.equal(x.get('username').value, 'account');
  x.get('password').value = 'logout-secret'; await x.get('logout').listeners.click(); assert.equal(x.get('password').value, '');
});
test('gateway without captcha can still authenticate', async () => {
  const x = page({saved: 'https://vpn.example.com', initialize: {ok: true, value: {server: 'https://vpn.example.com', captchaRequired: false}}}); await tick(); await tick();
  assert.equal(x.get('captcha-area').hidden, true); assert.equal(x.get('captcha').required, false); assert.equal(x.get('submit').disabled, false);
});
