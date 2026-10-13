'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {Preferences} = require('../app/preferences.cjs');
async function workspace(t) { const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vpn-preferences-')); t.after(() => fs.rm(dir, {recursive: true, force: true})); return dir; }
test('only normalized server origin persists with private permissions and atomic replacement', async t => {
  const dir = await workspace(t), prefs = new Preferences(dir);
  assert.equal(await prefs.readServer(), '');
  assert.equal(await prefs.saveServer(' HTTPS://VPN.Example.com:443/ '), 'https://vpn.example.com');
  assert.deepEqual(JSON.parse(await fs.readFile(prefs.file, 'utf8')), {server: 'https://vpn.example.com'});
  assert.equal((await fs.stat(prefs.file)).mode & 0o777, 0o600);
  await prefs.saveServer('http://vpn.example.com:8080');
  assert.equal(await prefs.readServer(), 'http://vpn.example.com:8080');
  assert.deepEqual(await fs.readdir(dir), ['server.json']);
});
test('URLs containing credentials, query secrets, paths, fragments or unsupported schemes cannot persist', async t => {
  const prefs = new Preferences(await workspace(t)); await prefs.saveServer('http://vpn.example.com');
  for (const value of ['https://account:password@vpn.example.com', 'https://vpn.example.com/?session=secret', 'http://vpn.example.com/por/login', 'https://vpn.example.com/#secret', 'file:///etc/passwd', 'not a url']) await assert.rejects(prefs.saveServer(value));
  assert.equal(await prefs.readServer(), 'http://vpn.example.com');
  const raw = await fs.readFile(prefs.file, 'utf8'); assert.ok(!/account|password|secret/.test(raw));
});
test('corrupt or credential-bearing saved values and symlink preferences are ignored', async t => {
  const dir = await workspace(t), prefs = new Preferences(dir);
  for (const text of ['not json', JSON.stringify({server: 'http://user:secret@vpn.example.com'}), JSON.stringify({server: 'https://vpn.example.com?password=secret'})]) {
    await fs.writeFile(prefs.file, text); assert.equal(await prefs.readServer(), '');
  }
  await fs.rm(prefs.file); const outside = path.join(dir, 'outside'); await fs.writeFile(outside, '{"server":"http://vpn.example.com"}'); await fs.symlink(outside, prefs.file);
  assert.equal(await prefs.readServer(), ''); await prefs.saveServer('https://vpn.example.com');
  assert.equal(await fs.readFile(outside, 'utf8'), '{"server":"http://vpn.example.com"}'); assert.equal((await fs.lstat(prefs.file)).isSymbolicLink(), false);
});
test('main remembers a validated address before failed gateway initialization and rejects foreign IPC', async t => {
  const {EventEmitter} = require('node:events');
  const vm = require('node:vm');
  const {pathToFileURL} = require('node:url');
  const dir = await workspace(t), handlers = new Map(), appDirectory = path.resolve(__dirname, '../app');
  let window;
  class FakeWindow {
    constructor() { window = this; this.webContents = {mainFrame: {url: pathToFileURL(path.join(appDirectory, 'index.html')).href}, setWindowOpenHandler() {}, on() {}, send() {}}; }
    removeMenu() {} loadFile() {} on() {}
  }
  class FakeVpn extends EventEmitter { constructor() { super(); this.status = {state: 'disconnected'}; } async stop() {} }
  class FakeAuth { constructor(server) { this.base = new URL(server); } close() {} async initialize() { throw new Error('Gateway offline'); } }
  const electron = {app: {isPackaged: false, setName() {}, requestSingleInstanceLock: () => true, whenReady: async () => {}, on() {}, getPath: () => dir}, BrowserWindow: FakeWindow, ipcMain: {handle: (name, fn) => handlers.set(name, fn)}, shell: {}, dialog: {}};
  const source = await fs.readFile(path.join(appDirectory, 'main.cjs'), 'utf8');
  vm.runInNewContext(source, {__dirname: appDirectory, require(name) {
    if (name === 'electron') return electron;
    if (name === './preferences.cjs') return {Preferences};
    if (['./resources.cjs','./resource-browser.cjs','./lifecycle.cjs'].includes(name))return require('../app/'+name.slice(2));
    if (name === './credentials.cjs') return require('../app/credentials.cjs');
    if (name === './auth.cjs') return {AuthClient: FakeAuth};
    if (name === './vpn.cjs') return {VpnSupervisor: FakeVpn};
    if (name === './tun-launcher.cjs') return {spawnTun() { throw new Error('TUN must not launch during login'); }};
    return require(name);
  }});
  await new Promise(resolve => setImmediate(resolve));
  const invoke = handlers.get('auth:call'), event = {sender: window.webContents, senderFrame: window.webContents.mainFrame};
  await assert.rejects(invoke({sender: {}, senderFrame: {}}, {action: 'initialize', data: {server: 'http://untrusted.example'}}), /来源无效/);
  assert.equal(await new Preferences(dir).readServer(), '');
  const result = await invoke(event, {action: 'initialize', data: {server: 'https://vpn.example.com:8443'}});
  assert.equal(result.ok, false); assert.equal(result.error, 'Gateway offline'); assert.equal(await new Preferences(dir).readServer(), 'https://vpn.example.com:8443');
  const accountHandler=handlers.get('preferences:account');
  await assert.rejects(accountHandler({sender:{},senderFrame:{}},{action:'read',server:'https://vpn.example.com'}),/来源无效/);
  assert.equal((await accountHandler(event,{action:'save',server:'https://vpn.example.com',data:{username:'remembered-id',rememberPassword:false}})).ok,true);
  assert.equal((await accountHandler(event,{action:'read',server:'https://vpn.example.com'})).value.username,'remembered-id');
  const invalid = await invoke(event, {action: 'initialize', data: {server: 'http://username:password@vpn.example.com'}});
  assert.equal(invalid.ok, false); assert.equal(await new Preferences(dir).readServer(), 'https://vpn.example.com:8443');
});
