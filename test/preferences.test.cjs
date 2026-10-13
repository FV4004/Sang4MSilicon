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
