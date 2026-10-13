'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {PassThrough} = require('node:stream');
const {createHash} = require('node:crypto');
const {spawnTun, installScript, quote, appleString} = require('../app/tun-launcher.cjs');
const {VpnSupervisor, configuration} = require('../app/vpn.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const bytes = Buffer.from('mock signed helper'), hash = createHash('sha256').update(bytes).digest('hex');
const payload = {server: 'vpn.example.com:443', sessionId: 'test-private-session', mode: 'tun'};
function setup(options = {}) {
  const auth = new EventEmitter(); auth.pid = 33; auth.stderr = new PassThrough(); auth.killed = [];
  auth.kill = signal => { auth.killed.push(signal); return true; };
  const socket = new EventEmitter(); socket.destroyed = false; socket.writes = [];
  socket.write = data => { socket.writes.push(data); return true; }; socket.destroy = () => { socket.destroyed = true; queueMicrotask(() => socket.emit('close')); };
  const calls = [], verifications = [];
  const regular = {isFile: () => true, isSymbolicLink: () => false};
  const deps = {platform: 'darwin', uid: 501, randomBytes: () => Buffer.alloc(16, 1), pollMs: 1, timeoutMs: 1000, cleanupMs: 30,
    fs: {lstat: async filename => filename === '/var/run/mchip-vpn' ? {isDirectory: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o40755} : filename.endsWith('.sock') ? {isSocket: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o140600} : regular, readFile: async filename => filename.endsWith('.sha256') ? hash + '  mchip-vpn-helper\n' : bytes},
    execFile: async (...args) => { verifications.push(args); }, spawn: (...args) => { calls.push(args); return auth; }, connect: () => { queueMicrotask(() => socket.emit('connect')); return socket; }, ...options};
  const child = spawnTun('/Applications/VPN.app/Contents/Resources/bin/helper', [], {}, deps); const events = [];
  child.stdout.on('data', data => { for (const line of data.toString().trim().split('\n')) events.push(JSON.parse(line)); });
  child.stdin.end(JSON.stringify(payload) + '\n');
  const closed = new Promise(resolve => child.once('close', resolve));
  const event = value => socket.emit('data', Buffer.from(JSON.stringify(value) + '\n'));
  return {child, events, calls, verifications, auth, socket, closed, event};
}
test('installer quotes shell/AppleScript boundaries, verifies root-owned copy and executes only fixed helper', () => {
  const source = "/Applications/O'Brien $(echo bad).app/helper";
  const command = installScript(source, hash, '/var/run/mchip-vpn/501-' + 'a'.repeat(32) + '.sock', 501);
  assert.ok(command.includes(quote(source))); assert.ok(command.includes('/usr/bin/codesign --verify --strict "$tmp"')); assert.ok(command.includes('/bin/mv -f "$tmp"'));
  assert.ok(command.includes('[ $((0$perm & 0022)) = 0 ]')); assert.ok(!command.includes(payload.sessionId));
  assert.equal(appleString('say "x"\n'), '"say \\"x\\"\\n"');
  assert.throws(() => installScript(source, hash, '/tmp/evil.sock', 501)); assert.throws(() => installScript(source, '$(bad)', '/var/run/mchip-vpn/501-' + 'a'.repeat(32) + '.sock', 501));
});
test('TUN session travels only through validated private socket and stop waits for cleanup acknowledgement', async () => {
  const x = setup(); await tick(); await tick();
  assert.equal(x.verifications[0][0], '/usr/bin/codesign'); assert.equal(x.calls[0][0], '/usr/bin/osascript'); assert.ok(!JSON.stringify(x.calls).includes(payload.sessionId));
  assert.deepEqual(x.socket.writes, [JSON.stringify(payload) + '\n']);
  x.event({event: 'ready', mode: 'tun', ip: '10.0.0.2', interface: 'utun4', routeCount: 2, dnsCount: 1});
  let ended = false; x.closed.then(() => { ended = true; }); x.child.kill('SIGTERM'); await tick(); assert.equal(ended, false); assert.equal(x.socket.writes[1], '{"event":"stop"}\n');
  x.event({event: 'stopped'}); x.socket.emit('close'); await x.closed; assert.equal(x.child.cleanupFailed, undefined);
});
test('non-macOS and checksum mismatch never request privileged execution or transmit session', async () => {
  for (const options of [{platform: 'linux'}, {fs: {lstat: async () => ({isFile: () => true, isSymbolicLink: () => false}), readFile: async filename => filename.endsWith('.sha256') ? '0'.repeat(64) : bytes}}]) {
    const x = setup(options); await x.closed; assert.equal(x.calls.length, 0); assert.equal(x.socket.writes.length, 0); assert.equal(x.events[0].event, 'error');
  }
});
test('unsafe socket ownership/permissions and writable root directory refuse session delivery', async () => {
  for (const bad of ['directory', 'socket']) {
    const x = setup({fs: {readFile: async filename => filename.endsWith('.sha256') ? hash : bytes,
      lstat: async filename => filename === '/var/run/mchip-vpn' ? {isDirectory: () => true, isSymbolicLink: () => false, uid: 0, mode: bad === 'directory' ? 0o40777 : 0o40755} : filename.endsWith('.sock') ? {isSocket: () => true, isSymbolicLink: () => false, uid: bad === 'socket' ? 999 : 501, mode: 0o140600} : {isFile: () => true, isSymbolicLink: () => false}}});
    await x.closed; assert.equal(x.socket.writes.length, 0); assert.equal(x.events[0].code, 'PERMISSION_DENIED');
  }
});
test('force stop uses EOF rather than killing privileged process and reports unconfirmed cleanup', async () => {
  const x = setup(); await tick(); await tick(); x.child.kill('SIGKILL'); await tick();
  assert.equal(x.socket.destroyed, true); assert.deepEqual(x.auth.killed, []);
  x.auth.emit('close', 0); await x.closed; assert.equal(x.child.cleanupFailed, true); assert.equal(x.events.at(-1).code, 'CLEANUP_FAILED');
});
test('cancelled authorization before session delivery creates no network configuration', async () => {
  let resolveCheck; const checking = new Promise(resolve => { resolveCheck = resolve; });
  const x = setup({execFile: async () => checking}); await tick(); x.child.kill('SIGTERM'); resolveCheck(); await x.closed; await tick(); assert.equal(x.calls.length, 0); assert.equal(x.socket.writes.length, 0);
});
test('TUN supervisor validates readiness separately and uses privileged adapter', async () => {
  assert.deepEqual(configuration({hostname: 'vpn.example.com', tunnelPort: 443, sessionId: 'secret', mode: 'tun', socksPort: 0}), {server: 'vpn.example.com:443', sessionId: 'secret', mode: 'tun'});
  const child = new EventEmitter(); child.pid = 5; child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { queueMicrotask(() => child.emit('close')); return true; };
  const supervisor = new VpnSupervisor({helperPath: '/helper', spawnChild: () => { throw new Error('Wrong mode'); }, spawnTunChild: () => child, tunStartTimeout: 1000});
  const pending = supervisor.start({hostname: 'vpn.example.com', tunnelPort: 443, sessionId: 'secret', mode: 'tun'});
  child.stdout.write('{"event":"stage","stage":"routes"}\n'); assert.equal(supervisor.status.stage, 'routes');
  child.stdout.write('{"event":"ready","mode":"tun","ip":"10.0.0.2","interface":"utun3","routeCount":3,"dnsCount":0}\n');
  assert.equal((await pending).interface, 'utun3'); await supervisor.stop();
});

test('process exit racing the socket cleanup acknowledgement does not report a false failure', async()=>{
 const x=setup();await tick();await tick();x.child.kill('SIGTERM');x.auth.emit('close',0);
 x.event({event:'stopped'});x.socket.emit('close');await x.closed;assert.equal(x.child.cleanupFailed,undefined);
});
