'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {PassThrough, Writable} = require('node:stream');
const {VpnSupervisor, configuration} = require('../app/vpn.cjs');
const input = {hostname: 'vpn.example.com', tunnelPort: 443, sessionId: 'private-session', socksPort: 1080, httpPort: 1081};
function setup(options = {}) {
  const child = new EventEmitter(); child.pid = 12; child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.payload = '';
  child.stdin = new Writable({write(chunk, _encoding, done) { child.payload += chunk.toString(); done(); }});
  child.signals = []; child.kill = signal => { child.signals.push(signal); if (signal === 'SIGKILL' || options.closeOnTerm) queueMicrotask(() => child.emit('close', 0)); return true; };
  const calls = [];
  const supervisor = new VpnSupervisor({helperPath: '/fixed/helper', startTimeout: 50, killTimeout: 5, ...options, spawnChild: (...args) => { calls.push(args); return child; }});
  const events = []; supervisor.on('status', value => events.push(value));
  const event = value => child.stdout.write(JSON.stringify(value) + '\n');
  const ready = (mode = 'l3', ip = '10.0.0.2') => event({event: 'ready', mode, ip, socksAddress: '127.0.0.1:1080', httpAddress: '127.0.0.1:1081'});
  return {child, supervisor, calls, events, event, ready};
}
test('configuration separates HTTP login from tunnel port and validates local ports', () => {
  assert.equal(configuration({...input, hostname: '[2001:db8::1]'}).server, '[2001:db8::1]:443');
  assert.throws(() => configuration({...input, httpPort: 1080}), /不同端口/);
  assert.throws(() => configuration({...input, tunnelPort: 0}), /端口/);
  assert.throws(() => configuration({...input, socksPort: 80}), /本地代理端口/);
  assert.throws(() => configuration({...input, sessionId: 'bad\nsecret'}), /认证/);
});
test('session is passed only over stdin, fragmented readiness is supported', async () => {
  const x = setup({closeOnTerm: true}); const pending = x.supervisor.start(input);
  assert.deepEqual(x.calls[0][1], []); assert.equal(x.child.payload, JSON.stringify({server: 'vpn.example.com:443', sessionId: input.sessionId, socksPort: 1080, httpPort: 1081}) + '\n');
  x.child.stdout.write('{"event":"stage","stage":"tu'); x.child.stdout.write('nnel"}\n'); x.ready();
  assert.equal((await pending).state, 'connected'); assert.equal(x.events[1].stage, 'tunnel');
  await x.supervisor.stop(); assert.equal(x.supervisor.active, null); assert.deepEqual(x.child.signals, ['SIGTERM']);
});
test('TCP readiness allows absent virtual IP; L3 requires IPv4', async () => {
  const x = setup({closeOnTerm: true}); const pending = x.supervisor.start(input); x.ready('tcp', ''); assert.equal((await pending).ip, ''); await x.supervisor.stop();
  const y = setup({closeOnTerm: true}); const failure = assert.rejects(y.supervisor.start(input), /无效状态/); y.ready('l3', ''); await failure; await y.supervisor.stop();
});
test('start timeout cannot mark connection ready and escalates termination', async () => {
  const x = setup({startTimeout: 5}); await assert.rejects(x.supervisor.start(input), /超时/); x.ready(); await x.supervisor.stop();
  assert.deepEqual(x.child.signals, ['SIGTERM', 'SIGKILL']); assert.equal(x.supervisor.status.state, 'disconnected'); assert.ok(!x.events.some(value => value.state === 'connected'));
});
test('cancel while starting rejects startup and waits for child close', async () => {
  const x = setup(); const reject = assert.rejects(x.supervisor.start(input), /取消/); const stopping = x.supervisor.stop();
  x.ready(); await reject; await stopping; assert.equal(x.supervisor.active, null); assert.ok(!x.events.some(value => value.state === 'connected'));
});
test('unexpected exit resets connected state and permits a later launch', async () => {
  const x = setup({closeOnTerm: true}); let pending = x.supervisor.start(input); x.ready(); await pending; x.child.emit('close', 1);
  assert.equal(x.supervisor.status.state, 'disconnected'); assert.equal(x.supervisor.status.code, 'HELPER_EXIT');
  const y = setup({closeOnTerm: true}); pending = y.supervisor.start(input); y.ready(); await pending; await y.supervisor.stop();
});
test('helper error and stderr do not expose secrets through status', async () => {
  const x = setup({closeOnTerm: true}); const rejected = assert.rejects(x.supervisor.start(input), /证书验证失败/);
  x.child.stderr.write('password=do-not-display'); x.event({event: 'error', code: 'TLS_CERT_INVALID', message: 'sessionId=do-not-display'}); await rejected; await x.supervisor.stop();
  assert.ok(!JSON.stringify(x.events).includes('do-not-display')); assert.ok(!JSON.stringify(x.events).includes(input.sessionId));
});
test('malformed output and wrong proxy addresses fail closed', async () => {
  for (const payload of ['not-json\n', JSON.stringify({event: 'ready', mode: 'l3', ip: '10.0.0.2', socksAddress: '0.0.0.0:1080', httpAddress: '127.0.0.1:1081'}) + '\n']) {
    const x = setup({closeOnTerm: true}); const rejected = assert.rejects(x.supervisor.start(input), /无效状态/); x.child.stdout.write(payload); await rejected; await x.supervisor.stop();
  }
});
test('spawn error with no PID cleans up and duplicate startup is denied', async () => {
  const x = setup({closeOnTerm: true}); const rejected = assert.rejects(x.supervisor.start(input), /无法启动/); await assert.rejects(x.supervisor.start(input), /正在连接/);
  x.child.pid = undefined; x.child.emit('error', new Error('private spawn diagnostics')); await rejected; assert.equal(x.supervisor.active, null);
});

test('late close from an earlier process cannot clear a new connection', async () => {
  const x = setup({closeOnTerm: true}); const first = x.supervisor.start(input); x.ready(); await first; await x.supervisor.stop();
  const y = setup({closeOnTerm: true}); x.supervisor.spawnChild = () => y.child;
  const second = x.supervisor.start(input); y.ready(); await second;
  x.child.emit('close', 1); assert.equal(x.supervisor.status.state, 'connected'); await x.supervisor.stop();
});
