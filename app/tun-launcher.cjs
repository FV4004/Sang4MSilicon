'use strict';
const fs = require('node:fs/promises');
const {createHash, randomBytes} = require('node:crypto');
const {spawn, execFile} = require('node:child_process');
const {promisify} = require('node:util');
const net = require('node:net');
const {EventEmitter} = require('node:events');
const {PassThrough, Writable} = require('node:stream');
const run = promisify(execFile);
const ROOT_HELPER = '/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-helper';
const SOCKET_DIR = '/var/run/mchip-vpn';
function quote(value) { return "'" + String(value).replace(/'/g, "'\\''") + "'"; }
function appleString(value) { return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"'; }
function installScript(source, hash, socket, uid) {
  if (!/^[a-f0-9]{64}$/.test(hash) || !Number.isSafeInteger(uid) || uid < 1 || !new RegExp('^/var/run/mchip-vpn/' + uid + '-[a-f0-9]{32}\\.sock$').test(socket)) throw new Error('Invalid installation parameters');
  return `set -eu
parent='/Library/PrivilegedHelperTools'
[ ! -L "$parent" ] || exit 70
if [ ! -e "$parent" ]; then /usr/bin/install -d -o root -g wheel -m 0755 "$parent"; fi
[ -d "$parent" ] && [ "$(/usr/bin/stat -f %u "$parent")" = 0 ] || exit 70
perm=$(/usr/bin/stat -f %Lp "$parent")
[ $((0$perm & 0022)) = 0 ] || exit 70
[ ! -L ${quote(ROOT_HELPER)} ] || exit 70
tmp=$(/usr/bin/mktemp "$parent/.mchip-vpn.XXXXXX")
trap '/bin/rm -f "$tmp"' EXIT HUP INT TERM
/bin/cp -X ${quote(source)} "$tmp"
/usr/sbin/chown root:wheel "$tmp"
/bin/chmod 0755 "$tmp"
actual=$(/usr/bin/shasum -a 256 "$tmp")
[ "\${actual%% *}" = ${quote(hash)} ] || exit 71
/usr/bin/codesign --verify --strict "$tmp" >/dev/null 2>&1
/bin/mv -f "$tmp" ${quote(ROOT_HELPER)}
trap - EXIT HUP INT TERM
exec ${quote(ROOT_HELPER)} --tun-control ${quote(socket)} --owner-uid ${quote(uid)} </dev/null >/dev/null 2>&1`;
}
function spawnTun(helperPath, _args, _options, deps = {}) {
  const platform = deps.platform || process.platform, uid = deps.uid ?? process.getuid?.();
  const io = deps.fs || fs, launch = deps.spawn || spawn, execute = deps.execFile || run, connect = deps.connect || net.createConnection;
  const pollMs = deps.pollMs ?? 100, timeoutMs = deps.timeoutMs ?? 180000, cleanupMs = deps.cleanupMs ?? 45000;
  const child = new EventEmitter(); child.pid = process.pid; child.stdout = new PassThrough(); child.stderr = new PassThrough();
  let auth, socket, config = '', configSent = false, stopping = false, closed = false, acknowledged = false, forced = false, pollTimer, deadline, cleanupTimer;
  const socketPath = `${SOCKET_DIR}/${uid}-${(deps.randomBytes || randomBytes)(16).toString('hex')}.sock`;
  const emit = event => { if (!closed) child.stdout.write(JSON.stringify(event) + '\n'); };
  function finish(code = 0) {
    if (closed) return; closed = true; clearTimeout(pollTimer); clearTimeout(deadline); clearTimeout(cleanupTimer); config = '';
    child.pid = undefined; child.stdout.end(); child.stderr.end(); child.emit('close', code);
  }
  function fail(code) { emit({event: 'error', code}); if (configSent) { stopping = true; socket?.destroy(); child.cleanupFailed = true; cleanupTimer = setTimeout(() => finish(1), cleanupMs); } else { auth?.kill('SIGTERM'); socket?.destroy(); finish(1); } }
  child.stdin = new Writable({write(chunk, _encoding, done) {
    config += chunk.toString('utf8');
    if (config.length > 16384) { done(new Error('Invalid configuration')); return; }
    if (socket && !configSent && !stopping && config.includes('\n')) { configSent = true; socket.write(config); config = ''; }
    done();
  }});
  child.kill = signal => {
    if (closed) return false; stopping = true; config = '';
    if (!configSent) { auth?.kill('SIGTERM'); socket?.destroy(); finish(); return true; }
    if (signal === 'SIGKILL') { forced = true; socket?.destroy(); }
    else if (socket && !socket.destroyed) socket.write('{"event":"stop"}\n');
    if (!cleanupTimer) cleanupTimer = setTimeout(() => { child.cleanupFailed = true; emit({event: 'error', code: 'CLEANUP_FAILED'}); finish(1); }, cleanupMs);
    return true;
  };
  async function poll() {
    if (closed || stopping) return;
    try {
      const dir = await io.lstat(SOCKET_DIR), file = await io.lstat(socketPath);
      if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== 0 || (dir.mode & 0o022) || !file.isSocket() || file.isSymbolicLink() || file.uid !== uid || (file.mode & 0o777) !== 0o600) { fail('PERMISSION_DENIED'); return; }
    } catch (error) {
      if (error.code === 'ENOENT') { pollTimer = setTimeout(poll, pollMs); return; }
      fail('PERMISSION_DENIED'); return;
    }
    if (closed || stopping) return;
    socket = connect({path: socketPath}); let buffer = '';
    socket.on('connect', () => {
      if (stopping || closed) { socket.destroy(); return; }
      if (config.includes('\n')) { configSent = true; socket.write(config); config = ''; }
    });
    socket.on('data', data => {
      if (closed) return;
      buffer += data.toString('utf8');
      if (buffer.length > 16384) { fail('PROTOCOL_ERROR'); return; }
      let end;
      while ((end = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
        let event; try { event = JSON.parse(line); } catch { fail('PROTOCOL_ERROR'); return; }
        if (event.event === 'ready') clearTimeout(deadline);
        if (event.event === 'error' && event.code === 'CLEANUP_FAILED') child.cleanupFailed = true;
        if (event.event === 'stopped') { acknowledged = true; continue; }
        emit(event);
      }
    });
    socket.on('error', () => { if (!stopping) fail('TUN_UNAVAILABLE'); });
    socket.on('close', () => {
      if (closed) return;
      if (acknowledged) finish();
      else if (!configSent) finish();
      else if (!stopping) { child.cleanupFailed = true; emit({event: 'error', code: 'CLEANUP_FAILED'}); finish(1); }
      // Forced EOF asks the root helper to restore routes/DNS; wait for its process exit.
    });
  }
  queueMicrotask(async () => {
    if (platform !== 'darwin') { fail('UNSUPPORTED_PLATFORM'); return; }
    if (!Number.isSafeInteger(uid) || uid < 1) { fail('PERMISSION_DENIED'); return; }
    try {
      const stat = await io.lstat(helperPath), manifestStat = await io.lstat(helperPath + '.sha256');
      if (!stat.isFile() || stat.isSymbolicLink() || !manifestStat.isFile() || manifestStat.isSymbolicLink()) throw new Error('Unsafe helper');
      const manifest = String(await io.readFile(helperPath + '.sha256', 'utf8')).trim();
      if (!/^[a-fA-F0-9]{64}(?:[ \t]+\*?[^\r\n]+)?$/.test(manifest)) throw new Error('Invalid manifest');
      const hash = manifest.slice(0, 64).toLowerCase();
      if (createHash('sha256').update(await io.readFile(helperPath)).digest('hex') !== hash) throw new Error('Hash mismatch');
      await execute('/usr/bin/codesign', ['--verify', '--strict', helperPath], {timeout: 15000, maxBuffer: 16384});
      if (closed || stopping) return;
      const script = installScript(helperPath, hash, socketPath, uid);
      auth = launch('/usr/bin/osascript', ['-e', 'do shell script ' + appleString(script) + ' with administrator privileges'], {stdio: ['ignore', 'ignore', 'pipe']});
      auth.stderr.on('data', () => {}); auth.stderr.on('error', () => {});
      auth.on('error', () => fail('PERMISSION_DENIED'));
      auth.on('close', code => {
        if (closed) return;
        if (!configSent) fail(code ? 'PERMISSION_DENIED' : 'TUN_UNAVAILABLE');
        else if (acknowledged) finish();
        else if (forced) { child.cleanupFailed = true; emit({event: 'error', code: 'CLEANUP_FAILED'}); finish(1); }
        else if (!cleanupTimer) cleanupTimer = setTimeout(() => { child.cleanupFailed = true; emit({event: 'error', code: 'CLEANUP_FAILED'}); finish(1); }, cleanupMs);
      });
      deadline = setTimeout(() => fail('START_TIMEOUT'), timeoutMs);
      void poll();
    } catch { fail('HELPER_UNAVAILABLE'); }
  });
  return child;
}
async function recoveryPending() {
 try { return (await fs.lstat('/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-state/resolver-lease.json')).isFile(); } catch { return false; }
}
async function recoverTun(helperPath) {
 return new Promise((resolve,reject)=>{
  const child=spawnTun(helperPath,[],{});let failure=false;
  child.stdout.on('data',bytes=>{if(bytes.toString().includes('"event":"error"'))failure=true});
  child.on('error',()=>reject(new Error('网络恢复组件无法启动。')));
  child.on('close',code=>{if(code||failure||child.cleanupFailed)reject(new Error('未能恢复上次网络配置，请检查授权后重试。'));else resolve()});
  child.stdin.on('error',()=>{failure=true});child.stdin.end('{"mode":"recover"}\n');
 });
}
module.exports = {spawnTun, recoverTun, recoveryPending, installScript, quote, appleString};
