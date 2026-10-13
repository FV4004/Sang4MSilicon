'use strict';
const {spawn} = require('node:child_process');
const {EventEmitter} = require('node:events');
const {isIP} = require('node:net');
const WARNINGS=Object.freeze({DNS_UNAVAILABLE:'网关未提供可用内网 DNS，暂只分流 IP 与静态域名。',DOMAIN_RULE_SKIPPED:'部分域名规则不受支持，已跳过。'});
const ERRORS = Object.freeze({START_TIMEOUT: 'VPN 连接超时，请检查隧道端口与服务器。', HELPER_UNAVAILABLE: 'VPN 组件无法启动，请重新安装测试版。', HELPER_EXIT: 'VPN 组件已退出，连接已断开。', PROTOCOL_ERROR: 'VPN 组件返回了无效状态。', PORT_IN_USE: '本地代理端口已占用，请更换端口。', AUTH_FAILED: 'VPN 隧道会话认证失败，请重新登录。', CONNECT_FAILED: '无法建立 VPN 隧道，请检查服务器和端口。', TUNNEL_FAILED: 'VPN 隧道连接失败。', CANCELLED: 'VPN 连接已取消。', TLS_CERT_INVALID: 'VPN 网关证书验证失败。', UNSUPPORTED_SESSION: '网关会话格式不受支持，请重新登录。', CONFIG_FAILED: '无法获取 VPN 资源配置。', RESOURCE_FETCH_FAILED:'网关未返回资源列表，请重新登录后重试。', RESOURCE_PARSE_FAILED:'网关资源列表格式不受支持，无法建立内网路由。', DNS_ROUTING_UNAVAILABLE:'网关未提供可用 IPv4 路由或内网 DNS，当前无法生成 TUN 路由。', RESOURCE_ROUTES_UNSUPPORTED:'网关资源包含本版不支持的全网路由或路由数量超限。', DNS_DOMAIN_LIMIT:'下发的 DNS 域名超过 16,384 个有效分流域，请检查网关配置。', PERMISSION_DENIED: 'macOS 管理员授权未完成，请重试。', TUN_UNAVAILABLE: '无法启动 macOS TUN 接口。', ROUTE_FAILED: '内网路由配置失败，连接已停止。', DNS_CONFLICT: '内网 DNS 配置存在冲突，连接已停止。', CLEANUP_FAILED: '未能确认网络配置恢复，请检查系统路由和 DNS 后再连接。', TUN_UNSUPPORTED: '当前网关不支持此版本的 TUN 模式，可尝试本地代理。', UNSUPPORTED_PLATFORM: '系统 TUN 模式仅支持 macOS。'});
function port(value) { if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error('端口必须为 1 至 65535 的整数。'); return value; }
function configuration({hostname, tunnelPort, sessionId, socksPort = 1080, httpPort = 1081, mode}) {
  if (typeof hostname !== 'string' || !hostname || /[\s/\\\x00]/.test(hostname)) throw new Error('VPN 服务器地址无效。');
  if (typeof sessionId !== 'string' || !sessionId || sessionId.length > 4096 || /[\r\n\x00]/.test(sessionId)) throw new Error('请先完成账号认证。');
  if (mode !== undefined && !['tun', 'proxy'].includes(mode)) throw new Error('VPN 模式无效。');
  const host = hostname.replace(/^\[|\]$/g, '');
  const server = `${host.includes(':') ? '[' + host + ']' : host}:${port(tunnelPort)}`;
  if (mode === 'tun') return {server, sessionId, mode};
  const a = port(socksPort), b = port(httpPort); if (a < 1024 || b < 1024) throw new Error('本地代理端口必须为 1024 至 65535。'); if (a === b) throw new Error('SOCKS5 与 HTTP 代理必须使用不同端口。');
  return {server, sessionId, socksPort: a, httpPort: b, ...(mode ? {mode} : {})};
}
class VpnSupervisor extends EventEmitter {
  constructor({helperPath, spawnChild = spawn, spawnTunChild, tunStartTimeout = 180000, tunKillTimeout = 30000, startTimeout = 60000, killTimeout = 2000} = {}) {
    super(); this.helperPath = helperPath; this.spawnTunChild = spawnTunChild; this.tunStartTimeout = tunStartTimeout; this.tunKillTimeout = tunKillTimeout; this.spawnChild = spawnChild; this.startTimeout = startTimeout; this.killTimeout = killTimeout; this.active = null; this.status = {state: 'disconnected'};
  }
  publish(status) { this.status = status; this.emit('status', status); }
  async start(input) {
    if (this.active) throw new Error('VPN 已连接或正在连接。');
    const config = configuration(input);
    let resolve, reject; const ready = new Promise((yes, no) => { resolve = yes; reject = no; });
    const r = {child: null, config, resolve, reject, settled: false, stopping: false, buffer: '', done: null};
    r.done = new Promise(yes => { r.finishStop = yes; }); this.active = r;
    this.publish({state: 'connecting', stage: 'token'});
    try {
      const launch = config.mode === 'tun' ? this.spawnTunChild : this.spawnChild;
      if (!launch) throw new Error('Missing TUN launcher');
      r.child = launch(this.helperPath, [], {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
      r.child.once('error', () => this.fail(r, 'HELPER_UNAVAILABLE'));
      r.child.once('close', () => this.finish(r));
      r.child.stdout.on('data', chunk => this.read(r, chunk));
      r.child.stdout.on('error', () => this.fail(r, 'PROTOCOL_ERROR'));
      r.child.stderr.on('data', () => {}); // Drain without logging possibly sensitive helper diagnostics.
      r.child.stderr.on('error', () => {});
      r.child.stdin.on('error', () => this.fail(r, 'HELPER_UNAVAILABLE'));
      r.startTimer = setTimeout(() => this.fail(r, 'START_TIMEOUT'), config.mode === 'tun' ? this.tunStartTimeout : this.startTimeout);
      r.child.stdin.end(JSON.stringify(config) + '\n');
    } catch { this.fail(r, 'HELPER_UNAVAILABLE'); if (!r.child) this.finish(r); }
    return ready;
  }
  read(r, chunk) {
    if (this.active !== r) return;
    r.buffer += chunk.toString('utf8');
    if (r.buffer.length > 16384) { this.fail(r, 'PROTOCOL_ERROR'); return; }
    let end;
    while ((end = r.buffer.indexOf('\n')) >= 0) {
      const line = r.buffer.slice(0, end); r.buffer = r.buffer.slice(end + 1);
      if (!line.trim()) continue;
      let event; try { event = JSON.parse(line); } catch { this.fail(r, 'PROTOCOL_ERROR'); return; }
      if (r.stopping) {
        if (event.event === 'error' && event.code === 'CLEANUP_FAILED') { r.failure = 'CLEANUP_FAILED'; this.publish({state: 'error', code: r.failure, message: ERRORS[r.failure]}); }
        continue;
      }
      if (event.event === 'stage' && ['token', 'ip', 'tunnel', 'routes'].includes(event.stage) && !r.settled) this.publish({state: 'connecting', stage: event.stage});
      else if (event.event === 'ready' && !r.settled && r.config.mode === 'tun' && event.mode === 'tun' && isIP(event.ip) === 4 && /^utun[0-9]+$/.test(event.interface) && Number.isSafeInteger(event.routeCount) && event.routeCount > 0 && Number.isSafeInteger(event.dnsCount) && event.dnsCount >= 0) {
        r.settled = true; clearTimeout(r.startTimer);
        const value = {state: 'connected', mode: 'tun', ip: event.ip, interface: event.interface, routeCount: event.routeCount, dnsCount: event.dnsCount, warnings: Array.isArray(event.warnings) ? [...new Set(event.warnings.filter(code=>typeof code==='string'&&Object.hasOwn(WARNINGS,code)))].map(code=>WARNINGS[code]) : []};
        this.publish(value); r.resolve(value);
      }
      else if (event.event === 'ready' && !r.settled && r.config.mode !== 'tun' && ((event.mode === 'l3' && isIP(event.ip) === 4) || (event.mode === 'tcp' && (event.ip === '' || event.ip === undefined || isIP(event.ip) === 4))) && event.socksAddress === `127.0.0.1:${r.config.socksPort}` && event.httpAddress === `127.0.0.1:${r.config.httpPort}`) {
        r.settled = true; clearTimeout(r.startTimer);
        const value = {state: 'connected', ip: event.ip || '', mode: event.mode, socksAddress: event.socksAddress, httpAddress: event.httpAddress};
        this.publish(value); r.resolve(value);
      } else if (event.event === 'error') { this.fail(r, Object.hasOwn(ERRORS, event.code) ? event.code : 'TUNNEL_FAILED'); return; }
      else { this.fail(r, 'PROTOCOL_ERROR'); return; }
    }
  }
  fail(r, code) {
    if (this.active !== r || r.stopping) return;
    r.failure = code; this.publish({state: 'error', code, message: ERRORS[code]}); this.terminate(r);
  }
  terminate(r) {
    if (r.stopping) return;
    r.stopping = true; clearTimeout(r.startTimer);
    if (!r.settled) { r.settled = true; r.reject(new Error(ERRORS[r.failure || 'CANCELLED'])); }
    if (!r.child) { this.finish(r); return; }
    // A process which failed to spawn has no PID and cannot receive signals.
    if (!r.child.pid) { this.finish(r); return; }
    r.killTimer = setTimeout(() => { if (this.active === r) { try { r.child.kill('SIGKILL'); } catch {} } }, r.config.mode === 'tun' ? this.tunKillTimeout : this.killTimeout);
    try { r.child.kill('SIGTERM'); } catch { /* close/error still owns cleanup */ }
  }
  finish(r) {
    clearTimeout(r.startTimer); clearTimeout(r.killTimer);
    if (!r.settled) { r.settled = true; r.reject(new Error(ERRORS[r.failure || 'HELPER_EXIT'])); }
    if (this.active === r) {
      this.active = null;
      const code = (r.child?.cleanupFailed ? 'CLEANUP_FAILED' : r.failure) || (!r.stopping ? 'HELPER_EXIT' : undefined);
      this.publish({state: 'disconnected', ...(code ? {code, message: ERRORS[code]} : {})});
    }
    r.finishStop(); r.config.sessionId = ''; r.buffer = '';
  }
  async stop() {
    const r = this.active; if (!r) return;
    this.publish({state: 'stopping'}); this.terminate(r); await r.done;
    if (r.failure === 'CLEANUP_FAILED' || r.child?.cleanupFailed) throw new Error(ERRORS.CLEANUP_FAILED);
  }
}
module.exports = {VpnSupervisor, configuration};
