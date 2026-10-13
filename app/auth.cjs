'use strict';
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const {XMLParser, XMLValidator} = require('fast-xml-parser');
const {CookieJar} = require('tough-cookie');
const parser = new XMLParser({ignoreAttributes: true, parseTagValue: false, processEntities: false, trimValues: true});

function serverURL(value) {
  if (typeof value !== 'string' || value.length > 2048) throw new Error('请输入 HTTP 服务器地址。');
  let u;
  try { u = new URL(value.trim()); } catch { throw new Error('地址格式无效，例如 http://vpn.example.com:8080。'); }
  if (u.protocol !== 'http:' || !u.hostname || u.username || u.password || u.search || u.hash || !['', '/'].includes(u.pathname)) {
    throw new Error('请输入完整 HTTP 服务器地址和可选端口，不包含用户名、密码或页面路径。');
  }
  return u;
}
function parseAuth(body) {
  const text = body.toString('utf8');
  if (/<!DOCTYPE|<!ENTITY/i.test(text) || XMLValidator.validate(text) !== true) throw new Error('服务器返回了无效认证 XML；请检查服务器地址和版本。');
  const root = parser.parse(text);
  const a = root.Auth;
  if (!a || typeof a !== 'object' || !/^[-+]?\d+$/.test(String(a.ErrorCode ?? ''))) throw new Error('服务器响应缺少 Auth/ErrorCode。');
  return a;
}
function rsaPassword(password, config) {
  const n = String(config.RSA_ENCRYPT_KEY ?? '').replace(/^0x/i, '');
  const rawE = String(config.RSA_ENCRYPT_EXP || '65537');
  if (!/^[0-9a-f]+$/i.test(n) || n.length < 128 || n.length > 2048 || n.length % 2) throw new Error('服务器未提供有效 RSA 公钥，已停止登录。');
  if (!/^(\d+|0x[\da-f]+)$/i.test(rawE)) throw new Error('服务器 RSA 指数无效。');
  const e = BigInt(rawE);
  if (e < 3n || e > 0xffffffffn || e % 2n !== 1n) throw new Error('服务器 RSA 指数无效。');
  const rand = String(config.CSRF_RAND_CODE || '');
  if (!rand) throw new Error('服务器缺少防重放随机码，请重新获取验证码。');
  const hexE = e.toString(16).padStart(Math.ceil(e.toString(16).length / 2) * 2, '0');
  const key = crypto.createPublicKey({key: {kty: 'RSA', n: Buffer.from(n, 'hex').toString('base64url'), e: Buffer.from(hexE, 'hex').toString('base64url')}, format: 'jwk'});
  try { return crypto.publicEncrypt({key, padding: crypto.constants.RSA_PKCS1_PADDING}, Buffer.from(password + '_' + rand, 'utf8')).toString('hex'); }
  catch { throw new Error('密码长度超出服务器 RSA 加密限制，或公钥不兼容。'); }
}
function captchaType(b) {
  if (b.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (['GIF87a', 'GIF89a'].includes(b.subarray(0, 6).toString())) return 'image/gif';
  if (b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') return 'image/webp';
  throw new Error('服务器未返回支持的验证码图片。');
}
class AuthClient {
  constructor(origin, {timeout = 15000} = {}) {
    this.base = serverURL(origin); this.jar = new CookieJar(); this.timeout = timeout;
    this.config = null; this.twfid = ''; this.challenge = ''; this.authenticated = false;
    this.closed = false; this.activeRequests = new Set();
  }
  close() {
    this.closed = true;
    for (const req of this.activeRequests) req.destroy(new Error('操作已取消。'));
    this.activeRequests.clear(); this.config = null; this.twfid = ''; this.challenge = ''; this.authenticated = false;
    this.jar = new CookieJar();
  }
  async request(pathname, {method = 'GET', form, headers = {}} = {}, redirectCount = 0) {
    if (this.closed) throw new Error('会话已关闭，请重新获取验证码。');
    const u = new URL(pathname, this.base);
    if (u.origin !== this.base.origin) throw new Error('服务器要求跳转到其他地址，请使用最终 HTTP 登录地址重新连接。');
    if (!u.searchParams.has('apiversion')) u.searchParams.set('apiversion', '1');
    const payload = form ? Buffer.from(new URLSearchParams(form).toString()) : null;
    const cookie = await this.jar.getCookieString(u.href);
    const response = await new Promise((resolve, reject) => {
      const req = (u.protocol === 'https:' ? https : http).request(u, {method, headers: {
        Accept: '*/*', 'User-Agent': 'MChipVPNLogin/0.1.0', ...(cookie ? {Cookie: cookie} : {}), ...headers,
        ...(payload ? {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': payload.length} : {})
      }}, res => {
        const chunks = []; let size = 0;
        res.on('data', b => { size += b.length; if (size > 2 * 1024 * 1024) req.destroy(new Error('服务器响应过大。')); else chunks.push(b); });
        res.on('error', reject);
        res.on('end', () => resolve({status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks)}));
      });
      this.activeRequests.add(req);
      const timer = setTimeout(() => req.destroy(new Error('连接超时，请检查服务器和网络。')), this.timeout);
      req.once('close', () => { clearTimeout(timer); this.activeRequests.delete(req); });
      req.on('error', err => reject(err.message === '连接超时，请检查服务器和网络。' || err.message === '服务器响应过大。' || err.message === '操作已取消。' ? err : new Error('无法连接服务器，请检查地址、端口和网络。')));
      if (payload) req.write(payload);
      req.end();
    });
    if (this.closed) throw new Error('操作已取消。');
    for (const item of response.headers['set-cookie'] || []) await this.jar.setCookie(item, u.href);
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      if (!response.headers.location || redirectCount >= 5) throw new Error('服务器重定向过多或地址无效。');
      const next = new URL(response.headers.location, u);
      const toGET = response.status === 303 || ([301, 302].includes(response.status) && method === 'POST');
      return this.request(next.href, toGET ? {method: 'GET'} : {method, form, headers}, redirectCount + 1);
    }
    if (response.status < 200 || response.status >= 300) throw new Error(`服务器返回 HTTP ${response.status}。`);
    return response;
  }
  saveSession(a) {
    if (a.TwfID) this.twfid = String(a.TwfID);
    if (a.CSRF_RAND_CODE && this.config) this.config.CSRF_RAND_CODE = a.CSRF_RAND_CODE;
  }
  async initialize() {
    this.authenticated = false; this.challenge = ''; this.config = null;
    const init = parseAuth((await this.request('/por/login_auth.csp')).body);
    if (Number(init.ErrorCode) !== 1) throw new Error(`初始化认证失败（${init.ErrorCode}）。`);
    this.saveSession(init);
    const config = parseAuth((await this.request('/public/psw_config')).body);
    if (Number(config.ErrorCode) !== 1) throw new Error(`读取登录配置失败（${config.ErrorCode}）。`);
    this.config = {...init, ...config};
    this.saveSession(config);
    const required = Number(config.USE_RAND_CODE ?? init.RndImg ?? 0) === 1;
    let image = null;
    if (required) image = await this.captcha();
    return {server: this.base.origin, captchaRequired: required, captchaImage: image, phase: 'ready'};
  }
  async captcha() {
    if (!this.config || this.authenticated || this.challenge) throw new Error('请重新初始化登录会话。');
    const configured = this.config.RAND_CODE_URL;
    const target = configured ? new URL(String(configured), this.base) : new URL('/por/rand_code.csp', this.base);
    target.searchParams.set('rnd', crypto.randomBytes(8).toString('hex'));
    const {body} = await this.request(target.href);
    return `data:${captchaType(body)};base64,${body.toString('base64')}`;
  }
  async login({username, password, captcha = ''}) {
    if (!this.config || this.challenge || this.authenticated) throw new Error('请先获取新的登录配置与验证码。');
    if (typeof username !== 'string' || !username.trim() || username.length > 256 || typeof password !== 'string' || !password || password.length > 4096 || typeof captcha !== 'string' || captcha.length > 128) throw new Error('请输入有效用户名、密码和验证码。');
    if (Number(this.config.USE_RAND_CODE ?? this.config.RndImg ?? 0) === 1 && !captcha.trim()) throw new Error('请输入图片中的验证码。');
    const encrypted = rsaPassword(password, this.config);
    const response = await this.request('/por/login_psw.csp?anti_replay=1&encrypt=1', {method: 'POST', form: {
      mitm_result: '', svpn_req_randcode: String(this.config.CSRF_RAND_CODE), svpn_name: username.trim(), svpn_password: encrypted, svpn_rand_code: captcha.trim()
    }});
    return this.authResult(parseAuth(response.body));
  }
  async authResult(a) {
    this.saveSession(a);
    const code = Number(a.ErrorCode);
    const next = String(a.NextService || '').trim();
    if ((code === 1 || code === 2) && next) {
      this.challenge = next;
      const supported = /^(token|radius|sms1|sms2|totp)$/i.test(next);
      return {phase: supported ? 'challenge' : 'unsupported', nextService: next, message: supported ? '请输入服务器要求的动态验证码或应答。' : '服务器要求此测试版尚未支持的认证步骤，请使用官方客户端完成。'};
    }
    if (code !== 1 || next) { this.config = null; throw new Error(`认证失败（${code}），请重新获取验证码后重试。`); }
    if (!this.twfid) throw new Error('认证响应缺少会话，无法确认登录成功。');
    const u = new URL('/por/update_session.csp', this.base); u.searchParams.set('twfid', this.twfid);
    await this.request(u.href, {headers: {TWFID: this.twfid}});
    this.authenticated = true; this.challenge = ''; this.config = null;
    return {phase: 'authenticated', message: '认证成功。此测试版尚未建立 VPN 数据隧道。'};
  }
  async submitChallenge(value) {
    if (typeof value !== 'string' || !value.trim() || value.length > 256) throw new Error('请输入动态验证码或应答。');
    const next = this.challenge.toLowerCase();
    const routes = {token: ['/por/login_token.csp', 'svpn_inputtoken'], radius: ['/por/login_radius.csp', 'svpn_inputradius'], sms1: ['/por/login_sms1.csp', 'svpn_inputsms'], sms2: ['/por/login_sms2.csp', 'svpn_inputsms'], totp: ['/auth/token', 'svpn_inputtoken']};
    if (!routes[next]) throw new Error('该认证步骤暂不支持。');
    const [route, field] = routes[next];
    const form = {[field]: value.trim(), ...(next === 'totp' ? {twfid: this.twfid} : {})};
    return this.authResult(parseAuth((await this.request(route, {method: 'POST', form})).body));
  }
  async logout() {
    if (this.authenticated) await this.request('/por/logout.csp', {method: 'POST'});
    this.close(); return {phase: 'idle', message: '登录会话已清除。'};
  }
}
module.exports = {AuthClient, serverURL, parseAuth, rsaPassword, captchaType};
