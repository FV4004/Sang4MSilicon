const {test, after} = require('node:test');
const https = require('node:https');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
let tlsFixture;
function localTLS() {
 if (tlsFixture) return tlsFixture;
 const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mchip-tls-test-'));
 after(() => fs.rmSync(dir, {recursive: true, force: true}));
 const cfg = path.join(dir, 'openssl.cnf');
 fs.writeFileSync(cfg, '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n');
 execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', path.join(dir,'key.pem'), '-out', path.join(dir,'cert.pem'), '-config', cfg], {stdio: 'ignore'});
 tlsFixture = {key: fs.readFileSync(path.join(dir,'key.pem')), cert: fs.readFileSync(path.join(dir,'cert.pem'))};
 return tlsFixture;
}
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const {AuthClient, serverURL, parseAuth, rsaPassword} = require('../app/auth.cjs');
const pair = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
const jwk = pair.publicKey.export({format: 'jwk'});
const modulus = Buffer.from(jwk.n, 'base64url').toString('hex');
const rotatedPair = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
const rotatedModulus = Buffer.from(rotatedPair.publicKey.export({format: 'jwk'}).n, 'base64url').toString('hex');
const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000b49444154789c636000020000050001a5f645400000000049454e44ae426082', 'hex');
const xml = data => '<Auth>' + Object.entries(data).map(([k,v]) => `<${k}>${v}</${k}>`).join('') + '</Auth>';
function decrypted(hex, privateKey = pair.privateKey) {
 const b = crypto.privateDecrypt({key: privateKey, padding: crypto.constants.RSA_NO_PADDING}, Buffer.from(hex, 'hex'));
 assert.equal(b[0], 0); assert.equal(b[1], 2);
 const end = b.indexOf(0, 2); assert.ok(end >= 10); return b.subarray(end + 1).toString('utf8');
}
async function mock(t, options = {}) {
 const calls = []; let initRequests = 0;
 const handler = async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  let body = ''; for await (const b of req) body += b;
  calls.push({path: u.pathname, query: u.searchParams, headers: req.headers, method: req.method, body: new URLSearchParams(body)});
  const write = data => { res.setHeader('Content-Type', 'application/xml'); res.end(xml(data)); };
  if (u.pathname === '/por/login_auth.csp') { res.setHeader('Set-Cookie', 'testsession=present; Path=/; HttpOnly' + (options.tls ? '; Secure' : '')); initRequests++; return write({ErrorCode: initRequests > 1 && options.failRefresh ? 20026 : 1, TwfID: 'initial-session', ...(initRequests > 1 ? {RSA_ENCRYPT_KEY: options.rotateAuth ? rotatedModulus : modulus, RSA_ENCRYPT_EXP: 65537, CSRF_RAND_CODE: options.rotateAuth ? 'fresh-random' : 'csrf-42'} : {})}); }
  if (u.pathname === '/public/psw_config') return write({ErrorCode: 1, RSA_ENCRYPT_KEY: modulus, RSA_ENCRYPT_EXP: 65537, CSRF_RAND_CODE: 'csrf-42', USE_RAND_CODE: options.noCaptcha ? 0 : 1});
  if (u.pathname === '/por/rand_code.csp') { res.setHeader('Content-Type', 'image/png'); return res.end(png); }
  if (u.pathname === '/por/login_psw.csp') {
   if (options.redirect) { res.writeHead(307, {Location: options.redirect}); return res.end(); }
   if (options.slow) return;
   const form = new URLSearchParams(body);
   if ((!options.noCaptcha && form.get('svpn_rand_code') !== 'A1B2') || options.reject || options.rejectCode) return write({ErrorCode: options.rejectCode || 0});
   return write({ErrorCode: 1, TwfID: 'authenticated-session', ...(options.mfa ? {NextService: options.mfa} : {})});
  }
  if (u.pathname === '/por/login_token.csp') return write({ErrorCode: 1, TwfID: 'final-session'});
  if (u.pathname === '/por/update_session.csp') return write({ErrorCode: 1});
  if (u.pathname === '/por/logout.csp') return write({ErrorCode: 1});
  res.writeHead(404); res.end();
 };
 const server = options.tls ? https.createServer(localTLS(), handler) : http.createServer(handler);
 await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
 t.after(() => { server.closeAllConnections(); server.close(); });
 return {origin: `${options.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}`, calls};
}
const creds = {username: 'user&测试', password: 'p+a&ss中文', captcha: 'A1B2'};
test('HTTP/HTTPS server validation supports default/custom ports and rejects invalid origins', () => {
 assert.equal(serverURL('http://127.0.0.1:8080').origin, 'http://127.0.0.1:8080');
 assert.equal(serverURL('http://[::1]:8080').hostname, '[::1]');
 assert.equal(serverURL('https://example.com').origin, 'https://example.com');
 assert.equal(serverURL('http://example.com').port, '');
 assert.equal(serverURL('https://example.com:443').port, '');
 assert.equal(serverURL('http://example.com:80').port, '');
 assert.equal(serverURL('https://example.com:8443').port, '8443');
 for (const value of ['file:///tmp/a','http://a:b@example.com','http://example.com/por/login','http://example.com?token=x']) assert.throws(() => serverURL(value));
});
test('RSA ciphertext decrypts to exact SDK password_randomcode and stays modulus-sized', () => {
 const encrypted = rsaPassword(creds.password, {RSA_ENCRYPT_KEY: modulus, RSA_ENCRYPT_EXP: '65537', CSRF_RAND_CODE: 'csrf-42'});
 assert.equal(encrypted.length, 512); assert.equal(decrypted(encrypted), 'p+a&ss中文_csrf-42');
});
test('Missing anti-replay random code never sends plaintext', () => assert.throws(() => rsaPassword('secret', {RSA_ENCRYPT_KEY: modulus}), /随机码/));
test('Invalid XML, DTD and missing status are rejected', () => {
 for (const s of ['<html>login</html>', '<Auth><ErrorCode>x</ErrorCode></Auth>', '<!DOCTYPE Auth><Auth><ErrorCode>1</ErrorCode></Auth>', '<Auth>']) assert.throws(() => parseAuth(Buffer.from(s)));
});
test('HTTP login uses server captcha, cookies, encoded form, RSA and session synchronization', async t => {
 const {origin,calls} = await mock(t); const client = new AuthClient(origin);
 const init = await client.initialize(); assert.equal(init.captchaRequired,true); assert.match(init.captchaImage, /^data:image\/png;base64,/);
 assert.equal((await client.login(creds)).phase, 'authenticated');
 const login = calls.find(c => c.path === '/por/login_psw.csp');
 assert.equal(login.method,'POST'); assert.equal(login.query.get('encrypt'),'1'); assert.equal(login.query.get('anti_replay'),'1'); assert.equal(login.query.get('apiversion'),'1');
 assert.equal(login.headers.cookie,'testsession=present'); assert.equal(login.body.get('svpn_name'),creds.username);
 assert.equal(decrypted(login.body.get('svpn_password')), creds.password + '_csrf-42');
 assert.equal(login.body.get('svpn_req_randcode'),'csrf-42'); assert.equal(login.body.get('svpn_rand_code'),'A1B2');
 const sync = calls.find(c => c.path === '/por/update_session.csp'); assert.equal(sync.headers.twfid,'authenticated-session');
 assert.equal(sync.query.get('twfid'),'authenticated-session');
 await client.logout(); assert.equal(client.twfid,''); assert.equal(client.closed,true); assert.ok(calls.find(c => c.path === '/por/logout.csp'));
});
test('Captcha refresh reuses session and changes random query', async t => {
 const {origin,calls} = await mock(t); const client = new AuthClient(origin); await client.initialize(); await client.captcha();
 const imgs = calls.filter(c => c.path === '/por/rand_code.csp'); assert.equal(imgs.length,2); assert.notEqual(imgs[0].query.get('rnd'),imgs[1].query.get('rnd')); assert.equal(imgs[1].headers.cookie,'testsession=present');
});
test('Missing captcha is rejected before credential request, wrong captcha cannot authenticate', async t => {
 const {origin,calls} = await mock(t); const client = new AuthClient(origin); await client.initialize();
 await assert.rejects(client.login({...creds,captcha:''}),/验证码/); assert.equal(calls.filter(c => c.path.includes('login_psw')).length,0);
 await assert.rejects(client.login({...creds,captcha:'WRONG'}),/服务器拒绝了认证/); assert.equal(client.authenticated,false); assert.equal(client.config,null);
});
test('Gateways without image captcha remain supported', async t => {
 const {origin,calls} = await mock(t,{noCaptcha:true}); const client = new AuthClient(origin); assert.equal((await client.initialize()).captchaRequired,false);
 assert.equal((await client.login({...creds,captcha:''})).phase,'authenticated'); assert.equal(calls.filter(c => c.path.includes('rand_code')).length,0);
});
test('Further authentication is not reported as successful', async t => {
 const {origin} = await mock(t,{mfa:'token'}); const client = new AuthClient(origin); await client.initialize();
 assert.equal((await client.login(creds)).phase,'challenge'); assert.equal(client.authenticated,false);
 assert.equal((await client.submitChallenge('123456')).phase,'authenticated');
});
test('Unsupported device/certificate authentication remains explicit', async t => {
 const {origin} = await mock(t,{mfa:'cert'}); const client = new AuthClient(origin); await client.initialize();
 assert.equal((await client.login(creds)).phase,'unsupported'); assert.equal(client.authenticated,false);
});
test('Cross-origin redirects never forward credential body', async t => {
 const {origin} = await mock(t,{redirect:'http://127.0.0.1:1/steal'}); const client = new AuthClient(origin); await client.initialize();
 await assert.rejects(client.login(creds),/其他地址/); assert.equal(client.authenticated,false);
});
test('Hung gateway requests time out', async t => {
 const {origin} = await mock(t,{slow:true}); const client = new AuthClient(origin,{timeout:100}); await client.initialize();
 await assert.rejects(client.login(creds),/超时/);
});

test('HTTPS login verifies trusted TLS and preserves secure cookies through captcha and login', async t => {
 const {origin,calls} = await mock(t,{tls:true});
 const client = new AuthClient(origin,{tlsCA:localTLS().cert});
 assert.equal((await client.initialize()).captchaRequired,true);
 await client.captcha();
 assert.equal((await client.login(creds)).phase,'authenticated');
 for(const call of calls.filter(c => c.path !== '/por/login_auth.csp')) assert.equal(call.headers.cookie,'testsession=present');
 await client.logout();
});
test('HTTPS refuses untrusted server certificates without submitting credentials', async t => {
 const {origin,calls} = await mock(t,{tls:true});
 const client = new AuthClient(origin);
 await assert.rejects(client.initialize(),/HTTPS 证书验证失败/);
 assert.equal(calls.length,0); assert.equal(client.authenticated,false);
});

test('Password submission refreshes auth challenge and uses rotated RSA key without reloading captcha', async t => {
 const {origin,calls} = await mock(t,{rotateAuth:true}); const client = new AuthClient(origin);
 await client.initialize(); assert.equal((await client.login(creds)).phase,'authenticated');
 const loginIndex = calls.findIndex(c => c.path === '/por/login_psw.csp');
 assert.equal(calls[loginIndex-1].path,'/por/login_auth.csp');
 assert.equal(calls.filter(c => c.path === '/por/login_auth.csp').length,2);
 assert.equal(calls.filter(c => c.path === '/por/rand_code.csp').length,1);
 assert.equal(calls[loginIndex].body.get('svpn_req_randcode'),'fresh-random');
 assert.equal(decrypted(calls[loginIndex].body.get('svpn_password'),rotatedPair.privateKey),creds.password+'_fresh-random');
 assert.equal(calls[loginIndex].headers.cookie,'testsession=present');
});
test('20004 is reported as password authentication, not captcha or official-client attestation', async t => {
 const {origin} = await mock(t,{rejectCode:20004}); const client = new AuthClient(origin); await client.initialize();
 await assert.rejects(client.login(creds),/用户名或密码验证未通过.*20004/);
 assert.equal(client.authenticated,false);
});
test('Failed auth refresh prevents password submission', async t => {
 const {origin,calls} = await mock(t,{failRefresh:true}); const client = new AuthClient(origin); await client.initialize();
 await assert.rejects(client.login(creds),/刷新认证配置失败/);
 assert.equal(calls.filter(c => c.path === '/por/login_psw.csp').length,0);
});

test('logout failure still clears credentials, cookies and local authentication',async()=>{
 const c=new AuthClient('http://vpn.example.com');c.twfid='temporary-session';c.authenticated=true;
 c.request=async()=>{throw Error('gateway offline')};await assert.rejects(c.logout(),/offline/);
 assert.equal(c.closed,true);assert.equal(c.authenticated,false);assert.equal(c.twfid,'');
});
