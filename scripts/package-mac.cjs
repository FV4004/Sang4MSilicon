'use strict';
const path = require('node:path');
const fs = require('node:fs');
const {createHash} = require('node:crypto');
(async () => {
 const {packager} = await import('@electron/packager');
 const root = path.resolve(__dirname, '..');
 const helper = path.join(root, '.build', 'mchip-vpn-helper');
 if (!fs.existsSync(helper)) throw new Error('先构建 macOS arm64 VPN helper。');
 fs.mkdirSync(path.join(root, '.build', 'bin'), {recursive:true});
 fs.copyFileSync(helper, path.join(root, '.build', 'bin', 'mchip-vpn-helper'));
 fs.chmodSync(path.join(root, '.build', 'bin', 'mchip-vpn-helper'),0o755);
 fs.writeFileSync(path.join(root,'.build','bin','mchip-vpn-helper.sha256'),createHash('sha256').update(fs.readFileSync(helper)).digest('hex')+'\n');
 const paths = await packager({
  dir: path.join(root, 'app'), out: path.join(root, 'dist'), name: 'Sang4MSilicon',
  platform: 'darwin', arch: 'arm64', electronVersion: '44.7.0',
  appBundleId: 'dev.connectlab.mchip-vpn-login', appVersion: '0.4.0-beta.1',
  appCategoryType: 'public.app-category.utilities', asar: true, overwrite: true,
  prune: true, osxSign: false,
  extraResource: path.join(root, '.build', 'bin'),
  extendInfo: {NSAppTransportSecurity: {NSAllowsArbitraryLoads: true}, NSLocalNetworkUsageDescription: '连接你指定的 VPN 网关并获取认证验证码。'},
  download: {cacheRoot: path.join(root, '.cache', 'electron')}
 });
 fs.writeFileSync(path.join(root,'dist','build-info.json'), JSON.stringify({version:'0.4.0-beta.1', platform:'darwin',arch:'arm64',electron:'44.7.0',signed:false,notarized:false,authenticationOnly:false,proxyMode:true,tunMode:true,vpnEngine:"zju-connect",vpnEngineCommit:"c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63",paths},null,2));
 console.log(paths.join('\n'));
})().catch(e => { console.error(e.message); process.exitCode = 1; });
