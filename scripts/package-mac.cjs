'use strict';
const path = require('node:path');
const fs = require('node:fs');
(async () => {
 const {packager} = await import('@electron/packager');
 const root = path.resolve(__dirname, '..');
 const paths = await packager({
  dir: path.join(root, 'app'), out: path.join(root, 'dist'), name: 'M Chip VPN Login',
  platform: 'darwin', arch: 'arm64', electronVersion: '44.7.0',
  appBundleId: 'dev.connectlab.mchip-vpn-login', appVersion: '0.1.0-beta.1',
  appCategoryType: 'public.app-category.utilities', asar: true, overwrite: true,
  prune: true, osxSign: false,
  extendInfo: {NSAppTransportSecurity: {NSAllowsArbitraryLoads: true}, NSLocalNetworkUsageDescription: '连接你指定的 VPN 网关并获取认证验证码。'},
  download: {cacheRoot: path.join(root, '.cache', 'electron')}
 });
 fs.writeFileSync(path.join(root,'dist','build-info.json'), JSON.stringify({version:'0.1.0-beta.1', platform:'darwin',arch:'arm64',electron:'44.7.0',signed:false,notarized:false,authenticationOnly:true,paths},null,2));
 console.log(paths.join('\n'));
})().catch(e => { console.error(e.message); process.exitCode = 1; });
