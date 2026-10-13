'use strict';
const fs=require('node:fs'), path=require('node:path'), assert=require('node:assert/strict'), {createHash}=require('node:crypto');
(async()=>{
 const asar=await import('@electron/asar');const bundle=process.argv[2];if(!bundle)throw Error('Expected app path');
 const resource=path.join(bundle,'Contents/Resources');const archive=path.join(resource,'app.asar');
 for(const name of ['main.cjs','preload.cjs','auth.cjs','vpn.cjs','tun-launcher.cjs','preferences.cjs','renderer.js','index.html','style.css','package.json'])assert.deepEqual(asar.extractFile(archive,name),fs.readFileSync(path.join(__dirname,'../app',name)),'Source mismatch: '+name);
 const helper=path.join(resource,'bin/mchip-vpn-helper');assert.equal(createHash('sha256').update(fs.readFileSync(helper)).digest('hex'),fs.readFileSync(helper+'.sha256','utf8').trim());
 console.log('Packaged source and signed helper checksum verified');
})().catch(e=>{console.error(e.message);process.exitCode=1});
