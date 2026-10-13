'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const {randomBytes} = require('node:crypto');
const {serverURL} = require('./auth.cjs');
class Preferences {
  constructor(directory) { this.directory = directory; this.file = path.join(directory, 'server.json'); }
  async readServer() {
    try {
      const stat = await fs.lstat(this.file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) return '';
      const value = JSON.parse(await fs.readFile(this.file, 'utf8'));
      return serverURL(value.server).origin;
    } catch { return ''; }
  }
  async saveServer(value) {
    const server = serverURL(value).origin;
    await fs.mkdir(this.directory, {recursive: true, mode: 0o700});
    const temporary = path.join(this.directory, '.server-' + randomBytes(16).toString('hex'));
    try {
      await fs.writeFile(temporary, JSON.stringify({server}) + '\n', {flag: 'wx', mode: 0o600});
      await fs.rename(temporary, this.file);
    } finally { await fs.rm(temporary, {force: true}); }
    return server;
  }
}
module.exports = {Preferences};
