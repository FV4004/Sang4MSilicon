'use strict';
const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('vpnAuth', Object.freeze({
  recoverNetwork: () => ipcRenderer.invoke('vpn:call', {action: 'recover'}),
  readSavedServer: () => ipcRenderer.invoke('preferences:server'),
  initialize: server => ipcRenderer.invoke('auth:call', {action: 'initialize', data: {server}}),
  captcha: () => ipcRenderer.invoke('auth:call', {action: 'captcha'}),
  login: data => ipcRenderer.invoke('auth:call', {action: 'login', data}),
  challenge: value => ipcRenderer.invoke('auth:call', {action: 'challenge', data: {value}}),
  logout: () => ipcRenderer.invoke('auth:call', {action: 'logout'}),
  connectVpn: data => ipcRenderer.invoke('vpn:call', {action: 'start', data}),
  disconnectVpn: () => ipcRenderer.invoke('vpn:call', {action: 'stop'}),
  vpnStatus: () => ipcRenderer.invoke('vpn:call', {action: 'status'}),
  openLicenses: () => ipcRenderer.invoke('vpn:call', {action: 'license'}),
  onVpnStatus: callback => {
    if (typeof callback !== 'function') throw new TypeError('状态回调无效。');
    const handler = (_event, status) => callback(status);
    ipcRenderer.on('vpn:status', handler);
    return () => ipcRenderer.removeListener('vpn:status', handler);
  }
}));
