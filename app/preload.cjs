'use strict';
const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('vpnAuth', Object.freeze({
  initialize: server => ipcRenderer.invoke('auth:call', {action: 'initialize', data: {server}}),
  captcha: () => ipcRenderer.invoke('auth:call', {action: 'captcha'}),
  login: data => ipcRenderer.invoke('auth:call', {action: 'login', data}),
  challenge: value => ipcRenderer.invoke('auth:call', {action: 'challenge', data: {value}}),
  logout: () => ipcRenderer.invoke('auth:call', {action: 'logout'})
}));
