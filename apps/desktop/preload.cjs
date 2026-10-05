const { contextBridge, ipcRenderer } = require('electron');
const call = (method, args) => ipcRenderer.invoke('share:action', method, args).then(result => {
  if (!result.ok) throw new Error(result.message || '操作失败');
  return result.value;
});
contextBridge.exposeInMainWorld('shareToken', Object.freeze({
  state: () => call('state'),
  importHub: () => call('hub.import'),
  openHub: () => call('hub.open'),
  pair: args => call('pair.begin', args),
  joinSpace: args => call('pair.join', args),
  pollPairing: () => call('pair.poll'),
  cancelPairing: () => call('pair.cancel'),
  openPairing: () => call('pair.open'),
  logout: () => call('logout'),
  selectDirectory: () => call('directory.select'),
  detectCodex: () => call('codex.detect'),
  selectCodex: () => call('codex.select'),
  subscriptionSelect: executableId => call('subscription.select', { executableId }),
  subscriptionStatus: () => call('subscription.status'),
  subscriptionLogin: () => call('subscription.login'),
  subscriptionCancel: () => call('subscription.cancel'),
  subscriptionLogout: () => call('subscription.logout'),
  startSession: args => call('consumer.start', args),
  stopSession: sessionId => call('consumer.stop', { sessionId }),
  openTerminal: sessionId => call('terminal.open', { sessionId }),
  terminalAttach: () => call('terminal.attach'),
  terminalWrite: data => call('terminal.write', { data }),
  terminalResize: (cols, rows) => call('terminal.resize', { cols, rows }),
  saveSharing: args => call('donor.configure', args),
  startSharing: () => call('donor.start'),
  pauseSharing: () => call('donor.drain'),
  stopSharing: () => call('donor.stop'),
  resolveSharing: () => call('donor.resolve'),
  revokeDevice: deviceId => call('device.revoke', { deviceId }),
  resolveDelivery: args => call('session.resolve', args),
  exportDiagnostics: () => call('diagnostics.export'),
  quit: () => call('app.quit'),
  onEvent: callback => {
    const listener = (_event, value) => callback(value);
    ipcRenderer.on('share:event', listener);
    return () => ipcRenderer.removeListener('share:event', listener);
  },
}));
