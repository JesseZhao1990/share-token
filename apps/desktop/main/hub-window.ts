import { BrowserWindow, session, type Session } from 'electron';
import { randomUUID } from 'node:crypto';
import type { HubTrustProfile } from '../../../packages/hub-client/trust.js';
import { acceptsHubCertificate, acceptsHubUrl } from './hub-trust.js';

/** A remote Hub never receives the desktop preload, local IPC API, or system trust. */
export class HubWindowManager {
  private window: BrowserWindow | null = null;
  private session: Session | null = null;
  private identity = '';
  private expiryTimer: ReturnType<typeof setInterval> | null = null;

  async open(profile: HubTrustProfile, target: string): Promise<void> {
    if (!acceptsHubUrl(profile, target)) throw new Error('空间页面地址或证书无效，请重新导入连接文件。');
    const identity = profile.hubUrl + '\0' + profile.certificatePem;
    if (this.identity && this.identity !== identity) await this.close();
    if (!this.session) {
      this.identity = identity;
      const isolated = session.fromPartition(`share-token-hub-${randomUUID()}`, { cache: false });
      this.session = isolated;
      isolated.setSSLConfig({ minVersion: 'tls1.2' });
      isolated.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
      isolated.setPermissionCheckHandler(() => false);
      isolated.on('will-download', event => event.preventDefault());
      isolated.webRequest.onBeforeRequest((details, callback) => callback({ cancel: !acceptsHubUrl(profile, details.url, true) }));
      isolated.setCertificateVerifyProc((request, callback) => {
        if (request.hostname !== new URL(profile.hubUrl).hostname) { callback(-3); return; }
        callback(acceptsHubCertificate(profile, request.hostname, request.certificate.data) ? 0 : -2);
      });
      this.expiryTimer = setInterval(() => { if (!acceptsHubUrl(profile, profile.hubUrl)) void this.close(); }, 30_000);
      this.expiryTimer.unref();
    }
    if (!this.window || this.window.isDestroyed()) {
      const window = new BrowserWindow({ width: 1120, height: 820, minWidth: 760, minHeight: 560, show: false,
        title: `共享token · ${profile.hubUrl}`, webPreferences: { session: this.session, sandbox: true, contextIsolation: true,
          nodeIntegration: false, nodeIntegrationInSubFrames: false, webSecurity: true, webviewTag: false, devTools: false,
          spellcheck: false, safeDialogs: true, navigateOnDragDrop: false } });
      this.window = window;
      window.setMenu(null);
      window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
      window.webContents.on('will-navigate', (event, url) => { if (!acceptsHubUrl(profile, url)) event.preventDefault(); });
      window.webContents.on('will-redirect', (event, url) => { if (!acceptsHubUrl(profile, url)) event.preventDefault(); });
      window.webContents.on('will-frame-navigate', details => { if (!acceptsHubUrl(profile, details.url)) details.preventDefault(); });
      window.webContents.on('will-attach-webview', event => event.preventDefault());
      window.on('page-title-updated', event => event.preventDefault());
      window.on('closed', () => { if (this.window === window) this.window = null; });
      window.once('ready-to-show', () => window.show());
    }
    await this.window.loadURL(target);
    this.window.show();
    this.window.focus();
  }

  async close(): Promise<void> {
    if (this.expiryTimer) clearInterval(this.expiryTimer); this.expiryTimer = null;
    const window = this.window; this.window = null;
    if (window && !window.isDestroyed()) window.destroy();
    const isolated = this.session; this.session = null; this.identity = '';
    if (isolated) {
      isolated.webRequest.onBeforeRequest((_details, callback) => callback({ cancel: true }));
      isolated.setCertificateVerifyProc((_request, callback) => callback(-2));
      await Promise.allSettled([isolated.closeAllConnections(), isolated.clearStorageData(), isolated.clearAuthCache()]);
      isolated.setCertificateVerifyProc(null);
    }
  }
}
