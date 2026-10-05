import { experimentalSubscriptionEnabled, assertExperimentalSubscriptionEnabled } from '../../../packages/upstream/experimental.js';
import { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, net, powerMonitor, protocol, session, shell, Tray } from 'electron';
import { join, resolve, sep, extname, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { access, writeFile, realpath, mkdir } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { randomUUID, createHash } from 'node:crypto';
import { hostname, release } from 'node:os';
import { z } from 'zod';
import { PrivateStore } from '../../../packages/platform/private-store.js';
import { createLocalSecretCipher } from '../../../packages/platform/local-secret.js';
import { policySchema } from '../../../packages/protocol/index.js';
import { WorkerProcess } from './worker.js';
import { HubWindowManager } from './hub-window.js';
import { assertSavedHubTrust, hubTrustDisplay, loadHubTrustProfile, readHubTrustFile, saveHubTrustProfile } from './hub-trust.js';
import { validateHubTrustProfile, type HubTrustProfile } from '../../../packages/hub-client/trust.js';
import type { SubscriptionAccountStatus } from '../../../packages/upstream/subscription.js';
import type { DeviceCredentials, PairingDisplay } from '../../../packages/hub-client/index.js';
import type { ConsumerSessionSnapshot } from '../../../packages/client-core/consumer.js';

protocol.registerSchemesAsPrivileged([{ scheme: 'share', privileges: { standard: true, secure: true, supportFetchAPI: true } }]);
// The open-source edition uses an independent profile; do not restore private deployment state.
let dataDirectory = join(app.getPath('appData'), 'Share Token Open Source');
if (!app.isPackaged && process.env.SHARE_TOKEN_TEST_DATA_DIR) dataDirectory = resolve(process.env.SHARE_TOKEN_TEST_DATA_DIR);
const explicitDataDirectory = app.commandLine.getSwitchValue('user-data-dir');
if (explicitDataDirectory && isAbsolute(explicitDataDirectory)) dataDirectory = explicitDataDirectory;
mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
app.setPath('userData', dataDirectory);
app.setName('共享token');
const locked = app.requestSingleInstanceLock();
if (!locked) { app.quit(); } else { void app.whenReady().then(start).catch(async () => { await dialog.showMessageBox({ type: 'error', message: '共享token无法启动', detail: '请检查安装包是否完整，以及应用数据目录是否可读写。没有启动模型调用。' }); app.exit(1); }); }

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let control: WorkerProcess;
let donor: WorkerProcess;
let secrets: PrivateStore;
let quitting = false;
let ready = false;
let lastError = '';
let pairing: PairingDisplay | null = null;
let connectedHub = '';
let donorInitialized = false;
let boundDeviceId = '';
let subscriptionStatus: SubscriptionAccountStatus | null = null;
let subscriptionBinary: string | null = null;
let hubTrust: HubTrustProfile | null = null;
const hubWindows = new HubWindowManager();
let actionTail = Promise.resolve<unknown>(null);
const terminals = new Map<string, BrowserWindow>();
const buffers = new Map<string, string>();
const terminalSequences = new Map<string, number>();
const terminalSessions = new Map<string, ConsumerSessionSnapshot>();
const directories = new Map<string, string>();
const executables = new Map<string, string>();
const sessionIdSchema = z.object({ sessionId: z.string().min(1).max(128) }).strict();

function push(value: unknown) { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('share:event', value); }
function workerEvent(value: unknown) {
  if (!value || typeof value !== 'object') return;
  const event = value as { type: string; sessionId?: string; data?: string };
  if (event.type === 'session.updated') {
    const snapshot = (value as { session?: ConsumerSessionSnapshot }).session;
    if (snapshot?.sessionId) {
      terminalSessions.set(snapshot.sessionId, snapshot);
      const target = terminals.get(snapshot.sessionId);
      if (target && !target.isDestroyed()) target.webContents.send('share:event', value);
    }
  }
  if (event.type === 'terminal.data' && event.sessionId && typeof event.data === 'string') {
    const sequence = (terminalSequences.get(event.sessionId) ?? 0) + 1; terminalSequences.set(event.sessionId, sequence);
    buffers.set(event.sessionId, ((buffers.get(event.sessionId) ?? '') + event.data).slice(-128 * 1024));
    const target = terminals.get(event.sessionId); if (target && !target.isDestroyed()) target.webContents.send('share:event', { ...event, sequence }); return;
  }
  if (event.type === 'terminal.exit' && event.sessionId) { const target = terminals.get(event.sessionId); if (target && !target.isDestroyed()) target.webContents.send('share:event', value); }
  push(value);
}
function secureWindow(window: BrowserWindow) {
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', event => event.preventDefault());
  window.webContents.on('will-attach-webview', event => event.preventDefault());
}
function makeWindow(terminalId?: string) {
  const window = new BrowserWindow({ width: terminalId ? 1060 : 1180, height: 800, minWidth: 820, minHeight: 600, show: false, icon: join(app.getAppPath(), 'dist/apps/desktop/brand/app-icon.png'), title: terminalId ? '共享token · Codex 终端' : '共享token · 朋友间共享', backgroundColor: '#f5f5f0', titleBarStyle: 'hiddenInset', webPreferences: { preload: join(app.getAppPath(), 'dist/apps/desktop/preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false, spellcheck: false, webSecurity: true } });
  secureWindow(window);
  void window.loadURL(`share://app/index.html${terminalId ? `?terminal=${encodeURIComponent(terminalId)}` : ''}`);
  window.once('ready-to-show', () => window.show());
  return window;
}
function showMain() { if (!mainWindow || mainWindow.isDestroyed()) { mainWindow = makeWindow(); mainWindow.on('close', event => { if (!quitting) { event.preventDefault(); mainWindow?.hide(); } }); } else mainWindow.show(); }
async function openTerminal(id: string) {
  const state = await control.request<{ sessions: { id?: string; sessionId?: string }[] }>('snapshot');
  if (!state.sessions.some(s => (s.sessionId ?? s.id) === id)) throw new Error('会话不存在。');
  const existing = terminals.get(id); if (existing && !existing.isDestroyed()) { existing.show(); return; }
  const window = makeWindow(id); terminals.set(id, window); window.on('closed', () => terminals.delete(id));
}
function ownedTerminal(event: Electron.IpcMainInvokeEvent): string | null {
  for (const [id, window] of terminals) if (window.webContents.id === event.sender.id) return id;
  return null;
}
function trustedFrame(event: Electron.IpcMainInvokeEvent) {
  if (event.senderFrame !== event.sender.mainFrame) throw new Error('不允许子页面调用本地功能。');
  const url = new URL(event.senderFrame.url);
  if (url.origin !== 'share://app' && !(url.protocol === 'share:' && url.hostname === 'app')) throw new Error('页面来源无效。');
}
async function initDonor(hubUrl: string) {
  if (donorInitialized && connectedHub === hubUrl) return;
  if (!boundDeviceId) throw new Error('设备身份尚未确认。');
  const scope = createHash('sha256').update(`${hubUrl}\0${boundDeviceId}`).digest('hex').slice(0, 24);
  await donor.request('init', { hubUrl, hubTrust: trustForHub(hubUrl), stateDir: join(app.getPath('userData'), 'spaces', scope) }); donorInitialized = true; connectedHub = hubUrl;
}
function trustForHub(hubUrl: string): HubTrustProfile | undefined {
  if (!hubTrust) return undefined;
  const trust = validateHubTrustProfile(hubTrust);
  if (trust.hubUrl !== new URL(hubUrl).origin) throw new Error('Hub 地址与已导入的连接文件不一致，请先断开并导入对应空间的连接文件。');
  return hubTrust;
}
async function openHubPage(url: string) {
  const origin = new URL(url).origin;
  const trust = trustForHub(origin);
  if (trust) await hubWindows.open(trust, url);
  else await shell.openExternal(url);
}
async function snapshot() {
  const [consumer, sharing] = await Promise.all([control.request<Record<string, unknown>>('snapshot'), donor.request('snapshot')]);
  return { ...consumer, connected: consumer.connected === true, sharing, pairing, deviceName: hostname(), version: app.getVersion(), platform: `${process.platform}-${process.arch}`, credentialStorage: 'local-encrypted', lastError: consumer.connectionError ?? lastError, buildChannel: 'open-source-mock-preview', experimentalSubscriptionEnabled: experimentalSubscriptionEnabled(), subscription: subscriptionStatus, subscriptionReady: !!subscriptionBinary, hubTrust: hubTrust ? hubTrustDisplay(hubTrust) : null };
}
async function quit() {
  if (quitting) return;
  const answer = await dialog.showMessageBox(mainWindow ?? undefined as never, { type: 'question', message: '退出共享token？', detail: '将停止本应用的共享与 Codex 会话。已经到达上游的请求可能仍有消耗，未知结果会保留供核实。关闭窗口则继续在菜单栏运行。', buttons: ['返回', '停止并退出'], cancelId: 0, defaultId: 0 });
  if (answer.response !== 1) return;
  quitting = true; await hubWindows.close(); await donor.close().catch(() => {}); await control.close().catch(() => {}); tray?.destroy(); app.quit();
}
async function action(event: Electron.IpcMainInvokeEvent, method: string, value: unknown): Promise<unknown> {
  trustedFrame(event);
  const terminalId = ownedTerminal(event);
  if (terminalId) {
    if (method === 'terminal.attach') return { sessionId: terminalId, backlog: buffers.get(terminalId) ?? '', sequence: terminalSequences.get(terminalId) ?? 0, session: terminalSessions.get(terminalId) };
    if (method === 'terminal.write') { const args = z.object({ data: z.string().max(65536) }).strict().parse(value); return control.request(method, { sessionId: terminalId, ...args }); }
    if (method === 'terminal.resize') { const args = z.object({ cols: z.number().int().min(2).max(500), rows: z.number().int().min(2).max(200) }).strict().parse(value); return control.request(method, { sessionId: terminalId, ...args }); }
    throw new Error('终端窗口只能操作自己的会话。');
  }
  if (event.sender.id !== mainWindow?.webContents.id) throw new Error('窗口无权操作。');
  if (method === 'state') return snapshot();
  if (method === 'hub.import') {
    if (value !== undefined && value !== null) throw new Error('请使用系统文件选择窗口导入连接文件。');
    const state = await control.request<{ connected: boolean }>('snapshot');
    if (state.connected || pairing) throw new Error('请先断开当前空间或取消配对，再导入连接文件。');
    const selected = await dialog.showOpenDialog(mainWindow!, { properties: ['openFile'], title: '导入朋友提供的内网连接文件', filters: [{ name: '共享token连接文件', extensions: ['json'] }] });
    if (selected.canceled || !selected.filePaths[0]) return null;
    const profile = await readHubTrustFile(selected.filePaths[0]);
    if (donorInitialized) await donor.request('stop');
    await hubWindows.close();
    hubTrust = await saveHubTrustProfile(app.getPath('userData'), profile);
    donorInitialized = false; connectedHub = ''; lastError = '';
    push({ type: 'hub.trust.changed' });
    return hubTrustDisplay(hubTrust);
  }
  if (method === 'hub.open') {
    if (value !== undefined && value !== null) throw new Error('空间管理入口不接受自定义地址。');
    const origin = connectedHub || hubTrust?.hubUrl;
    if (!origin) throw new Error('请先导入连接文件或连接朋友空间。');
    await openHubPage(origin + '/'); return null;
  }
  if (method === 'pair.begin') {
    const args = z.object({ hubUrl: z.string().url().max(2048), deviceName: z.string().trim().min(1).max(80) }).strict().parse(value);
    const state = await control.request<{ connected: boolean; sessions: unknown[] }>('snapshot');
    if (state.connected) throw new Error('请先断开当前空间，再连接新空间。');
    await donor.request('stop').catch(() => {});
    pairing = await control.request<PairingDisplay>(method, { ...args, hubTrust: trustForHub(args.hubUrl) }); connectedHub = new URL(args.hubUrl).origin; lastError = ''; return pairing;
  }
  if (method === 'pair.join') {
    const args = z.object({ hubUrl: z.string().url().max(2048), deviceName: z.string().trim().min(1).max(80), sharedCode: z.string().max(32).transform(value => value.replace(/[\s-]/g, '')).pipe(z.string().regex(/^\d{8}$/)) }).strict().parse(value);
    if (pairing) throw new Error('请先取消已有的设备确认，再用配对码连接。');
    const state = await control.request<{ connected: boolean }>('snapshot');
    if (state.connected) throw new Error('这台电脑已经连接朋友空间。');
    await donor.request('stop').catch(() => {});
    connectedHub = new URL(args.hubUrl).origin;
    const result = await control.request<{ status: string }>(method, { ...args, hubTrust: trustForHub(args.hubUrl) });
    if (result.status !== 'approved') throw new Error('连接尚未确认，请稍后再试。');
    lastError = ''; await hubWindows.close(); await initDonor(connectedHub);
    push({ type: 'device.connected' }); return null;
  }
  if (method === 'pair.open') {
    if (!pairing || new URL(pairing.verificationUriComplete).origin !== connectedHub) throw new Error('没有有效的配对地址。');
    await openHubPage(pairing.verificationUriComplete); return null;
  }
  if (method === 'pair.poll') {
    try { const result = await control.request<{ status: string }>(method); if (result.status === 'approved') { pairing = null; await initDonor(connectedHub); } return result; }
    catch (error) { if (['ACCESS_DENIED', 'EXPIRED_TOKEN', 'PAIRING_CANCELLED', 'SHARE_CREDENTIAL_STORE_FAILED', 'SHARE_PAIRING_MISSING'].includes(String((error as { code?: string }).code))) { pairing = null; await hubWindows.close(); } throw error; }
  }
  if (method === 'pair.cancel') {
    let remoteCancelled = false;
    try { await control.request(method); remoteCancelled = true; }
    catch { /* Local cancellation must remain available while the Hub is offline. */ }
    finally { pairing = null; await hubWindows.close(); if (!remoteCancelled) lastError = '本机已取消配对，远端取消尚未确认。旧配对码将在到期后失效。'; }
    return { remoteCancelled };
  }
  if (method === 'logout') {
    await donor.request('stop').catch(() => {}); const result = await control.request('logout'); await secrets.clear(); await hubWindows.close(); pairing = null; donorInitialized = false; connectedHub = ''; boundDeviceId = ''; directories.clear(); executables.clear();
    for (const window of terminals.values()) window.destroy(); terminals.clear(); buffers.clear(); terminalSequences.clear(); terminalSessions.clear(); return result;
  }
  if (method === 'directory.select') { const selected = await dialog.showOpenDialog(mainWindow!, { properties: ['openDirectory'], title: '选择在本机使用 Codex 的项目' }); if (selected.canceled) return null; const path = selected.filePaths[0]!; const id = randomUUID(); directories.set(id, path); return { id, path }; }
  if (method === 'codex.detect') {
    const found = await control.request<unknown[]>('codex.detect');
    return found.map(item => { const entry = item as { path: string }; const id = randomUUID(); executables.set(id, entry.path); return { ...(item as object), id }; });
  }
  if (method === 'codex.select') { const selected = await dialog.showOpenDialog(mainWindow!, { properties: ['openFile'], title: '选择已安装的 Codex 可执行文件' }); if (selected.canceled) return null; const id = randomUUID(); executables.set(id, selected.filePaths[0]!); return { id, path: selected.filePaths[0], version: '启动前校验' }; }
  if (method.startsWith('subscription.')) assertExperimentalSubscriptionEnabled();
  if (method === 'subscription.status') {
    subscriptionStatus = await donor.request<SubscriptionAccountStatus>('subscription.status'); return subscriptionStatus;
  }
  if (method === 'subscription.select') {
    const args = z.object({ executableId: z.string().uuid() }).strict().parse(value);
    const binary = executables.get(args.executableId); if (!binary) throw new Error('请重新检测或选择 Codex 程序。');
    subscriptionStatus = await donor.request<SubscriptionAccountStatus>('subscription.init', { binary, codexHome: join(app.getPath('userData'), 'subscription', 'codex') });
    subscriptionBinary = binary; return subscriptionStatus;
  }
  if (method === 'subscription.login') {
    if (!subscriptionBinary) throw new Error('请先选择用于订阅接入的 Codex 程序。');
    const login = await donor.request<{ loginId: string; authUrl: string }>('subscription.login');
    let url: URL; try { url = new URL(login.authUrl); } catch { await donor.request('subscription.cancel'); throw new Error('Codex 未返回有效的官方登录地址。'); }
    if (url.protocol !== 'https:' || url.hostname !== 'auth.openai.com' || url.port || url.username || url.password || url.hash || url.pathname !== '/oauth/authorize') { await donor.request('subscription.cancel'); throw new Error('Codex 登录地址未通过官方 HTTPS 地址校验。'); }
    await shell.openExternal(url.href); return { loginId: login.loginId };
  }
  if (method === 'subscription.cancel') return donor.request('subscription.cancel');
  if (method === 'subscription.logout') { subscriptionStatus = await donor.request<SubscriptionAccountStatus>('subscription.logout'); return subscriptionStatus; }
  if (method === 'consumer.start') {
    const args = z.object({ sourceId: z.string().min(1).max(128), model: z.string().min(1).max(128), directoryId: z.string().uuid(), executableId: z.string().uuid() }).strict().parse(value);
    const cwd = directories.get(args.directoryId), codexPath = executables.get(args.executableId); if (!cwd || !codexPath) throw new Error('请重新选择项目和 Codex 程序。');
    const result = await control.request<{ sessionId?: string; id?: string }>(method, { sourceId: args.sourceId, model: args.model, cwd, codexPath });
    const id = result.sessionId ?? result.id; if (id) await openTerminal(id); return result;
  }
  if (method === 'consumer.stop') return control.request(method, sessionIdSchema.parse(value));
  if (method === 'terminal.open') { await openTerminal(sessionIdSchema.parse(value).sessionId); return null; }
  if (method === 'donor.configure') {
    const args = z.object({ name: z.string().trim().min(1).max(80), kind: z.enum(['mock', 'subscription']), policy: policySchema }).strict().parse(value);
    await initDonor(connectedHub); return donor.request('configure', args);
  }
  if (method === 'donor.start') return donor.request('start');
  if (method === 'donor.drain') return donor.request('drain');
  if (method === 'donor.stop') return donor.request('stop');
  if (method === 'donor.resolve') {
    const answer = await dialog.showMessageBox(mainWindow!, { type: 'warning', message: '核实此来源的未知请求？', detail: '只在你已核实并接受未决消耗后继续。旧请求可能仍在上游执行；确认不会退款、重试或把 UNKNOWN 改为成功，也不会清除身份变更造成的阻挡。来源保持暂停。', buttons: ['保持暂停', '已核实并接受'], cancelId: 0, defaultId: 0 });
    if (answer.response !== 1) return null; await donor.request('drain'); return donor.request('resolve');
  }
  if (method === 'device.revoke') { const args = z.object({ deviceId: z.string().min(1).max(128) }).strict().parse(value); if (args.deviceId === boundDeviceId) return action(event, 'logout', undefined); return control.request('hub.request', { method: 'DELETE', path: `/client/v2/devices/${encodeURIComponent(args.deviceId)}` }); }
  if (method === 'session.resolve') {
    const args = sessionIdSchema.parse(value);
    const answer = await dialog.showMessageBox(mainWindow!, { type: 'warning', message: '核实该会话的交付状态？', detail: '此操作确认该会话全部未决交付。已执行请求的响应无法回放，可能已有消耗；确认保留原记录，不重新发送模型请求，也不解除来源的执行未知阻挡。', buttons: ['保持待核实', '已核实并接受'], cancelId: 0, defaultId: 0 });
    if (answer.response !== 1) return null;
    return control.request('hub.request', { method: 'POST', path: `/client/v2/sessions/${encodeURIComponent(args.sessionId)}/resolve-unknown`, body: { acknowledge: true } });
  }
  if (method === 'diagnostics.export') {
    const file = await dialog.showSaveDialog(mainWindow!, { defaultPath: `share-token-diagnostics-${Date.now()}.json`, filters: [{ name: 'JSON', extensions: ['json'] }] });
    if (!file.filePath) return null;
    const state = await snapshot();
    const sessions = [...terminalSessions.values()].map(value => ({ sessionId: value.sessionId, state: value.state, errorCode: value.errorCode ?? null, terminalStarted: value.terminalStarted ?? false, exitCode: value.exitCode ?? null, exitSignal: value.exitSignal ?? null }));
    const report = { version: state.version, platform: state.platform, arch: process.arch, osRelease: release(), channel: state.buildChannel, connected: state.connected, credentialStorage: state.credentialStorage, sessions, exportedAt: new Date().toISOString(), note: '仅导出版本、连接状态和会话错误码；不含凭据、项目路径、终端文本或模型正文。' };
    await writeFile(file.filePath, JSON.stringify(report, null, 2), { mode: 0o600 }); return { path: file.filePath };
  }
  if (method === 'app.quit') { void quit(); return null; }
  throw new Error('不支持的桌面操作。');
}
async function start() {
  const rendererRoot = join(app.getAppPath(), 'dist/desktop');
  protocol.handle('share', async request => {
    const url = new URL(request.url);
    const path = resolve(rendererRoot, `.${decodeURIComponent(url.pathname)}`);
    if (url.hostname !== 'app' || !path.startsWith(rendererRoot + sep) || !['.html', '.js', '.css', '.woff2', '.png'].includes(extname(path))) return new Response('Not found', { status: 404 });
    return net.fetch(pathToFileURL(path).toString());
  });
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'"] } }));
  await mkdir(app.getPath('userData'), { recursive: true, mode: 0o700 });
  const secretsDirectory = join(await realpath(app.getPath('userData')), 'local-secrets');
  secrets = new PrivateStore(join(secretsDirectory, 'device.encrypted'), await createLocalSecretCipher(secretsDirectory));
  let trustLoadFailed = false;
  try { hubTrust = await loadHubTrustProfile(app.getPath('userData')); } catch { trustLoadFailed = true; lastError = '保存的内网连接文件无效或证书已过期，请重新导入。'; }
  if (!hubTrust && !trustLoadFailed) {
    const bundledProfile = join(app.getAppPath(), 'dist/apps/desktop/default.connection.json');
    try { hubTrust = await readHubTrustFile(bundledProfile); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { trustLoadFailed = true; lastError = '内置空间连接信息无效，请在更多连接方式中更新。'; } }
  }
  const runtime = app.isPackaged ? join(app.getAppPath(), 'runtime', process.platform === 'win32' ? 'node.exe' : 'node') : join(app.getAppPath(), 'node_modules/node/bin/node');
  await access(runtime);
  const entry = join(app.getAppPath(), 'dist/apps/client-worker/host.js');
  control = new WorkerProcess(runtime, entry, 'consumer', undefined, async value => {
    const record = value as { hubUrl: string; credentials: DeviceCredentials | null };
    if (record.credentials) { const trust = trustForHub(record.hubUrl); if (trust) await saveHubTrustProfile(app.getPath('userData'), trust); await secrets.write({ ...record, hubTrustFingerprint256: trust ? hubTrustDisplay(trust).fingerprint256 : null }); boundDeviceId = record.credentials.deviceId; }
    else { await secrets.clear(); await hubWindows.close(); boundDeviceId = ''; donorInitialized = false; void donor?.request('suspend').catch(() => {}); push({ type: 'device.disconnected' }); }
  });
  donor = new WorkerProcess(runtime, entry, 'donor', (method, path, body) => control.request('hub.request', { method, path, body }));
  for (const worker of [control, donor]) { worker.on('event', workerEvent); worker.on('stopped', message => { if (!quitting) { if (worker === control) { void donor.request('suspend').catch(() => {}); void hubWindows.close(); } lastError = String(message); push({ type: 'worker.stopped', message }); } }); }
  try {
    const saved = await secrets.read<{ hubUrl: string; credentials: DeviceCredentials; hubTrustFingerprint256?: string | null }>();
    if (saved && !trustLoadFailed) {
      assertSavedHubTrust(saved.hubUrl, saved.hubTrustFingerprint256, hubTrust); connectedHub = saved.hubUrl; boundDeviceId = saved.credentials.deviceId;
      await control.request('connect', { ...saved, hubTrust: trustForHub(saved.hubUrl) }); await initDonor(saved.hubUrl);
    } else if (!saved) {
      // Do not attempt to decrypt the legacy Keychain-backed file: even reading
      // it through safeStorage can present a password dialog after an update.
      // Preserve that file, and let the user join once using the familiar code.
      try { await access(join(app.getPath('userData'), 'device.encrypted')); if (!lastError) lastError = '本次更新后，请重新输入一次配对码；朋友可能需要重新允许你使用共享。以后打开会自动连接。'; }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
  } catch { lastError = '上次连接未恢复，请检查网络、连接证书或重新输入配对码。'; }
  ipcMain.handle('share:action', async (event, method: unknown, args: unknown) => {
    if (typeof method !== 'string' || method.length > 80 || JSON.stringify(args ?? null).length > 128 * 1024) return { ok: false, message: '请求无效。' };
    const invoke = () => action(event, method, args);
    try {
      const result = ['state', 'terminal.write', 'terminal.resize', 'terminal.attach'].includes(method) ? await invoke() : await (actionTail = actionTail.catch(() => null).then(invoke));
      return { ok: true, value: result };
    } catch (error) { return { ok: false, message: error instanceof z.ZodError ? '输入内容无效，请检查后重试。' : error instanceof Error ? error.message.slice(0, 500) : '操作未完成。' }; }
  });
  const brandDirectory = join(app.getAppPath(), 'dist/apps/desktop/brand');
  if (process.platform === 'darwin') app.dock?.setIcon(nativeImage.createFromPath(join(brandDirectory, 'app-icon.png')));
  const icon = nativeImage.createFromPath(join(brandDirectory, 'trayTemplate.png'));
  icon.setTemplateImage(true); tray = new Tray(icon); tray.setToolTip('共享token · 关窗后继续运行');
  tray.setContextMenu(Menu.buildFromTemplate([{ label: '打开共享token', click: showMain }, { label: '暂停接单', click: () => { void donor.request('drain').catch(() => {}); } }, { label: '立即停止共享', click: () => { void donor.request('stop').catch(() => {}); } }, { type: 'separator' }, { label: '退出共享token', click: () => { void quit(); } }]));
  Menu.setApplicationMenu(Menu.buildFromTemplate([{ label: '共享token', submenu: [{ role: 'about' }, { type: 'separator' }, { label: '退出共享token', accelerator: 'CmdOrCtrl+Q', click: () => { void quit(); } }] }, { label: '编辑', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] }, { label: '窗口', submenu: [{ role: 'minimize' }, { role: 'close' }] }]));
  powerMonitor.on('suspend', () => { void donor.request('suspend').catch(() => {}); });
  powerMonitor.on('resume', () => { void donor.request('wake').catch(() => {}); push({ type: 'system.resumed' }); });
  ready = true; showMain();
}
app.on('second-instance', () => { if (ready) showMain(); });
app.on('activate', () => { if (ready) showMain(); });
app.on('window-all-closed', () => {});
app.on('before-quit', event => { if (!quitting && ready) { event.preventDefault(); void quit(); } });
