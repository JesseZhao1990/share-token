import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { HubClient, type DeviceCredentials } from '../../packages/hub-client/index.js';
import { validateHubTrustProfile, type HubTrustProfile } from '../../packages/hub-client/trust.js';
import { ConsumerController } from '../../packages/client-core/consumer.js';
import { detectCodex, inspectCodexPath } from '../../packages/client-core/launcher.js';
import { DonorController } from '../../packages/client-core/donor.js';
import { CodexSubscriptionAccount, SubscriptionAdapter, MockAdapter, assertExperimentalSubscriptionEnabled } from '../../packages/upstream/index.js';
import { ShareError, type Grant, type Member, type Source } from '../../packages/protocol/index.js';
import { restoreClientError, serializeClientError } from '../../packages/protocol/client-errors.js';

const role = process.argv[2];
if (!process.send || !['consumer', 'donor'].includes(role ?? '')) throw new Error('This worker requires a private desktop IPC parent.');
const send = (message: object) => { if (process.connected) process.send!(message, () => {}); };
const emit = (value: unknown) => send({ type: 'event', value });
const requests = new Map<string, { resolve(value: unknown): void; reject(error: Error): void; timer: NodeJS.Timeout }>();
function parentRequest(type: 'hub.request' | 'credentials.save', value: Record<string, unknown>): Promise<unknown> {
  if (!process.connected || closing) return Promise.reject(restoreClientError({ code: 'SHARE_WORKER_UNAVAILABLE' }));
  const id = randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { requests.delete(id); reject(restoreClientError({ code: 'SHARE_WORKER_TIMEOUT' })); }, 20_000);
    requests.set(id, { resolve, reject, timer }); process.send!({ type, id, ...value }, error => { if (error) { clearTimeout(timer); requests.delete(id); reject(restoreClientError({ code: 'SHARE_WORKER_UNAVAILABLE' })); } });
  });
}
let hub: HubClient | null = null;
let connectedTrust = '';
let consumer: ConsumerController | null = null;
let donor: DonorController | null = null;
let subscription: CodexSubscriptionAccount | null = null;
let closing = false;
const requireHub = () => { if (!hub) throw new ShareError('SHARE_PAIRING_REQUIRED', '请先连接朋友空间。', 401); return hub; };
const object = (value: unknown) => (value ?? {}) as Record<string, unknown>;

async function connect(args: { hubUrl: string; credentials?: DeviceCredentials | null; hubTrust?: HubTrustProfile }) {
  if (consumer) await consumer.close();
  hub = new HubClient({ baseUrl: args.hubUrl, hubTrust: args.hubTrust, credentials: args.credentials, onCredentials: async credentials => {
    await parentRequest('credentials.save', { hubUrl: args.hubUrl, credentials });
  } });
  consumer = new ConsumerController({ hub, onEvent: emit });
  connectedTrust = JSON.stringify(args.hubTrust ?? null);
  return hub.meta();
}
async function close() {
  if (closing) return; closing = true;
  for (const wait of requests.values()) { clearTimeout(wait.timer); wait.reject(new Error('Worker closing')); } requests.clear();
  await Promise.allSettled([consumer?.close(), donor?.close()]);
  await subscription?.close();
}
async function handle(method: string, value: unknown): Promise<unknown> {
  const args = object(value);
  if (method === 'close') { await close(); return null; }
  if (closing) throw new Error('Worker is closing.');
  if (role === 'donor') {
    if (method.startsWith('subscription.')) assertExperimentalSubscriptionEnabled();
    if (method === 'subscription.init') {
      const installation = await inspectCodexPath(String(args.binary));
      if (installation.version !== '0.153.4') throw new ShareError('SHARE_CODEX_VERSION_UNSUPPORTED', '订阅接入需要 Codex CLI 0.153.4，请选择兼容版本。', 409);
      await donor?.stopNow('subscription_binary_changed');
      await subscription?.close();
      subscription = new CodexSubscriptionAccount({ codexHome: String(args.codexHome), binary: installation.path });
      return subscription.inspect();
    }
    if (method.startsWith('subscription.')) {
      if (!subscription) throw new ShareError('SHARE_SUBSCRIPTION_UNAVAILABLE', '请先选择本机 Codex 程序。', 409);
      if (method === 'subscription.status') return subscription.inspect();
      if (method === 'subscription.login') { await donor?.stopNow('subscription_login'); return subscription.startLogin(); }
      if (method === 'subscription.cancel') return subscription.cancelLogin();
      if (method === 'subscription.logout') { await donor?.stopNow('subscription_logout'); await subscription.logout(); return subscription.inspect(); }
      throw new ShareError('SHARE_INPUT_INVALID', '不支持的订阅账号操作。');
    }
    if (method === 'init') {
      await donor?.close();
      const hubUrl = String(args.hubUrl);
      const hubTrust = args.hubTrust ? validateHubTrustProfile(args.hubTrust) : undefined;
      donor = new DonorController({ stateDir: join(String(args.stateDir), 'donor'), hubTrust, hub: { baseUrl: hubUrl, request: <T>(method: string, path: string, body?: unknown) => parentRequest('hub.request', { method, path, body }) as Promise<T> }, subscriptionAccount: { inspect: () => { if (!subscription) throw new ShareError('SHARE_SUBSCRIPTION_UNAVAILABLE', '请先选择 Codex 程序并登录订阅账号。', 409); return subscription.inspect(); } }, adapterFactory: config => { if (config.kind === 'mock') return new MockAdapter({ accountBinding: config.accountBinding, models: config.policy.models }); if (!subscription || config.kind !== 'subscription') throw new ShareError('SHARE_SUBSCRIPTION_UNAVAILABLE', '请先登录订阅账号。', 409); return new SubscriptionAdapter({ account: subscription, models: config.policy.models, accountBinding: config.accountBinding }); }, onSnapshot: snapshot => emit({ type: 'donor.updated', snapshot }) });
      return donor.snapshot();
    }
    if (!donor) { if (method === 'snapshot') return null; throw new ShareError('SHARE_PAIRING_REQUIRED', '请先连接朋友空间。'); }
    if (method === 'configure') return donor.configure(args as never, { confirmExpansion: true });
    if (method === 'start') return donor.start();
    if (method === 'drain') return donor.drain();
    if (method === 'stop') return donor.stopNow('user_stop');
    if (method === 'resolve') return donor.resolveUnknown({ acknowledge: true });
    if (method === 'suspend') return donor.suspend();
    if (method === 'wake') return donor.wake();
    if (method === 'snapshot') return donor.snapshot();
    throw new Error('Unknown donor operation.');
  }
  if (method === 'connect') return connect(args as unknown as { hubUrl: string; credentials?: DeviceCredentials; hubTrust?: HubTrustProfile });
  if (method === 'pair.begin') { await connect({ hubUrl: String(args.hubUrl), hubTrust: args.hubTrust ? validateHubTrustProfile(args.hubTrust) : undefined }); return requireHub().startPairing({ deviceName: String(args.deviceName), platform: process.platform, clientVersion: '0.6.0', requestedScopes: ['consumer', 'donor'] }); }
  if (method === 'pair.join') {
    const trust = args.hubTrust ? validateHubTrustProfile(args.hubTrust) : undefined;
    if (!hub || hub.baseUrl !== new URL(String(args.hubUrl)).origin || connectedTrust !== JSON.stringify(trust ?? null)) await connect({ hubUrl: String(args.hubUrl), hubTrust: trust });
    const meta = await requireHub().meta();
    if (!meta.pairing.matchingCodeAvailable) throw new ShareError('SHARE_MATCHING_UNAVAILABLE', '连接服务尚未支持自选配对码，请更新连接服务后重试。', 409);
    return requireHub().joinWithMatchingCode({ deviceName: String(args.deviceName), platform: process.platform, clientVersion: '0.6.0', requestedScopes: ['consumer', 'donor'] }, String(args.sharedCode));
  }
  if (method === 'pair.poll') return requireHub().pollPairing();
  if (method === 'pair.cancel') return requireHub().cancelPairing();
  if (method === 'codex.detect') return detectCodex();
  if (method === 'hub.request') return requireHub().request(String(args.method), String(args.path), args.body);
  if (method === 'snapshot') {
    if (!hub?.getCredentials()) return { connected: false, sessions: consumer?.snapshot() ?? [] };
    const results = await Promise.allSettled([
      hub.request('GET', '/client/v2/me'), hub.request('GET', '/client/v2/sources'), hub.request('GET', '/client/v2/grants'),
      hub.request('GET', '/client/v2/devices'), hub.request('GET', '/client/v2/requests'), hub.request('GET', '/client/v2/members'),
    ]);
    const state: Record<string, unknown> = { connected: true, hubUrl: hub.baseUrl, sources: [], grants: [], devices: [], requests: [], members: [], sessions: consumer?.snapshot() ?? [] };
    for (const result of results) if (result.status === 'fulfilled') Object.assign(state, object(result.value)); else state.connectionError = '空间状态未完整同步，请检查网络或重新配对。';
    if (!hub.getCredentials()) return { connected: false, sessions: consumer?.snapshot() ?? [], connectionError: '设备身份已失效，请重新配对。' };
    return state;
  }
  if (method === 'consumer.start') {
    const client = requireHub();
    let grantId = typeof args.grantId === 'string' ? args.grantId : '';
    if (!grantId) {
      const { grants } = await client.request<{ grants: Grant[] }>('GET', '/client/v2/grants');
      const memberId = client.getCredentials()!.memberId;
      grantId = grants.find(g => g.sourceId === args.sourceId && g.memberId === memberId && !g.revoked && g.models.includes(String(args.model)))?.id ?? '';
      if (!grantId) { const created = await client.request<{ grant: Grant }>('POST', '/client/v2/grants', { sourceId: args.sourceId, label: '桌面会话', models: [args.model] }); grantId = created.grant.id; }
    }
    return consumer!.create({ grantId, model: String(args.model), cwd: String(args.cwd), codexPath: String(args.codexPath) });
  }
  if (method === 'consumer.stop') return consumer!.stop(String(args.sessionId));
  if (method === 'terminal.write') return consumer!.write(String(args.sessionId), String(args.data));
  if (method === 'terminal.resize') return consumer!.resize(String(args.sessionId), Number(args.cols), Number(args.rows));
  if (method === 'logout') {
    await consumer?.close();
    const credentials = hub?.getCredentials();
    let revoked = false;
    if (credentials) { try { await hub!.request('DELETE', `/client/v2/devices/${encodeURIComponent(credentials.deviceId)}`); revoked = true; } catch {} }
    await hub?.setCredentials(null); hub = null; consumer = null; return { revoked };
  }
  throw new Error('Unknown consumer operation.');
}
process.on('message', message => {
  const msg = object(message);
  if (msg.type === 'hub.reply' || msg.type === 'credentials.reply') {
    const pending = requests.get(String(msg.id)); if (!pending) return;
    clearTimeout(pending.timer); requests.delete(String(msg.id));
    if (msg.ok) pending.resolve(msg.value); else pending.reject(restoreClientError(msg.error)); return;
  }
  if (msg.type !== 'request' || typeof msg.id !== 'string' || typeof msg.method !== 'string') return;
  void handle(msg.method, msg.args).then(value => { send({ type: 'reply', id: msg.id, ok: true, value }); }, error => {
    send({ type: 'reply', id: msg.id, ok: false, error: serializeClientError(error) });
  });
});
process.once('disconnect', () => { void close().finally(() => process.exit(0)); });
process.once('SIGTERM', () => { void close().finally(() => process.exit(0)); });
