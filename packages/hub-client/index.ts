import { createHash, randomBytes } from 'node:crypto';
import { ShareError, type Member } from '../protocol/index.js';
import { assertSafeUrl } from '../protocol/security.js';
import type { ClientAuthResponse, ClientDevice, ClientMeta, DevicePairingResponse } from '../protocol/client.js';
import { createHubFetch, validateHubTrustProfile, type HubTrustProfile } from './trust.js';
export { createHubFetch, validateHubTrustProfile, type HubTrustProfile, type ValidatedHubTrustProfile } from './trust.js';

export interface DeviceCredentials {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  refreshExpiresAt: number;
  deviceId: string;
  memberId: string;
}
export type PairedDevice = ClientDevice;
export interface PairingInput { deviceName: string; platform: string; clientVersion: string; requestedScopes: ('consumer' | 'donor')[] }
export interface PairingDisplay { pairingId: string; userCode: string; verificationUri: string; verificationUriComplete: string; expiresAt: number; interval: number }
export type PairingPoll = { status: 'pending'; retryAfterMs: number } | { status: 'approved'; member: Member; device: PairedDevice };
export interface HubClientOptions {
  baseUrl: string;
  credentials?: DeviceCredentials | null;
  /** Exactly one owning HubClient rotates the refresh token. Never send this callback to a renderer. */
  onCredentials?: (credentials: DeviceCredentials | null) => Promise<void> | void;
  /** Non-owning clients obtain access credentials here and never rotate refresh tokens themselves. */
  tokenProvider?: () => Promise<DeviceCredentials>;
  fetch?: typeof fetch;
  /** A public, imported certificate scoped to this exact private Hub origin. */
  hubTrust?: HubTrustProfile;
  controlTimeoutMs?: number;
}
type AuthResponse = ClientAuthResponse;
type PairingResponse = DevicePairingResponse;
interface PendingPairing { display: PairingDisplay; deviceCode: string; verifier: string; nextPollAt: number }

export class HubClientError extends ShareError {}

/** Transport for one trusted Hub. It never follows redirects or retries ambiguous writes. */
export class HubClient {
  readonly baseUrl: string;
  private credentials: DeviceCredentials | null;
  private readonly fetchImpl: typeof fetch;
  private pendingPairing: PendingPairing | null = null;
  private sharedCodePairing: PendingPairing | null = null;
  private codePairingMethod: 'join' | 'match' | null = null;
  private sharedJoinRunning = false;
  private refreshPromise: Promise<DeviceCredentials> | null = null;
  private credentialVersion = 0;
  private credentialPersistence: Promise<void> = Promise.resolve();
  private readonly invalidationListeners = new Set<() => void>();

  constructor(private readonly options: HubClientOptions) {
    const url = assertSafeUrl(options.baseUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.pathname !== '/') throw new HubClientError('SHARE_HUB_URL_INVALID', 'Hub 地址必须是 HTTPS 根地址；仅本机开发允许 HTTP。');
    this.baseUrl = url.origin;
    this.credentials = options.credentials ? validateCredentials(options.credentials) : null;
    const trust = options.hubTrust ? validateHubTrustProfile(options.hubTrust) : undefined;
    if (trust && trust.hubUrl !== this.baseUrl) throw new HubClientError('SHARE_HUB_TRUST_INVALID', 'Hub 连接文件与当前空间地址不匹配。');
    this.fetchImpl = options.fetch ?? (trust ? createHubFetch(trust) : fetch);
  }

  getCredentials(): DeviceCredentials | null { return this.credentials ? { ...this.credentials } : null; }
  onCredentialsInvalidated(listener: () => void): () => void { this.invalidationListeners.add(listener); return () => { this.invalidationListeners.delete(listener); }; }
  async setCredentials(credentials: DeviceCredentials | null): Promise<void> {
    const next = credentials ? validateCredentials(credentials) : null;
    const version = ++this.credentialVersion;
    if (!next) {
      this.credentials = null;
      for (const listener of this.invalidationListeners) { try { listener(); } catch { /* Cleanup observers cannot retain an invalid identity. */ } }
    }
    const persisted = this.credentialPersistence.catch(() => undefined).then(async () => { await this.options.onCredentials?.(next ? { ...next } : null); });
    this.credentialPersistence = persisted;
    try { await persisted; }
    catch (error) { if (next && version === this.credentialVersion) await this.setCredentials(null).catch(() => undefined); throw error; }
    if (version === this.credentialVersion) this.credentials = next;
  }

  async request<T>(method: string, path: string, body?: unknown, options: { signal?: AbortSignal } = {}): Promise<T> {
    const credentials = await this.accessCredentials();
    const version = this.credentialVersion;
    try { return await this.json<T>(method, path, body, credentials.accessToken, options.signal); }
    catch (error) {
      // An older request must not clear credentials acquired by a newer login/refresh.
      if (error instanceof ShareError && error.status === 401 && !this.options.tokenProvider && this.credentialVersion === version && this.credentials?.accessToken === credentials.accessToken) await this.setCredentials(null).catch(() => undefined);
      throw error;
    }
  }

  async meta<T = ClientMeta>() { return this.json<T>('GET', '/client/v2/meta'); }

  async startPairing(input: PairingInput): Promise<PairingDisplay> {
    if (this.pendingPairing) throw new HubClientError('SHARE_PAIRING_ACTIVE', '已有设备配对，请先完成或取消。', 409);
    const verifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(verifier).digest('base64url');
    const response = await this.json<PairingResponse>('POST', '/client/v2/device-pairings', { ...input, codeChallenge, codeChallengeMethod: 'S256' });
    if (typeof response.deviceCode !== 'string' || !response.deviceCode || typeof response.pairingId !== 'string' || typeof response.userCode !== 'string' || !Number.isFinite(response.expiresAt) || response.expiresAt <= Date.now()) throw new HubClientError('SHARE_PAIRING_INVALID', 'Hub 返回了无效的设备配对信息。', 502);
    const verificationUri = this.verificationUrl(response.verificationUri);
    const verificationUriComplete = this.verificationUrl(response.verificationUriComplete ?? response.verificationUri);
    const interval = Math.max(1, Math.min(30, Number(response.interval) || 3));
    const display: PairingDisplay = { pairingId: response.pairingId, userCode: response.userCode, verificationUri, verificationUriComplete, expiresAt: response.expiresAt, interval };
    this.pendingPairing = { display, deviceCode: response.deviceCode, verifier, nextPollAt: Date.now() + interval * 1000 };
    return { ...display };
  }

  async pollPairing(): Promise<PairingPoll> {
    const pending = this.pendingPairing;
    if (!pending) throw new HubClientError('SHARE_PAIRING_MISSING', '没有正在进行的设备配对。', 409);
    if (pending.display.expiresAt <= Date.now()) { this.pendingPairing = null; throw new HubClientError('EXPIRED_TOKEN', '设备配对已过期，请重新配对。'); }
    if (Date.now() < pending.nextPollAt) return { status: 'pending', retryAfterMs: pending.nextPollAt - Date.now() };
    pending.nextPollAt = Date.now() + pending.display.interval * 1000;
    try {
      const result = await this.json<AuthResponse>('POST', '/client/v2/device-pairings/token', { deviceCode: pending.deviceCode, codeVerifier: pending.verifier });
      const credentials = credentialsFromAuth(result);
      if (this.pendingPairing !== pending) {
        await this.json('DELETE', `/client/v2/devices/${encodeURIComponent(credentials.deviceId)}`, undefined, credentials.accessToken).catch(() => undefined);
        throw new HubClientError('PAIRING_CANCELLED', '此设备配对已取消，不会保存登录身份。', 409);
      }
      try { await this.setCredentials(credentials); }
      catch {
        await this.json('DELETE', `/client/v2/devices/${encodeURIComponent(credentials.deviceId)}`, undefined, credentials.accessToken).catch(() => undefined);
        throw new HubClientError('SHARE_CREDENTIAL_STORE_FAILED', '本机无法安全保存设备身份。请重新配对；如远端撤销未成功，可在网页登录设备页撤销。', 500);
      }
      if (this.pendingPairing !== pending) {
        if (this.credentials?.accessToken === credentials.accessToken) await this.setCredentials(null).catch(() => undefined);
        await this.json('DELETE', `/client/v2/devices/${encodeURIComponent(credentials.deviceId)}`, undefined, credentials.accessToken).catch(() => undefined);
        throw new HubClientError('PAIRING_CANCELLED', '此设备配对已取消，不会保留登录身份。', 409);
      }
      this.pendingPairing = null;
      return { status: 'approved', member: result.member, device: result.device };
    } catch (error) {
      if (error instanceof ShareError && ['AUTHORIZATION_PENDING', 'SLOW_DOWN'].includes(error.code)) {
        if (error.code === 'SLOW_DOWN') pending.display.interval = Math.min(30, pending.display.interval + 5);
        pending.nextPollAt = Date.now() + pending.display.interval * 1000;
        return { status: 'pending', retryAfterMs: pending.display.interval * 1000 };
      }
      if (this.pendingPairing === pending && error instanceof ShareError && ['ACCESS_DENIED', 'EXPIRED_TOKEN', 'PAIRING_CANCELLED', 'SHARE_CREDENTIAL_STORE_FAILED'].includes(error.code)) this.pendingPairing = null;
      throw error;
    }
  }

  /** The short code is used only to approve this device's PKCE request. It is never persisted. */
  async joinWithSharedCode(input: PairingInput, sharedCode: string): Promise<PairingPoll> {
    return this.joinUsingCode(input, sharedCode, 'join');
  }

  /** Friends choose their own code; the Hub creates or reuses its isolated room. */
  async joinWithMatchingCode(input: PairingInput, sharedCode: string): Promise<PairingPoll> {
    return this.joinUsingCode(input, sharedCode, 'match');
  }

  private async joinUsingCode(input: PairingInput, sharedCode: string, method: 'join' | 'match'): Promise<PairingPoll> {
    if (this.sharedJoinRunning) throw new HubClientError('SHARE_JOIN_BUSY', '正在连接，请稍候再试。', 409);
    this.sharedJoinRunning = true;
    try { return await this.completeSharedCodeJoin(input, sharedCode, method); }
    finally { this.sharedJoinRunning = false; }
  }

  private async completeSharedCodeJoin(input: PairingInput, sharedCode: string, method: 'join' | 'match'): Promise<PairingPoll> {
    const normalized = sharedCode.replace(/[\s-]/g, '');
    if (!/^\d{8}$/.test(normalized)) throw new HubClientError('SHARE_CODE_INVALID', '请输入和朋友约定的 8 位数字配对码。');
    if (this.credentials) throw new HubClientError('SHARE_ALREADY_CONNECTED', '这台电脑已经连接朋友空间。', 409);
    if (!this.pendingPairing) {
      await this.startPairing(input);
      this.sharedCodePairing = this.pendingPairing;
      this.codePairingMethod = method;
    }
    const pending = this.pendingPairing!;
    if (pending !== this.sharedCodePairing || this.codePairingMethod !== method) throw new HubClientError('SHARE_PAIRING_ACTIVE', '请先取消已有的设备确认，再用配对码连接。', 409);
    try {
      await this.json('POST', `/client/v2/device-pairings/${method}`, { deviceCode: pending.deviceCode, codeVerifier: pending.verifier, sharedCode: normalized });
      if (this.pendingPairing !== pending) throw new HubClientError('PAIRING_CANCELLED', '连接已取消。', 409);
      pending.nextPollAt = 0;
      return await this.pollPairing();
    } catch (error) {
      if (error instanceof ShareError && ['SHARE_PAIRING_USED', 'SHARE_PAIRING_ENDED', 'SHARE_MATCHING_CODE_CONFLICT', 'EXPIRED_TOKEN', 'ACCESS_DENIED'].includes(error.code)) {
        // A previous token response may have been lost. Cancel/revoke that exact request first.
        await this.cancelPairing().catch(() => undefined);
        throw new HubClientError('SHARE_JOIN_RESTART', '上一次连接已结束，请再次点击加入。', 409);
      }
      throw error;
    }
  }

  async cancelPairing(): Promise<void> {
    const pending = this.pendingPairing;
    if (!pending) return;
    // Clear local approval intent before racing an in-flight token response.
    this.pendingPairing = null;
    await this.json('POST', '/client/v2/device-pairings/cancel', { deviceCode: pending.deviceCode, codeVerifier: pending.verifier });
  }

  async refresh(): Promise<DeviceCredentials> {
    if (this.options.tokenProvider) return validateCredentials(await this.options.tokenProvider());
    if (this.refreshPromise) return this.refreshPromise;
    const previous = this.credentials;
    if (!previous || previous.refreshExpiresAt <= Date.now()) { if (previous) await this.setCredentials(null).catch(() => undefined); throw new HubClientError('SHARE_REPAIR_REQUIRED', '设备登录已到期，请重新配对。', 401); }
    const version = this.credentialVersion;
    this.refreshPromise = (async () => {
      try {
        const response = await this.json<AuthResponse>('POST', '/client/v2/auth/refresh', { refreshToken: previous.refreshToken });
        const next = credentialsFromAuth(response);
        if (next.deviceId !== previous.deviceId || next.memberId !== previous.memberId) throw new Error('identity mismatch');
        if (this.credentialVersion !== version) throw new Error('identity changed while refreshing');
        await this.setCredentials(next);
        return { ...next };
      } catch {
        // A refresh may have been consumed even when its response was lost. Never retry it.
        if (this.credentialVersion === version) await this.setCredentials(null).catch(() => undefined);
        throw new HubClientError('SHARE_REPAIR_REQUIRED', '设备身份更新未确认，请重新配对；不会重复使用旧刷新凭据。', 401);
      } finally { this.refreshPromise = null; }
    })();
    return this.refreshPromise;
  }

  async dataRequest(path: string, options: { token: string; method: 'GET' | 'POST'; body?: Uint8Array; operationId?: string; signal?: AbortSignal }): Promise<Response> {
    if (!['/v1/models', '/v1/responses', '/v1/responses/compact'].includes(path)) throw new HubClientError('SHARE_PATH_UNSUPPORTED', '不支持的模型接口。', 404);
    const headers: Record<string, string> = { authorization: `Bearer ${options.token}`, accept: 'application/json, text/event-stream', 'accept-encoding': 'identity' };
    if (options.body) headers['content-type'] = 'application/json';
    if (options.operationId) headers['x-share-operation-id'] = options.operationId;
    return this.fetchChecked(path, { method: options.method, headers, body: options.body as BodyInit | undefined, signal: options.signal }, false);
  }

  private verificationUrl(input: string): string {
    let url: URL;
    try { url = new URL(input, this.baseUrl); } catch { throw new HubClientError('SHARE_PAIRING_INVALID', '设备确认页面地址无效。', 502); }
    if (url.origin !== this.baseUrl || url.username || url.password || url.hash || !url.pathname.startsWith('/')) throw new HubClientError('SHARE_PAIRING_INVALID', '设备确认页面不属于当前 Hub。', 502);
    return url.toString();
  }

  private async accessCredentials(): Promise<DeviceCredentials> {
    if (this.options.tokenProvider) {
      const value = validateCredentials(await this.options.tokenProvider());
      if (value.expiresAt <= Date.now()) throw new HubClientError('SHARE_REPAIR_REQUIRED', '设备登录已到期。', 401);
      return value;
    }
    if (!this.credentials) throw new HubClientError('SHARE_REPAIR_REQUIRED', '请先连接这台设备。', 401);
    return this.credentials.expiresAt <= Date.now() + 30_000 ? this.refresh() : { ...this.credentials };
  }

  private async json<T>(method: string, path: string, body?: unknown, token?: string, signal?: AbortSignal): Promise<T> {
    const headers: Record<string, string> = { accept: 'application/json', 'accept-encoding': 'identity' };
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined) headers['content-type'] = 'application/json';
    const response = await this.fetchChecked(path, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal }, true);
    let value: unknown = null;
    if (response.status !== 204) {
      const reader = response.body?.getReader(); const chunks: Uint8Array[] = []; let size = 0;
      try {
        if (reader) while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > 1024 * 1024) throw new Error('control response too large'); chunks.push(part.value); }
        value = size ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null;
      } catch { await reader?.cancel().catch(() => undefined); throw new HubClientError('SHARE_HUB_RESPONSE_INVALID', 'Hub 返回的控制信息无效。', 502); }
    }
    if (!response.ok) {
      const object = value && typeof value === 'object' ? value as Record<string, unknown> : {};
      const detail = object.error && typeof object.error === 'object' ? object.error as Record<string, unknown> : {};
      const code = typeof detail.code === 'string' && /^[A-Z0-9_]{1,100}$/.test(detail.code) ? detail.code : 'SHARE_HUB_REQUEST_FAILED';
      let message = typeof detail.message === 'string' ? detail.message.slice(0, 500) : `Hub 请求失败（${response.status}）。`;
      for (const secret of [token, this.credentials?.accessToken, this.credentials?.refreshToken, this.pendingPairing?.deviceCode, this.pendingPairing?.verifier]) if (secret) message = message.split(secret).join('[已隐藏]');
      throw new HubClientError(code, message, response.status);
    }
    return value as T;
  }

  private async fetchChecked(path: string, init: RequestInit, control: boolean): Promise<Response> {
    if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\') || path.includes('#') || /(?:^|\/)\.\.?(?:\/|$)/.test(path) || !/^\/(?:client\/v2|v1)\//.test(path)) throw new HubClientError('SHARE_PATH_UNSUPPORTED', '请求路径不属于当前 Hub 客户端接口。');
    const url = new URL(path, this.baseUrl);
    if (url.origin !== this.baseUrl || !/^\/(?:client\/v2|v1)\//.test(url.pathname)) throw new HubClientError('SHARE_PATH_UNSUPPORTED', '请求不能离开当前 Hub 客户端接口。');
    const signal = control ? AbortSignal.any([...(init.signal ? [init.signal] : []), AbortSignal.timeout(this.options.controlTimeoutMs ?? 15000)]) : init.signal;
    let response: Response;
    try { response = await this.fetchImpl(url, { ...init, signal, redirect: 'manual', credentials: 'omit', cache: 'no-store' }); }
    catch { throw new HubClientError('SHARE_HUB_CONNECTION_FAILED', '无法确认 Hub 请求结果，请检查连接；写操作不会自动重试。', 503); }
    if (response.status >= 300 && response.status < 400) { await response.body?.cancel().catch(() => undefined); throw new HubClientError('SHARE_HUB_REDIRECT_REJECTED', 'Hub 重定向已拒绝，请核对空间地址。', 502); }
    return response;
  }
}

function credentialsFromAuth(value: AuthResponse): DeviceCredentials {
  if (!value?.device?.id || !value.member?.id || !Number.isFinite(value.expiresIn) || value.expiresIn <= 0 || value.expiresIn > 3600) throw new HubClientError('SHARE_AUTH_RESPONSE_INVALID', 'Hub 返回的设备身份无效。', 502);
  return validateCredentials({ accessToken: value.accessToken, refreshToken: value.refreshToken, expiresAt: Date.now() + value.expiresIn * 1000, refreshExpiresAt: value.refreshExpiresAt, deviceId: value.device.id, memberId: value.member.id });
}
function validateCredentials(value: DeviceCredentials): DeviceCredentials {
  if (!value || typeof value.accessToken !== 'string' || !value.accessToken || typeof value.refreshToken !== 'string' || !value.refreshToken || !Number.isFinite(value.expiresAt) || !Number.isFinite(value.refreshExpiresAt) || typeof value.deviceId !== 'string' || !value.deviceId || typeof value.memberId !== 'string' || !value.memberId) throw new HubClientError('SHARE_CREDENTIAL_INVALID', '设备凭据格式无效。', 401);
  return { accessToken: value.accessToken, refreshToken: value.refreshToken, expiresAt: value.expiresAt, refreshExpiresAt: value.refreshExpiresAt, deviceId: value.deviceId, memberId: value.memberId };
}
