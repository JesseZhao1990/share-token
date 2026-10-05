import { createHash, randomUUID } from 'node:crypto';
import { writeFile, rename, chmod } from 'node:fs/promises';
import { mkdirSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { createRelay, inspectRelayJournal, resolveRelayUnknown, isPolicyExpansion, policyHash, type RelayHandle, type RelaySnapshot } from '../../apps/relay/index.js';
import { MockAdapter, CodexSubscriptionAccount, SubscriptionAdapter, experimentalSubscriptionEnabled, assertExperimentalSubscriptionEnabled, type UpstreamAdapter } from '../upstream/index.js';
import type { SubscriptionAccountStatus } from '../upstream/subscription.js';
import { checkAdmission } from '../policy/index.js';
import { ShareError, adapterKindSchema, idSchema, policySchema, type Capabilities, type QuotaSnapshot, type SharePolicy } from '../protocol/index.js';
import type { ClientSource, ClientSourceResponse, RelayLeaseResponse } from '../protocol/client.js';
import { validateHubTrustProfile, type HubTrustProfile } from '../hub-client/trust.js';
import { serializeClientError } from '../protocol/client-errors.js';

export interface DonorHub {
  readonly baseUrl: string;
  request<T>(method: string, path: string, body?: unknown): Promise<T>;
}
const inputSchema = z.object({
  name: z.string().trim().min(1).max(80).default('我的模拟来源'),
  kind: adapterKindSchema.default('mock'),
  hubUrl: z.string().url().optional(), sourceId: idSchema.optional(), nodeId: idSchema.optional(),
  accountBinding: z.string().min(1).max(256).optional(), policy: policySchema,
}).strict();
export interface DonorConfigureInput {
  name?: string; kind?: 'mock' | 'api_fixture' | 'subscription'; hubUrl?: string;
  sourceId?: string; nodeId?: string; accountBinding?: string;
  policy: z.input<typeof policySchema>;
}
export interface DonorConfig {
  name: string; kind: 'mock' | 'api_fixture' | 'subscription'; hubUrl: string;
  sourceId: string | null; nodeId: string; accountBinding: string; policy: SharePolicy;
}
export interface DonorSnapshot {
  status: 'unconfigured' | 'paused' | 'starting' | 'sharing' | 'draining' | 'stopped' | 'suspended' | 'unavailable' | 'frozen' | 'offline' | 'closed';
  configured: boolean; desiredSharing: boolean; config: DonorConfig | null; source: ClientSource | null;
  relay: RelaySnapshot | null; quota: QuotaSnapshot | null;
  adapter: Capabilities | null; subscriptionAvailable: boolean;
  policySync: 'local' | 'pending' | 'synced' | 'error'; hubPolicyRevision: number | null;
  lastError: { code: string; message: string } | null;
}
export interface DonorControllerOptions {
  stateDir: string; hub?: DonorHub; onSnapshot?: (snapshot: DonorSnapshot) => void;
  hubTrust?: HubTrustProfile;
  /** Trusted tests or an explicitly reviewed local adapter only; never renderer-provided code. */
  adapterFactory?: (config: DonorConfig) => UpstreamAdapter;
  subscriptionAccount?: { inspect(): Promise<SubscriptionAccountStatus> };
  heartbeatMs?: number;
}
interface SavedConfig { version: 1; config: DonorConfig; confirmedPolicyHash: string; hubPolicyRevision: number | null }

/** Shared donor lifecycle used by the signed Node worker and CLI tests. Never stores a token. */
export class DonorController {
  private config: DonorConfig | null = null;
  private source: ClientSource | null = null;
  private relay: RelayHandle | null = null;
  private relayState: RelaySnapshot | null = null;
  private adapter: UpstreamAdapter | null = null;
  private capability: Capabilities | null = null;
  private quota: QuotaSnapshot | null = null;
  private desiredSharing = false;
  private state: DonorSnapshot['status'] = 'unconfigured';
  private closed = false;
  private policySync: DonorSnapshot['policySync'] = 'local';
  private hubPolicyRevision: number | null = null;
  private lastError: DonorSnapshot['lastError'] = null;
  private lease: RelayLeaseResponse | null = null;
  private leaseTokenExpiresAt = 0;
  private leaseTimer: ReturnType<typeof setTimeout> | null = null;
  private renewal: Promise<void> | null = null;
  private epoch = 0;
  private startPromise: Promise<DonorSnapshot> | null = null;
  private configurationBusy = false;
  private closePromise: Promise<void> | null = null;
  private saveQueue: Promise<void> = Promise.resolve();
  private readonly configPath: string;
  private readonly listeners = new Set<(snapshot: DonorSnapshot) => void>();

  constructor(private readonly options: DonorControllerOptions) {
    if (options.hubTrust) {
      const trust = validateHubTrustProfile(options.hubTrust);
      if (options.hub && trust.hubUrl !== validatedHub(options.hub.baseUrl)) throw new ShareError('SHARE_HUB_MISMATCH', '连接证书不属于当前 Hub。', 409);
    }
    mkdirSync(options.stateDir, { recursive: true, mode: 0o700 });
    this.configPath = join(options.stateDir, 'donor-config.json');
    if (existsSync(this.configPath)) {
      try {
        const saved = JSON.parse(readFileSync(this.configPath, 'utf8')) as SavedConfig;
        if (saved.version !== 1 || !saved.config || saved.confirmedPolicyHash !== policyHash(saved.config.policy)) throw new Error('Invalid local configuration');
        const parsed = inputSchema.parse({ ...saved.config, sourceId: saved.config.sourceId ?? undefined });
        this.config = { ...parsed, hubUrl: validatedHub(parsed.hubUrl!), sourceId: parsed.sourceId ?? null, nodeId: parsed.nodeId!, accountBinding: parsed.accountBinding! };
        if (options.hub && this.config.hubUrl !== validatedHub(options.hub.baseUrl)) throw new Error('Saved configuration belongs to another Hub');
        this.hubPolicyRevision = saved.hubPolicyRevision;
        this.state = this.config.kind === 'api_fixture' ? 'unavailable' : 'paused';
        this.refreshJournalSnapshot();
      } catch { throw new ShareError('SHARE_DONOR_CONFIG_INVALID', '本机共享配置无效，请重新配置来源；未启动共享。', 409); }
    }
    if (options.onSnapshot) this.listeners.add(options.onSnapshot);
    // Restoring configuration never restores sharing intent or a bearer credential.
    this.emit();
  }

  snapshot(): DonorSnapshot {
    let status = this.state;
    if (this.closed) status = 'closed';
    else if (this.config?.kind === 'api_fixture' || (this.config?.kind === 'subscription' && !experimentalSubscriptionEnabled())) status = 'unavailable';
    else if (this.relayState?.freezeReasons.length) status = 'frozen';
    else if (this.relayState?.draining) status = 'draining';
    else if (this.desiredSharing && this.relayState && !this.relayState.connected && status !== 'starting') status = 'offline';
    else if (this.desiredSharing && this.relayState?.connected && !this.relayState.paused) status = 'sharing';
    return structuredClone({ status, configured: !!this.config, desiredSharing: this.desiredSharing, config: this.config, source: this.source,
      relay: this.relayState, quota: this.relayState?.quota ?? this.quota, adapter: this.capability, subscriptionAvailable: experimentalSubscriptionEnabled() && !!this.options.subscriptionAccount && (!!this.options.adapterFactory || this.options.subscriptionAccount instanceof CodexSubscriptionAccount),
      policySync: this.policySync, hubPolicyRevision: this.hubPolicyRevision, lastError: this.config?.kind === 'subscription' && !experimentalSubscriptionEnabled() ? { code: 'SHARE_EXPERIMENTAL_SUBSCRIPTION_DISABLED', message: '实验订阅适配默认关闭，请改用模拟来源。' } : this.lastError });
  }
  onSnapshot(listener: (snapshot: DonorSnapshot) => void): () => void { this.listeners.add(listener); listener(this.snapshot()); return () => { this.listeners.delete(listener); }; }
  private emit(): DonorSnapshot { const snapshot = this.snapshot(); for (const listener of this.listeners) { try { listener(snapshot); } catch {} } return snapshot; }
  private ensureOpen() { if (this.closed) throw new ShareError('SHARE_DONOR_CLOSED', '共享端已退出。', 409); }
  private fail(error: unknown) {
    const { code, message } = serializeClientError(error);
    this.lastError = { code, message }; this.emit();
  }
  private save(): Promise<void> {
    if (!this.config) return Promise.resolve();
    const payload = JSON.stringify({ version: 1, config: this.config, confirmedPolicyHash: policyHash(this.config.policy), hubPolicyRevision: this.hubPolicyRevision } satisfies SavedConfig, null, 2);
    const write = this.saveQueue.catch(() => {}).then(async () => {
      const temporary = `${this.configPath}.${randomUUID()}.tmp`;
      await writeFile(temporary, payload, { mode: 0o600 }); await rename(temporary, this.configPath); await chmod(this.configPath, 0o600);
    });
    this.saveQueue = write; return write;
  }
  private journalPath(): string | null {
    return this.config?.sourceId ? join(this.options.stateDir, `relay-${createHash('sha256').update(this.config.sourceId).digest('hex').slice(0, 24)}.sqlite`) : null;
  }
  private refreshJournalSnapshot() {
    const path = this.journalPath(); const config = this.config; if (!path || !config) return;
    const journal = inspectRelayJournal(path); if (!journal) return;
    this.relayState = { sourceId: config.sourceId!, nodeId: config.nodeId, connected: false, paused: true, draining: false, closed: true,
      activeRequestId: null, activeState: null, unknownCount: journal.unknownCount,
      freezeReasons: [...(journal.identityFrozen ? ['identity' as const] : []), ...(journal.unknownCount ? ['unknown' as const] : [])],
      quota: null, policy: config.policy, policyRevision: 1, policyHash: policyHash(config.policy), lastErrorCode: null };
  }

  async configure(input: DonorConfigureInput, controls: { confirmExpansion?: boolean } = {}): Promise<DonorSnapshot> {
    this.ensureOpen();
    if (this.configurationBusy || this.startPromise) throw new ShareError('SHARE_DONOR_BUSY', '共享端正在更新配置或启动，请稍后再试。', 409);
    this.configurationBusy = true;
    try { return await this.configureInternal(input, controls); }
    finally { this.configurationBusy = false; }
  }
  private async configureInternal(input: DonorConfigureInput, controls: { confirmExpansion?: boolean }): Promise<DonorSnapshot> {
    if (this.desiredSharing || this.relayState?.activeRequestId) throw new ShareError('SHARE_DONOR_BUSY', '请先停止共享，再修改来源配置。', 409);
    const parsed = inputSchema.parse(input);
    const previous = this.config;
    const hubUrl = validatedHub(parsed.hubUrl ?? this.options.hub?.baseUrl ?? previous?.hubUrl ?? '');
    if (this.options.hub && hubUrl !== validatedHub(this.options.hub.baseUrl)) throw new ShareError('SHARE_HUB_MISMATCH', '共享来源必须属于当前配对的 Hub。', 409);
    let accountBinding = parsed.accountBinding;
    if (parsed.kind === 'api_fixture') throw new ShareError('SHARE_DESKTOP_CHANNEL_UNAVAILABLE', '桌面端不开放 API 对照来源。', 501);
    if (parsed.kind === 'subscription') {
      const account = await this.inspectSubscription(parsed.policy.models);
      accountBinding = account.accountBinding!; // Only the account manager establishes identity; renderer labels are never identities.
      if (parsed.sourceId && (!previous || previous.sourceId !== parsed.sourceId || previous.accountBinding !== accountBinding || previous.kind !== 'subscription')) throw new ShareError('SHARE_ACCOUNT_CHANGED', '订阅重新绑定必须创建新来源。', 409);
    }
    const sameSource = !!previous && hubUrl === previous.hubUrl && parsed.kind === previous.kind && (!accountBinding || accountBinding === previous.accountBinding) && (!parsed.sourceId || parsed.sourceId === previous.sourceId);
    if (sameSource && isPolicyExpansion(previous!.policy, parsed.policy) && controls.confirmExpansion !== true) throw new ShareError('SHARE_POLICY_CONFIRMATION_REQUIRED', '放宽共享规则需要在本机明确确认。', 409);
    if (this.relay) { await this.relay.close(); this.relay = null; }
    await this.releaseLease(); this.relayState = null; this.source = null; this.adapter = null; this.capability = null; this.quota = null;
    this.ensureOpen();
    const nodeId = parsed.nodeId ?? previous?.nodeId ?? `node_${randomUUID()}`;
    this.config = { name: parsed.name, kind: parsed.kind, hubUrl, sourceId: parsed.sourceId ?? (sameSource ? previous?.sourceId ?? null : null), nodeId,
      accountBinding: accountBinding ?? (sameSource ? previous?.accountBinding : undefined) ?? `${parsed.kind}:${nodeId}`, policy: parsed.policy };
    this.hubPolicyRevision = null; this.policySync = 'local'; this.lastError = null;
    this.state = 'paused';
    await this.save(); this.refreshJournalSnapshot();
    if (this.options.hub && ['mock', 'subscription'].includes(this.config.kind)) {
      try {
        await this.ensureSource(); this.ensureOpen();
        // The local saved rule is already effective and no relay is accepting work.
        // Update an existing source instead of leaving the next start in policy conflict.
        const currentSource = this.source as ClientSource | null;
        if (currentSource && policyHash(currentSource.policy) !== policyHash(this.config.policy)) {
          const result = await this.options.hub.request<ClientSourceResponse>('PATCH', `/client/v2/sources/${encodeURIComponent(this.config.sourceId!)}/policy`, { policy: this.config.policy, ...(this.hubPolicyRevision ? { expectedRevision: this.hubPolicyRevision } : {}) });
          this.source = result.source; this.hubPolicyRevision = result.revision;
        }
        this.ensureOpen(); await this.syncPolicy();
      } catch (error) { this.policySync = 'error'; this.fail(error); throw error; }
    }
    return this.emit();
  }

  private async inspectSubscription(models: string[]): Promise<SubscriptionAccountStatus> {
    assertExperimentalSubscriptionEnabled();
    if (!this.options.subscriptionAccount || (!this.options.adapterFactory && !(this.options.subscriptionAccount instanceof CodexSubscriptionAccount))) throw new ShareError('SHARE_SUBSCRIPTION_UNAVAILABLE', '请先选择 Codex 程序并登录本应用的订阅账号。', 409);
    const account = await this.options.subscriptionAccount.inspect();
    if (!account.authenticated || !account.accountBinding) throw new ShareError('SHARE_SUBSCRIPTION_AUTH_REQUIRED', '订阅账号未登录或登录已失效，请重新登录。', 401);
    if (models.some(model => !account.models.includes(model))) throw new ShareError('SHARE_MODEL_UNAVAILABLE', '所选模型不在当前订阅账号可用列表中，请刷新后重新选择。', 409);
    return account;
  }

  private async ensureSource(): Promise<void> {
    const config = this.config; const hub = this.options.hub;
    if (!config || !hub) return;
    if (!config.sourceId) {
      let result: ClientSourceResponse;
      try {
        result = await hub.request<ClientSourceResponse>('POST', '/client/v2/sources', { name: config.name, kind: config.kind, accountBinding: config.accountBinding, policy: config.policy });
      } catch (error) {
        if (!(error instanceof ShareError) || error.code !== 'SHARE_SOURCE_EXISTS') throw error;
        const ownedElsewhere = () => new ShareError('SHARE_SOURCE_OWNED_ELSEWHERE', '这个订阅已绑定旧设备或其他成员的共享来源，请联系空间管理员迁移后再保存。', 409);
        const visible = await hub.request<{ sources: ClientSource[] }>('GET', '/client/v2/sources');
        const candidate = visible.sources.find(source => source.kind === config.kind && source.accountBinding === config.accountBinding);
        if (!candidate) throw ownedElsewhere();
        if (!idSchema.safeParse(candidate.id).success) throw new ShareError('SHARE_ACCOUNT_CHANGED', 'Hub 返回的来源与本机身份不一致。', 409);
        // Visibility is not ownership. Only this owner-only endpoint can authorize recovery.
        try { result = await hub.request<ClientSourceResponse>('GET', `/client/v2/sources/${encodeURIComponent(candidate.id)}`); }
        catch (error) {
          if (error instanceof ShareError && [403, 404].includes(error.status)) throw ownedElsewhere();
          throw error;
        }
        if (result.source.id !== candidate.id) throw new ShareError('SHARE_ACCOUNT_CHANGED', 'Hub 返回的来源与本机身份不一致。', 409);
      }
      if (result.source.kind !== config.kind || result.source.accountBinding !== config.accountBinding || !idSchema.safeParse(result.source.id).success) throw new ShareError('SHARE_ACCOUNT_CHANGED', 'Hub 返回的来源与本机身份不一致。', 409);
      this.source = result.source; config.sourceId = result.source.id; this.hubPolicyRevision = result.revision;
      await this.save(); return;
    }
    const result = await hub.request<{ sources: ClientSource[] }>('GET', '/client/v2/sources');
    const source = result.sources.find(item => item.id === config.sourceId);
    if (!source || source.kind !== config.kind || source.accountBinding !== config.accountBinding) throw new ShareError('SHARE_ACCOUNT_CHANGED', '来源与本机绑定不一致，请重新选择来源。', 409);
    this.source = source; this.hubPolicyRevision = source.policyRevision ?? this.hubPolicyRevision;
  }

  start(options: { relayToken?: string } = {}): Promise<DonorSnapshot> {
    if (this.configurationBusy) return Promise.reject(new ShareError('SHARE_DONOR_BUSY', '共享规则正在更新，请稍后启动。', 409));
    if (this.startPromise) return this.startPromise;
    this.startPromise = this.startInternal(options).finally(() => { this.startPromise = null; });
    return this.startPromise;
  }
  private async startInternal(options: { relayToken?: string }): Promise<DonorSnapshot> {
    this.ensureOpen(); const config = this.config;
    if (!config) throw new ShareError('SHARE_DONOR_UNCONFIGURED', '请先配置共享来源。', 409);
    if (config.kind === 'api_fixture') { this.state = 'unavailable'; this.emit(); throw new ShareError('SHARE_DESKTOP_CHANNEL_UNAVAILABLE', '桌面端不开放 API 对照来源。', 501); }
    if (this.relayState?.freezeReasons.length) throw new ShareError('SHARE_SOURCE_FROZEN', '来源有待核实问题，不能直接继续共享。', 409);
    const epoch = ++this.epoch; this.desiredSharing = true; this.state = 'starting'; this.lastError = null; this.emit();
    const checkCurrent = () => { if (epoch !== this.epoch || this.closed || !this.desiredSharing) throw new ShareError('SHARE_START_CANCELLED', '共享启动已被暂停或停止。', 409); };
    try {
      if (config.kind === 'subscription') { const account = await this.inspectSubscription(config.policy.models); checkCurrent(); if (account.accountBinding !== config.accountBinding) throw new ShareError('SHARE_ACCOUNT_CHANGED', '订阅账号已变化，请停止并重新保存来源。', 409); }
      await this.ensureSource(); checkCurrent();
      if (!config.sourceId) throw new ShareError('SHARE_SOURCE_MISSING', '尚未创建共享来源。', 409);
      this.adapter ??= this.options.adapterFactory?.(config) ?? (config.kind === 'subscription' && this.options.subscriptionAccount instanceof CodexSubscriptionAccount ? new SubscriptionAdapter({ account: this.options.subscriptionAccount, accountBinding: config.accountBinding, models: config.policy.models }) : new MockAdapter({ accountBinding: config.accountBinding, models: config.policy.models }));
      this.capability = await this.adapter.inspect(); checkCurrent();
      if (this.capability.accountBinding !== config.accountBinding || this.capability.kind !== config.kind || !this.capability.verified) throw new ShareError('SHARE_ACCOUNT_CHANGED', '适配器身份或能力与来源不一致。', 409);
      if (!this.capability.responses || !this.capability.compact || config.policy.models.some(model => !this.capability!.models.includes(model))) throw new ShareError('SHARE_MODEL_UNAVAILABLE', '订阅模型或协议能力已变化，请重新选择模型并保存。', 409);
      this.quota = await this.adapter.readQuota(); checkCurrent();
      if (config.kind === 'subscription' && this.quota.origin !== 'codex') throw new ShareError('SHARE_QUOTA_STALE', '真实订阅额度无法确认，请刷新账号状态。', 503);
      checkAdmission({ policy: config.policy, quota: this.quota, memberId: config.policy.allowedMemberIds[0] ?? '', model: config.policy.models[0]!, bodyBytes: 1 });
      if (!this.relay || !this.relay.snapshot().connected) {
        if (this.relay) { await this.relay.close(); this.relay = null; }
        if (this.options.hub) {
          await this.options.hub.request('POST', `/client/v2/sources/${encodeURIComponent(config.sourceId)}/desired-state`, { state: 'drain' }); checkCurrent();
          this.lease = await this.options.hub.request<RelayLeaseResponse>('POST', `/client/v2/sources/${encodeURIComponent(config.sourceId)}/relay-leases`, {}); this.leaseTokenExpiresAt = Date.now() + this.lease.expiresIn * 1000; checkCurrent(); this.scheduleRenewal();
        } else if (!options.relayToken) throw new ShareError('SHARE_AUTH_INVALID', '启动需要当前设备签发的临时 relay 凭据。', 401);
        const journal = this.journalPath()!;
        const token = options.relayToken;
        if (this.options.hubTrust && validateHubTrustProfile(this.options.hubTrust).hubUrl !== config.hubUrl) throw new ShareError('SHARE_HUB_MISMATCH', '连接证书不属于当前 Hub。', 409);
        this.relay = await createRelay({ hubUrl: config.hubUrl, hubCertificate: this.options.hubTrust?.certificatePem, token, tokenProvider: this.options.hub ? async () => { if (!this.lease || Math.min(this.lease.lease.expiresAt, this.leaseTokenExpiresAt) <= Date.now()) throw new ShareError('SHARE_RELAY_LEASE_EXPIRED', 'Relay 临时租约已过期。', 401); return this.lease.token; } : undefined,
          sourceId: config.sourceId, nodeId: config.nodeId, dbPath: journal, policy: config.policy, policyApprovalHash: policyHash(config.policy), adapter: this.adapter,
          initialPaused: true, heartbeatMs: this.options.heartbeatMs, onSnapshot: value => { this.relayState = value; if (!this.desiredSharing && !value.activeRequestId && this.state === 'draining') this.state = 'paused'; this.emit(); } });
        checkCurrent(); await this.relay.waitUntilReady(); checkCurrent();
      }
      await this.syncPolicy(); checkCurrent();
      this.relay.resume();
      if (this.options.hub) await this.options.hub.request('POST', `/client/v2/sources/${encodeURIComponent(config.sourceId)}/desired-state`, { state: 'active' });
      checkCurrent(); this.state = 'sharing'; return this.emit();
    } catch (error) {
      this.desiredSharing = false; this.relay?.stopNow('Donor startup did not complete');
      if (this.relay) { await this.relay.close(); this.relay = null; }
      await this.releaseLease(); if (!this.closed && this.state === 'starting') this.state = 'paused';
      this.fail(error); throw error;
    }
  }

  private async syncPolicy(): Promise<void> {
    const config = this.config!;
    if (!this.options.hub) { this.policySync = 'local'; return; }
    if (!this.source || policyHash(this.source.policy) !== policyHash(config.policy) || !this.hubPolicyRevision) throw new ShareError('SHARE_POLICY_CONFLICT', 'Hub 规则与本机规则不同，请检查差异后重新同步。', 409);
    this.policySync = 'pending'; this.emit();
    const result = await this.options.hub.request<ClientSourceResponse>('POST', `/client/v2/sources/${encodeURIComponent(config.sourceId!)}/policy-acks`, { revision: this.hubPolicyRevision, policyHash: createHash('sha256').update(JSON.stringify(this.source.policy)).digest('hex') });
    this.source = result.source; this.policySync = 'synced'; await this.save();
  }

  async drain(): Promise<DonorSnapshot> {
    this.ensureOpen(); ++this.epoch; this.desiredSharing = false; this.relay?.drain(); this.state = this.relayState?.activeRequestId ? 'draining' : 'paused'; this.emit();
    if (this.options.hub && this.config?.sourceId) { try { await this.options.hub.request('POST', `/client/v2/sources/${encodeURIComponent(this.config.sourceId)}/desired-state`, { state: 'drain' }); } catch (error) { this.fail(error); } }
    return this.emit();
  }
  async stopNow(reason = 'user_stopped'): Promise<DonorSnapshot> {
    ++this.epoch; this.desiredSharing = false; this.state = reason === 'suspend' ? 'suspended' : 'stopped'; this.relay?.stopNow(reason); this.emit();
    if (this.relay) { const relay = this.relay; this.relay = null; await relay.close(); }
    if (this.options.hub && this.config?.sourceId) { try { await this.options.hub.request('POST', `/client/v2/sources/${encodeURIComponent(this.config.sourceId)}/desired-state`, { state: 'stop' }); } catch (error) { this.fail(error); } }
    await this.releaseLease(); this.adapter = null; return this.emit();
  }
  suspend(): Promise<DonorSnapshot> { return this.stopNow('suspend'); }
  async wake(): Promise<DonorSnapshot> {
    this.ensureOpen(); this.desiredSharing = false; this.relay?.drain();
    if (this.adapter && this.config?.kind !== 'api_fixture') { this.capability = await this.adapter.inspect(); this.quota = await this.adapter.readQuota(); }
    if (this.state === 'suspended') this.state = 'paused'; return this.emit();
  }
  resume(): Promise<DonorSnapshot> { return this.start(); }

  async updatePolicy(nextPolicy: SharePolicy, controls: { confirmExpansion?: boolean } = {}): Promise<DonorSnapshot> {
    this.ensureOpen();
    if (this.configurationBusy || this.startPromise) throw new ShareError('SHARE_DONOR_BUSY', '共享端正在更新配置或启动，请稍后再试。', 409);
    this.configurationBusy = true;
    try { return await this.updatePolicyInternal(nextPolicy, controls); }
    finally { this.configurationBusy = false; }
  }
  private async updatePolicyInternal(nextPolicy: SharePolicy, controls: { confirmExpansion?: boolean }): Promise<DonorSnapshot> {
    this.ensureOpen(); if (!this.config) throw new ShareError('SHARE_DONOR_UNCONFIGURED', '请先配置共享来源。', 409);
    const next = policySchema.parse(nextPolicy);
    if (this.config.kind === 'subscription') {
      const account = await this.inspectSubscription(next.models);
      if (account.accountBinding !== this.config.accountBinding) throw new ShareError('SHARE_ACCOUNT_CHANGED', '订阅账号已变化，请停止并重新绑定来源。', 409);
      if (JSON.stringify(next.models) !== JSON.stringify(this.config.policy.models)) throw new ShareError('SHARE_DONOR_BUSY', '修改订阅模型请先停止共享，再保存来源配置。', 409);
    }
    if (isPolicyExpansion(this.config.policy, next) && controls.confirmExpansion !== true) throw new ShareError('SHARE_POLICY_CONFIRMATION_REQUIRED', '放宽共享规则需要在本机明确确认。', 409);
    const wasSharing = this.desiredSharing; const epoch = ++this.epoch;
    this.relay?.drain(); this.relay?.updatePolicy(next, controls);
    this.config.policy = next; this.policySync = 'pending'; await this.save(); this.emit();
    try {
      if (this.options.hub && this.config.sourceId) {
        const result = await this.options.hub.request<ClientSourceResponse>('PATCH', `/client/v2/sources/${encodeURIComponent(this.config.sourceId)}/policy`, { policy: next, ...(this.hubPolicyRevision ? { expectedRevision: this.hubPolicyRevision } : {}) });
        this.source = result.source; this.hubPolicyRevision = result.revision; await this.syncPolicy();
      } else this.policySync = 'local';
      if (epoch === this.epoch && wasSharing && this.desiredSharing) this.relay?.resume();
      return this.emit();
    } catch (error) { this.policySync = 'error'; this.desiredSharing = false; this.state = 'paused'; this.fail(error); throw error; }
  }
  async resolveUnknown(options: { acknowledge: true }): Promise<DonorSnapshot> {
    this.ensureOpen();
    if (options.acknowledge !== true) throw new ShareError('SHARE_RISK_ACKNOWLEDGEMENT_REQUIRED', '旧请求可能仍在上游执行，需要明确接受未决风险。', 409);
    if (this.relay) this.relay.resolveUnknown(options);
    else { const journal = this.journalPath(); if (!journal) throw new ShareError('SHARE_RELAY_JOURNAL_MISSING', '尚无可核实的本机请求记录。', 409); resolveRelayUnknown(journal, true); this.refreshJournalSnapshot(); }
    if (this.options.hub && this.config?.sourceId) await this.options.hub.request('POST', `/client/v2/sources/${encodeURIComponent(this.config.sourceId)}/resolve-unknown`, { acknowledge: true });
    return this.emit();
  }
  private scheduleRenewal() {
    if (this.leaseTimer) clearTimeout(this.leaseTimer);
    if (!this.lease || !this.options.hub || this.closed) return;
    this.leaseTimer = setTimeout(() => { void this.renewLease().catch(() => {}); }, Math.max(1000, Math.min(this.lease.lease.expiresAt, this.leaseTokenExpiresAt) - Date.now() - 60_000)); this.leaseTimer.unref();
  }
  private async renewLease(): Promise<void> {
    if (this.renewal) return this.renewal;
    const lease = this.lease; if (!lease || !this.options.hub) return;
    this.renewal = (async () => {
      try { const result = await this.options.hub!.request<RelayLeaseResponse>('POST', `/client/v2/relay-leases/${encodeURIComponent(lease.lease.id)}/renew`, {}); if (this.lease?.lease.id === lease.lease.id) { this.lease = result; this.leaseTokenExpiresAt = Date.now() + result.expiresIn * 1000; this.scheduleRenewal(); } }
      catch (error) { this.fail(error); await this.stopNow('lease_renewal_failed'); }
    })().finally(() => { this.renewal = null; });
    return this.renewal;
  }
  private async releaseLease() {
    if (this.leaseTimer) { clearTimeout(this.leaseTimer); this.leaseTimer = null; }
    const lease = this.lease; this.lease = null; this.leaseTokenExpiresAt = 0;
    if (lease && this.options.hub) { try { await this.options.hub.request('DELETE', `/client/v2/relay-leases/${encodeURIComponent(lease.lease.id)}`); } catch (error) { this.fail(error); } }
  }
  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.closePromise = (async () => { await this.stopNow('application_exit'); this.state = 'closed'; this.emit(); this.listeners.clear(); })();
    return this.closePromise;
  }
}

function validatedHub(value: string): string {
  let url: URL; try { url = new URL(value); } catch { throw new ShareError('SHARE_HUB_URL_INVALID', '请先设置当前 Hub 地址。'); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new ShareError('SHARE_HUB_URL_INVALID', '共享 Hub 必须是 HTTPS 根地址；本机测试可使用 HTTP。');
  return url.origin;
}
