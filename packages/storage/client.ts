import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { EMPTY_USAGE, ShareError, isTerminal, type Grant, type Member, type RequestRecord, type SharePolicy, type Source } from '../protocol/index.js';
import type { ClientAuthResponse, ClientDevice, ClientRequest, ClientSession, ClientSource, DevicePairingResponse, DevicePairingView, DeviceScope, RelayLease, RelayLeaseResponse, RunLease, RunLeaseResponse } from '../protocol/client.js';
import { Store } from './index.js';
import { matchesSharedCode, normalizeSharedCode, type SharedCodeVerifier } from './shared-code.js';

const hash = (input: string | Uint8Array) => createHash('sha256').update(input).digest('hex');
const secret = (kind: string) => `st_${kind}_${randomBytes(32).toString('base64url')}`;
const ACCESS_MS = 5 * 60_000, LEASE_MS = 15 * 60_000, MAX_RUN_MS = 8 * 3600_000, REFRESH_MS = 30 * 86400_000;
interface Pairing extends Omit<DevicePairingView, 'pairingId'> { id: string; deviceCodeHash: string; userCodeHash: string; codeChallenge: string; approvedBy: string | null; deviceId: string | null; lastPoll: number; sharedCodeJoined?: boolean; matchingRoomId?: string }
interface Family { id: string; deviceId: string; memberId: string; generation: number; createdAt: number; lastUsedAt: number; expiresAt: number; revoked: boolean }
interface Token { hash: string; kind: 'access' | 'refresh' | 'inference' | 'relay'; deviceId: string; familyId: string; leaseId: string | null; generation: number; expiresAt: number; consumedAt: number | null }
interface PolicyMeta { id: string; revision: number; appliedRevision: number; policyHash: string; acknowledgedBy: string | null }
interface RequestMeta { id: string; deviceId: string; sessionId: string; leaseId: string; operationId: string; bodyHash: string; consumerDelivery: 'pending' | 'transport_finished' | 'lost' | 'unknown'; resolvedAt: number | null }
type StoredRun = RunLease & { familyId: string };
type StoredRelay = RelayLease & { familyId: string };
export interface DeviceAuth { device: ClientDevice; member: Member; familyId: string; scopes: DeviceScope[] }
export interface InferenceAuth extends DeviceAuth { lease: RunLease; session: ClientSession; grant: Grant }
export interface RelayAuth extends DeviceAuth { lease: RelayLease }
const authError = () => new ShareError('SHARE_AUTH_INVALID', '设备凭据无效、已撤销或已过期。', 401);
const missing = () => new ShareError('SHARE_NOT_FOUND', '资源不存在或无权访问。', 404);
const fromRow = <T>(row: unknown): T | null => row ? JSON.parse((row as { data: string }).data) as T : null;

/** Versioned desktop state. All token values are returned once and only their verifiers persist. */
export class ClientStore {
  readonly hubId: string;
  constructor(readonly base: Store) {
    const existing = base.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='client_migrations'").get();
    if (existing && Number(base.db.prepare('SELECT MAX(version) AS version FROM client_migrations').get()!.version) > 3) throw new ShareError('SHARE_SCHEMA_NEWER', '数据库由更新版本创建，请升级 Hub；不会降级写入。', 409);
    base.db.exec(`CREATE TABLE IF NOT EXISTS client_objects(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(kind,id));
      CREATE TABLE IF NOT EXISTS client_tokens(hash TEXT PRIMARY KEY,kind TEXT NOT NULL,device_id TEXT NOT NULL,family_id TEXT NOT NULL,data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS client_requests(request_id TEXT PRIMARY KEY REFERENCES requests(id),device_id TEXT NOT NULL,session_id TEXT NOT NULL,lease_id TEXT NOT NULL,operation_id TEXT NOT NULL,data TEXT NOT NULL,UNIQUE(device_id,session_id,operation_id));
      CREATE INDEX IF NOT EXISTS client_request_session ON client_requests(session_id);
      CREATE TABLE IF NOT EXISTS client_resources(source_id TEXT NOT NULL,resource_id TEXT NOT NULL,session_id TEXT NOT NULL,PRIMARY KEY(source_id,resource_id));
      CREATE TABLE IF NOT EXISTS client_nonces(member_id TEXT NOT NULL,nonce TEXT NOT NULL,session_id TEXT NOT NULL,PRIMARY KEY(member_id,nonce));
      CREATE TABLE IF NOT EXISTS client_migrations(version INTEGER PRIMARY KEY,applied_at INTEGER NOT NULL);
      INSERT OR IGNORE INTO client_migrations VALUES(1,CAST(strftime('%s','now') AS INTEGER)*1000);
      INSERT OR IGNORE INTO client_migrations VALUES(2,CAST(strftime('%s','now') AS INTEGER)*1000);`);
    if (Number(base.db.prepare('SELECT MAX(version) AS version FROM client_migrations').get()!.version) < 3) base.transaction(() => {
      // The source IDs, owners, grants, requests and resource bindings remain untouched. Only
      // uniqueness changes from account-wide to owner-scoped, together with its forward marker.
      for (const source of base.listSources()) base.db.prepare('UPDATE sources SET binding=? WHERE id=?').run(JSON.stringify([source.ownerId, source.kind, source.accountBinding]), source.id);
      base.db.prepare('INSERT INTO client_migrations VALUES(3,?)').run(Date.now());
    });
    const identity = this.get<{ id: string }>('hub', 'identity'); this.hubId = identity?.id ?? randomUUID();
    if (!identity) this.put('hub', 'identity', { id: this.hubId });
  }
  recoverInterrupted() {
    // A Hub restart cannot prove consumer delivery. Legacy requests remain under their existing rules.
    for (const meta of this.listRequestMeta()) {
      const request = this.base.getRequest(meta.id);
      if (request?.state === 'CANCELLED_NOT_SENT') this.resolveUnsent(meta.id);
      else if (meta.resolvedAt === null && (request?.state === 'UNKNOWN' || (request && isTerminal(request.state) && meta.consumerDelivery === 'pending'))) this.freezeRequest(meta.id, 'unknown');
      // v1 recovery conservatively freezes grants; managed sources isolate delivery by stable session.
      if (request && this.isManagedSource(request.sourceId)) this.base.updateGrant(request.grantId, { frozen: false });
    }
  }
  private get<T>(kind: string, id: string): T | null { return fromRow<T>(this.base.db.prepare('SELECT data FROM client_objects WHERE kind=? AND id=?').get(kind, id)); }
  private put(kind: string, id: string, data: unknown) { this.base.db.prepare('INSERT OR REPLACE INTO client_objects VALUES(?,?,?)').run(kind, id, JSON.stringify(data)); }
  private list<T>(kind: string): T[] { return this.base.db.prepare('SELECT data FROM client_objects WHERE kind=?').all(kind).map(row => fromRow<T>(row)!); }
  private token(value: string, kind: Token['kind']): Token | null { if (!value || value.length > 512) return null; return fromRow<Token>(this.base.db.prepare('SELECT data FROM client_tokens WHERE hash=? AND kind=?').get(hash(value), kind)); }
  private putToken(token: Token) { this.base.db.prepare('INSERT OR REPLACE INTO client_tokens VALUES(?,?,?,?,?)').run(token.hash, token.kind, token.deviceId, token.familyId, JSON.stringify(token)); }
  private mint(kind: Token['kind'], family: Family, leaseId: string | null = null) {
    const value = secret(`v2_${kind}`); this.putToken({ hash: hash(value), kind, deviceId: family.deviceId, familyId: family.id, leaseId, generation: family.generation, expiresAt: kind === 'refresh' ? family.expiresAt : Date.now() + ACCESS_MS, consumedAt: null }); return value;
  }
  getDevice(id: string) { return this.get<ClientDevice>('device', id); }
  devices(member: Member) { return this.list<ClientDevice>('device').filter(device => device.memberId === member.id); }
  // Existing members remain in the legacy group. Matching never migrates their identities or data.
  memberRoom(memberId: string): string { return this.get<{ roomId: string }>('member-room', memberId)?.roomId ?? 'legacy'; }
  sameRoom(leftMemberId: string, rightMemberId: string): boolean { return this.memberRoom(leftMemberId) === this.memberRoom(rightMemberId); }
  sourceInRoom(memberId: string, sourceId: string): boolean { const source = this.base.getSource(sourceId); return !!source && this.sameRoom(memberId, source.ownerId); }
  grantInRoom(memberId: string, grant: Grant): boolean { return this.sourceInRoom(memberId, grant.sourceId) && this.sameRoom(memberId, grant.memberId); }
  validateRoomPolicy(ownerId: string, policy: SharePolicy) { for (const memberId of policy.allowedMemberIds) if (!this.base.getMember(memberId)?.active || !this.sameRoom(ownerId, memberId)) throw new ShareError('SHARE_MEMBER_INVALID', '共享名单只能包含当前朋友空间的有效成员。', 400); }
  private fromToken(token: Token | null): DeviceAuth {
    if (!token || token.expiresAt <= Date.now()) throw authError();
    const device = this.getDevice(token.deviceId), family = this.get<Family>('family', token.familyId);
    const member = device && this.base.getMember(device.memberId);
    if (!device || device.status !== 'active' || !member?.active || !family || family.revoked || family.expiresAt <= Date.now()) throw authError();
    return { device, member, familyId: family.id, scopes: device.scopes };
  }
  access(value: string): DeviceAuth { const token = this.token(value, 'access'); const auth = this.fromToken(token); this.put('device', auth.device.id, { ...auth.device, lastSeen: Date.now() }); return auth; }
  requireScope(auth: DeviceAuth, scope: DeviceScope) { if (!auth.scopes.includes(scope)) throw new ShareError('SHARE_SCOPE_REQUIRED', '该设备未获此工作模式权限，请重新配对并批准相应能力。', 403); }
  createPairing(input: { deviceName: string; platform: string; clientVersion: string; requestedScopes: DeviceScope[]; codeChallenge: string }, origin: string): DevicePairingResponse {
    const deviceCode = secret('device_code'); const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const bytes = randomBytes(8); const letters = [...bytes].map(value => alphabet[value % alphabet.length]).join(''); const userCode = `${letters.slice(0, 4)}-${letters.slice(4)}`;
    const pairing: Pairing = { id: randomUUID(), deviceName: input.deviceName, platform: input.platform, clientVersion: input.clientVersion, requestedScopes: [...new Set(input.requestedScopes)], approvedScopes: [], status: 'pending', expiresAt: Date.now() + 5 * 60_000, deviceCodeHash: hash(deviceCode), userCodeHash: hash(userCode), codeChallenge: input.codeChallenge, approvedBy: null, deviceId: null, lastPoll: 0 };
    this.put('pairing', pairing.id, pairing);
    return { pairingId: pairing.id, deviceCode, userCode, verificationUri: origin + '/pair', verificationUriComplete: `${origin}/pair?code=${encodeURIComponent(userCode)}`, expiresAt: pairing.expiresAt, interval: 3 };
  }
  private findPairing(field: 'userCodeHash' | 'deviceCodeHash', value: string): Pairing | null { return fromRow<Pairing>(this.base.db.prepare(`SELECT data FROM client_objects WHERE kind='pairing' AND json_extract(data,'$.${field}')=?`).get(hash(field === 'userCodeHash' ? value.trim().toUpperCase() : value))); }
  pairingView(code: string): DevicePairingView { const pair = this.findPairing('userCodeHash', code); if (!pair) throw missing(); return { pairingId: pair.id, deviceName: pair.deviceName, platform: pair.platform, clientVersion: pair.clientVersion, requestedScopes: pair.requestedScopes, approvedScopes: pair.approvedScopes, status: pair.expiresAt <= Date.now() && !['redeemed', 'cancelled', 'denied'].includes(pair.status) ? 'expired' : pair.status, expiresAt: pair.expiresAt }; }
  approvePairing(code: string, member: Member, scopes?: DeviceScope[]) {
    return this.base.transaction(() => {
      const pair = this.findPairing('userCodeHash', code); if (!pair) throw missing();
      if (pair.status !== 'pending' || pair.expiresAt <= Date.now()) throw new ShareError('SHARE_PAIRING_ENDED', '配对申请已结束或到期。', 409);
      const selected = scopes ?? pair.requestedScopes;
      if (!selected.length || selected.some(scope => !pair.requestedScopes.includes(scope))) throw new ShareError('SHARE_SCOPE_INVALID', '不能批准未申请的权限。', 403);
      this.put('pairing', pair.id, { ...pair, approvedBy: member.id, approvedScopes: [...new Set(selected)], status: 'approved' }); this.base.audit(member.id, 'device.approve', pair.id); return this.pairingView(code);
    });
  }
  denyPairing(code: string, member: Member) { return this.base.transaction(() => { const pair = this.findPairing('userCodeHash', code); if (!pair) throw missing(); if (!['pending', 'approved'].includes(pair.status) || (pair.approvedBy && pair.approvedBy !== member.id)) throw new ShareError('SHARE_PAIRING_ENDED', '配对申请已结束。', 409); this.put('pairing', pair.id, { ...pair, status: 'denied' }); this.base.audit(member.id, 'device.deny', pair.id); return { status: 'denied' }; }); }
  private verifiedPairing(deviceCode: string, verifier: string): Pairing { const pair = this.findPairing('deviceCodeHash', deviceCode); if (!pair || createHash('sha256').update(verifier).digest('base64url') !== pair.codeChallenge) throw authError(); return pair; }
  joinPairing(deviceCode: string, codeVerifier: string, sharedCode: string, verifier: SharedCodeVerifier | null): DevicePairingView {
    return this.joinWithSharedCode(() => this.verifiedPairing(deviceCode, codeVerifier), sharedCode, verifier);
  }
  joinPairingFromBrowser(userCode: string, sharedCode: string, verifier: SharedCodeVerifier | null): DevicePairingView {
    return this.joinWithSharedCode(() => { const pair = this.findPairing('userCodeHash', userCode); if (!pair) throw missing(); return pair; }, sharedCode, verifier);
  }
  matchPairing(deviceCode: string, codeVerifier: string, sharedCode: string): DevicePairingView {
    const code = normalizeSharedCode(sharedCode);
    if (!code) throw new ShareError('SHARE_CODE_INVALID', '请输入和朋友约定的 8 位数字配对码。', 400);
    return this.base.transaction(() => {
      const pair = this.verifiedPairing(deviceCode, codeVerifier);
      if (pair.expiresAt <= Date.now() || !['pending', 'approved'].includes(pair.status) || pair.status === 'approved' && !pair.matchingRoomId) throw new ShareError('SHARE_PAIRING_ENDED', '这次连接申请已结束，请重新连接。', 409);
      let key = this.get<{ key: string }>('matching-key', 'v1');
      if (!key) { key = { key: randomBytes(32).toString('hex') }; this.put('matching-key', 'v1', key); }
      // A keyed index joins the same code after a restart without ever persisting that code.
      const codeKey = createHmac('sha256', Buffer.from(key.key, 'hex')).update('friend-code-v1\0').update(code).digest('hex');
      let room = this.get<{ roomId: string }>('matching-room', codeKey);
      if (pair.status === 'approved' && room?.roomId !== pair.matchingRoomId) throw new ShareError('SHARE_MATCHING_CODE_CONFLICT', '这次连接已使用另一个配对码，请取消后重新连接。', 409);
      if (!room) { room = { roomId: randomUUID() }; this.put('matching-room', codeKey, room); }
      if (pair.status === 'pending') {
        // Room selection alone is not a completed connection. Create the member only when this
        // exact PKCE request is redeemed, so cancellations and expired approvals leave no ghosts.
        pair.approvedScopes = [...pair.requestedScopes]; pair.status = 'approved'; pair.matchingRoomId = room.roomId;
        this.put('pairing', pair.id, pair);
      }
      if (pair.approvedBy && !this.base.getMember(pair.approvedBy)?.active) throw authError();
      return { pairingId: pair.id, deviceName: pair.deviceName, platform: pair.platform, clientVersion: pair.clientVersion, requestedScopes: pair.requestedScopes, approvedScopes: pair.approvedScopes, status: pair.status, expiresAt: pair.expiresAt };
    });
  }
  private joinWithSharedCode(resolvePair: () => Pairing, sharedCode: string, verifier: SharedCodeVerifier | null): DevicePairingView {
    if (!verifier) throw new ShareError('SHARE_SHARED_CODE_DISABLED', '这个共享空间尚未设置配对码，请联系提供共享的朋友。', 409);
    // Return a failed verification from the transaction, then throw outside it: the failed-attempt
    // record must survive rollback, process restart, and requests arriving through another proxy.
    const result = this.base.transaction(() => {
      const pair = resolvePair(), now = Date.now();
      if (pair.expiresAt <= now || !['pending', 'approved'].includes(pair.status) || pair.status === 'approved' && !pair.sharedCodeJoined) throw new ShareError('SHARE_PAIRING_ENDED', '配对申请已结束或到期，请重新连接。', 409);
      const limiter = this.get<{ failedAt: number[]; blockedUntil: number }>('auth-rate', 'shared-code') ?? { failedAt: [], blockedUntil: 0 };
      if (limiter.blockedUntil > now) throw new ShareError('SHARE_RATE_LIMITED', '配对码错误次数过多，请在一分钟后重试。', 429);
      if (!matchesSharedCode(sharedCode, verifier)) {
        const failedAt = [...limiter.failedAt.filter(at => at > now - 60_000), now].slice(-5);
        this.put('auth-rate', 'shared-code', { failedAt, blockedUntil: failedAt.length >= 5 ? now + 60_000 : 0 });
        return { error: new ShareError('SHARE_SHARED_CODE_INVALID', '配对码不正确，请核对朋友提供的 8 位数字。', 401) };
      }
      // A lost approval response can be retried without producing another member. Device names
      // are labels only; sharing an existing name never grants access to that member's resources.
      if (pair.status === 'pending') {
        const member = this.base.createMember(pair.deviceName, 'member');
        pair.approvedBy = member.id; pair.approvedScopes = [...pair.requestedScopes]; pair.status = 'approved'; pair.sharedCodeJoined = true;
        this.put('pairing', pair.id, pair); this.base.audit(member.id, 'device.join.shared-code', pair.id);
      }
      if (!pair.approvedBy || !this.base.getMember(pair.approvedBy)?.active) throw authError();
      const view: DevicePairingView = { pairingId: pair.id, deviceName: pair.deviceName, platform: pair.platform, clientVersion: pair.clientVersion, requestedScopes: pair.requestedScopes, approvedScopes: pair.approvedScopes, status: pair.status, expiresAt: pair.expiresAt };
      return { pairing: view };
    });
    if (result.error) throw result.error;
    return result.pairing;
  }
  cancelPairing(deviceCode: string, verifier: string) { return this.base.transaction(() => { const pair = this.verifiedPairing(deviceCode, verifier); if (pair.status === 'redeemed' && pair.deviceId) { this.revokeDevice(pair.deviceId); this.put('pairing', pair.id, { ...pair, status: 'cancelled' }); return { status: 'cancelled', deviceId: pair.deviceId }; } if (pair.status === 'denied' || pair.status === 'cancelled') return { status: pair.status, deviceId: pair.deviceId }; this.put('pairing', pair.id, { ...pair, status: 'cancelled' }); return { status: 'cancelled' }; }); }
  private authResponse(family: Family): ClientAuthResponse { const device = this.getDevice(family.deviceId)!; return { accessToken: this.mint('access', family), refreshToken: this.mint('refresh', family), tokenType: 'Bearer', expiresIn: ACCESS_MS / 1000, refreshExpiresAt: family.expiresAt, device, member: this.base.getMember(device.memberId)! }; }
  redeemPairing(deviceCode: string, verifier: string): ClientAuthResponse {
    const pair = this.verifiedPairing(deviceCode, verifier);
    if (pair.expiresAt <= Date.now()) throw new ShareError('EXPIRED_TOKEN', '配对已过期，请重新开始。', 400);
    if (pair.status === 'pending') { if (Date.now() - pair.lastPoll < 2500) throw new ShareError('SLOW_DOWN', '请按配对轮询间隔等待。', 429); this.put('pairing', pair.id, { ...pair, lastPoll: Date.now() }); throw new ShareError('AUTHORIZATION_PENDING', '等待在浏览器确认设备。', 400); }
    if (pair.status === 'denied' || pair.status === 'cancelled') throw new ShareError('ACCESS_DENIED', '配对已拒绝或取消。', 403);
    if (pair.status !== 'approved' || !pair.approvedBy && !pair.matchingRoomId) throw new ShareError('SHARE_PAIRING_USED', '配对码已使用。', 409);
    return this.base.transaction(() => {
      const current = this.get<Pairing>('pairing', pair.id)!; if (current.status !== 'approved') throw new ShareError('SHARE_PAIRING_USED', '配对码已使用。', 409);
      if (current.matchingRoomId && !current.approvedBy) {
        const member = this.base.createMember(current.deviceName, 'member');
        this.put('member-room', member.id, { roomId: current.matchingRoomId });
        current.approvedBy = member.id;
        this.base.audit(member.id, 'device.join.matching-code', current.id);
      }
      if (!this.base.getMember(current.approvedBy!)?.active) throw authError();
      const device: ClientDevice = { id: randomUUID(), memberId: current.approvedBy!, name: pair.deviceName, platform: pair.platform, clientVersion: pair.clientVersion, scopes: pair.approvedScopes, status: 'active', createdAt: Date.now(), lastSeen: Date.now() };
      const family: Family = { id: randomUUID(), deviceId: device.id, memberId: device.memberId, generation: 0, createdAt: Date.now(), lastUsedAt: Date.now(), expiresAt: Date.now() + REFRESH_MS, revoked: false };
      this.put('device', device.id, device); this.put('family', family.id, family); this.put('pairing', pair.id, { ...current, status: 'redeemed', deviceId: device.id });
      this.base.audit(device.memberId, 'device.pair', device.id); return this.authResponse(family);
    });
  }
  refresh(value: string): { auth?: ClientAuthResponse; revokedDeviceId?: string } {
    return this.base.transaction(() => {
      const token = this.token(value, 'refresh'); if (!token) throw authError();
      const family = this.get<Family>('family', token.familyId); if (!family || family.revoked) throw authError();
      if (token.consumedAt !== null || token.generation !== family.generation) { this.revokeDevice(token.deviceId); return { revokedDeviceId: token.deviceId }; }
      this.fromToken(token); if (family.lastUsedAt + 7 * 86400_000 <= Date.now()) throw authError();
      this.putToken({ ...token, consumedAt: Date.now() }); const next = { ...family, generation: family.generation + 1, lastUsedAt: Date.now() }; this.put('family', next.id, next); return { auth: this.authResponse(next) };
    });
  }
  revokeDevice(id: string) {
    const device = this.getDevice(id); if (!device) throw missing(); this.put('device', id, { ...device, status: 'revoked' });
    for (const family of this.list<Family>('family')) if (family.deviceId === id) this.put('family', family.id, { ...family, revoked: true });
    for (const lease of this.list<StoredRun>('run')) if (lease.deviceId === id && lease.state === 'active') this.put('run', lease.id, { ...lease, state: 'revoked' });
    for (const lease of this.list<StoredRelay>('relay')) if (lease.deviceId === id && lease.state === 'active') this.put('relay', lease.id, { ...lease, state: 'revoked' });
    if (this.memberRoom(device.memberId) !== 'legacy') {
      const families = this.list<Family>('family');
      const hasAnotherDevice = this.list<ClientDevice>('device').some(other => other.memberId === device.memberId && other.status === 'active' && families.some(family => family.deviceId === other.id && !family.revoked && family.expiresAt > Date.now()));
      if (!hasAnotherDevice) this.base.deactivateMember(device.memberId);
    }
    this.base.audit(device.memberId, 'device.revoke', id); return device;
  }
  registerSource(source: Source) { this.validateRoomPolicy(source.ownerId, source.policy); const meta: PolicyMeta = { id: source.id, revision: 1, appliedRevision: 0, policyHash: hash(JSON.stringify(source.policy)), acknowledgedBy: null }; this.put('policy', source.id, meta); return this.sourceResponse(source.id); }
  isManagedSource(id: string) { return this.get<PolicyMeta>('policy', id) !== null; }
  policyMeta(id: string) { return this.get<PolicyMeta>('policy', id); }
  sourceResponse(id: string) { const source = this.base.getSource(id); if (!source) throw missing(); const meta = this.policyMeta(id); return { source: this.decorateSource(source), revision: meta?.revision ?? 0, appliedRevision: meta?.appliedRevision ?? 0 }; }
  decorateSource(source: Source): ClientSource { const meta = this.policyMeta(source.id); return { ...source, clientMode: meta ? source.kind === 'mock' ? 'mock-v1-compatibility' : source.kind === 'subscription' ? 'subscription-v1-compatibility' : 'unavailable' : 'unavailable', policyRevision: meta?.revision, appliedPolicyRevision: meta?.appliedRevision }; }
  updatePolicy(sourceId: string, policy: SharePolicy, expectedRevision?: number) { const source = this.base.getSource(sourceId); if (!source) throw missing(); this.validateRoomPolicy(source.ownerId, policy); const meta = this.policyMeta(sourceId); if (!meta) throw new ShareError('SHARE_UPGRADE_REQUIRED', '此来源仍使用旧协议，请创建桌面来源。', 409); if (expectedRevision !== undefined && expectedRevision !== meta.revision) throw new ShareError('SHARE_POLICY_CONFLICT', '规则已被修改，请重新读取。', 409); this.base.updateSource(sourceId, { policy }); this.put('policy', sourceId, { ...meta, revision: meta.revision + 1, policyHash: hash(JSON.stringify(policy)) }); return this.sourceResponse(sourceId); }
  ackPolicy(sourceId: string, deviceId: string, revision: number, policyHash?: string) { if (this.list<StoredRelay>('relay').some(lease => lease.sourceId === sourceId && lease.state === 'active' && lease.expiresAt > Date.now() && lease.deviceId !== deviceId)) throw new ShareError('SHARE_POLICY_DEVICE_MISMATCH', '规则必须由当前贡献设备确认。', 409); const meta = this.policyMeta(sourceId); if (!meta || revision !== meta.revision || (policyHash && meta.policyHash !== policyHash)) throw new ShareError('SHARE_POLICY_CONFLICT', '本地确认版本或规则摘要不匹配。', 409); this.put('policy', sourceId, { ...meta, appliedRevision: revision, acknowledgedBy: deviceId }); return this.sourceResponse(sourceId); }
  createSession(auth: DeviceAuth, input: { grantId: string; modelScope: string[]; requestNonce?: string }) {
    this.requireScope(auth, 'consumer');
    return this.base.transaction(() => {
      if (input.requestNonce) { const old = this.base.db.prepare('SELECT session_id FROM client_nonces WHERE member_id=? AND nonce=?').get(auth.member.id, input.requestNonce); if (old) { const session = this.ownedSession(auth, String(old.session_id)); if (session.grantId !== input.grantId || JSON.stringify(session.modelScope) !== JSON.stringify(input.modelScope)) throw new ShareError('SHARE_NONCE_CONFLICT', '同一个操作编号不能创建不同会话。', 409); this.assertSessionGrant(session); return session; } }
      const grant = this.base.getGrant(input.grantId); if (!grant || grant.memberId !== auth.member.id) throw missing(); this.assertGrant(grant);
      if (input.modelScope.some(model => !grant.models.includes(model))) throw new ShareError('SHARE_MODEL_NOT_ALLOWED', '会话模型超出授权。', 403);
      if (!this.isManagedSource(grant.sourceId) || !['mock', 'subscription'].includes(this.base.getSource(grant.sourceId)?.kind ?? '')) throw new ShareError('SHARE_CAPABILITY_UNAVAILABLE', '当前来源不支持桌面会话。', 501);
      const session: ClientSession = { id: randomUUID(), memberId: auth.member.id, grantId: grant.id, sourceId: grant.sourceId, modelScope: input.modelScope, state: 'open', frozen: false, createdAt: Date.now() }; this.put('session', session.id, session);
      if (input.requestNonce) this.base.db.prepare('INSERT INTO client_nonces VALUES(?,?,?)').run(auth.member.id, input.requestNonce, session.id); return session;
    });
  }
  getSession(id: string) { return this.get<ClientSession>('session', id); }
  sessions(memberId: string) { return this.list<ClientSession>('session').filter(session => session.memberId === memberId && this.sourceInRoom(memberId, session.sourceId)); }
  ownedSession(auth: DeviceAuth, id: string) { const session = this.getSession(id); if (!session || session.memberId !== auth.member.id || !this.sourceInRoom(auth.member.id, session.sourceId)) throw missing(); return session; }
  private assertSessionGrant(session: ClientSession): Grant { const grant = this.base.getGrant(session.grantId); if (!grant || grant.memberId !== session.memberId || grant.sourceId !== session.sourceId) throw missing(); this.assertGrant(grant); return grant; }
  private assertGrant(grant: Grant | null) { if (!grant || !this.sourceInRoom(grant.memberId, grant.sourceId)) throw missing(); if (grant.revoked || grant.expiresAt !== null && grant.expiresAt <= Date.now() || !this.base.getMember(grant.memberId)?.active) throw new ShareError('SHARE_GRANT_REVOKED', '授权已撤销或到期。', 403); }
  getRun(id: string): RunLease | null { const lease = this.get<StoredRun>('run', id); if (!lease) return null; const { familyId: _family, ...publicLease } = lease; return { ...publicLease, state: publicLease.state === 'active' && publicLease.expiresAt <= Date.now() ? 'expired' : publicLease.state }; }
  createRun(auth: DeviceAuth, sessionId: string, expectedEpoch?: number): RunLeaseResponse {
    this.requireScope(auth, 'consumer');
    return this.base.transaction(() => {
      const session = this.ownedSession(auth, sessionId); if (session.state !== 'open' || session.frozen) throw new ShareError('SHARE_SESSION_UNAVAILABLE', '会话已关闭或有待核实结果。', 409);
      this.assertSessionGrant(session);
      const runs = this.list<StoredRun>('run'); const previous = runs.filter(lease => lease.sessionId === sessionId); const maxEpoch = Math.max(0, ...previous.map(lease => lease.epoch));
      if (previous.some(lease => lease.state === 'active' && lease.expiresAt > Date.now())) throw new ShareError('SHARE_SESSION_BUSY', '会话已有有效运行实例。', 409);
      if (previous.length && expectedEpoch !== maxEpoch) throw new ShareError('SHARE_EPOCH_REQUIRED', '恢复会话必须确认当前运行版本。', 409);
      if (runs.filter(lease => lease.deviceId === auth.device.id && lease.state === 'active' && lease.expiresAt > Date.now() && this.getSession(lease.sessionId)?.sourceId === session.sourceId).length >= 2) throw new ShareError('SHARE_LEASE_LIMIT', '同设备同来源最多两个运行实例。', 429);
      if (this.sessionRequests(sessionId).some(request => !isTerminal(request.state) || (request.consumerDelivery !== 'transport_finished' && !this.requestMeta(request.id)?.resolvedAt))) throw new ShareError('SHARE_RESULT_UNKNOWN', '历史请求尚未核实，不能创建新运行实例。', 409);
      const lease: StoredRun = { id: randomUUID(), sessionId, deviceId: auth.device.id, familyId: auth.familyId, epoch: maxEpoch + 1, state: 'active', createdAt: Date.now(), expiresAt: Date.now() + LEASE_MS };
      this.put('run', lease.id, lease); return this.runResponse(lease);
    });
  }
  private runResponse(lease: StoredRun): RunLeaseResponse { return { lease: this.getRun(lease.id)!, token: this.mint('inference', this.get<Family>('family', lease.familyId)!, lease.id), expiresIn: ACCESS_MS / 1000 }; }
  renewRun(auth: DeviceAuth, id: string): RunLeaseResponse { this.requireScope(auth, 'consumer'); const lease = this.get<StoredRun>('run', id); if (!lease || lease.deviceId !== auth.device.id) throw missing(); if (lease.state !== 'active' || lease.expiresAt <= Date.now() || lease.createdAt + MAX_RUN_MS <= Date.now()) throw new ShareError('SHARE_LEASE_EXPIRED', '运行授权已过期。', 409); const session = this.ownedSession(auth, lease.sessionId); if (session.state !== 'open') throw new ShareError('SHARE_SESSION_CLOSED', '会话已关闭。', 409); this.assertSessionGrant(session); const next = { ...lease, expiresAt: Math.min(Date.now() + LEASE_MS, lease.createdAt + MAX_RUN_MS) }; this.put('run', id, next); return this.runResponse(next); }
  closeRun(auth: DeviceAuth, id: string) { const lease = this.get<StoredRun>('run', id); if (!lease || lease.deviceId !== auth.device.id) throw missing(); this.put('run', id, { ...lease, state: 'closed' }); return this.getRun(id)!; }
  closeSession(auth: DeviceAuth, id: string) { const session = this.ownedSession(auth, id); this.put('session', id, { ...session, state: 'closed' }); for (const lease of this.list<StoredRun>('run')) if (lease.sessionId === id && lease.state === 'active') this.put('run', lease.id, { ...lease, state: 'closed' }); return this.getSession(id)!; }
  assertAccountRelayAvailable(sourceId: string, exceptLeaseId?: string): void {
    const accountSources = new Set([sourceId, ...this.base.accountSiblingSources(sourceId).map(source => source.id)]);
    if (this.list<StoredRelay>('relay').some(lease => lease.id !== exceptLeaseId && accountSources.has(lease.sourceId) && this.relayConnectionValid(lease.id, lease.deviceId))) throw new ShareError('SHARE_RELAY_BUSY', '同一订阅已有有效共享连接，请先停止原设备共享。', 409);
  }
  createRelay(auth: DeviceAuth, sourceId: string): RelayLeaseResponse {
    this.requireScope(auth, 'donor');
    return this.base.transaction(() => {
      const source = this.base.getSource(sourceId); if (!source || source.ownerId !== auth.member.id || !this.isManagedSource(sourceId)) throw missing();
      if (this.policyMeta(sourceId)?.acknowledgedBy !== auth.device.id || this.policyMeta(sourceId)?.appliedRevision !== this.policyMeta(sourceId)?.revision) throw new ShareError('SHARE_POLICY_PENDING', '请先由该贡献设备确认当前规则。', 409);
      if (!['mock', 'subscription'].includes(source.kind)) throw new ShareError('SHARE_CAPABILITY_UNAVAILABLE', '当前来源不支持桌面 Relay 通道。', 501);
      const prior = this.list<StoredRelay>('relay').find(lease => lease.sourceId === sourceId && lease.state === 'active' && lease.expiresAt > Date.now());
      if (prior && (prior.deviceId !== auth.device.id || prior.familyId !== auth.familyId)) throw new ShareError('SHARE_RELAY_BUSY', '来源已有有效节点租约。', 409);
      this.base.assertAccountIdle(sourceId); this.assertAccountRelayAvailable(sourceId, prior?.id);
      if (prior) { const renewed = { ...prior, expiresAt: Date.now() + LEASE_MS }; this.put('relay', prior.id, renewed); return this.relayResponse(renewed); }
      const lease: StoredRelay = { id: randomUUID(), sourceId, deviceId: auth.device.id, familyId: auth.familyId, state: 'active', createdAt: Date.now(), expiresAt: Date.now() + LEASE_MS };
      this.put('relay', lease.id, lease); return this.relayResponse(lease);
    });
  }
  getRelay(id: string): RelayLease | null { const lease = this.get<StoredRelay>('relay', id); if (!lease) return null; const { familyId: _family, ...publicLease } = lease; return { ...publicLease, state: publicLease.state === 'active' && publicLease.expiresAt <= Date.now() ? 'expired' : publicLease.state }; }
  private relayResponse(lease: StoredRelay): RelayLeaseResponse { return { lease: this.getRelay(lease.id)!, token: this.mint('relay', this.get<Family>('family', lease.familyId)!, lease.id), expiresIn: ACCESS_MS / 1000 }; }
  renewRelay(auth: DeviceAuth, id: string): RelayLeaseResponse { this.requireScope(auth, 'donor'); const lease = this.get<StoredRelay>('relay', id); if (!lease || lease.deviceId !== auth.device.id) throw missing(); if (lease.state !== 'active' || lease.expiresAt <= Date.now()) throw new ShareError('SHARE_LEASE_EXPIRED', '节点授权已过期。', 409); this.base.assertAccountIdle(lease.sourceId); this.assertAccountRelayAvailable(lease.sourceId, lease.id); const next = { ...lease, expiresAt: Date.now() + LEASE_MS }; this.put('relay', id, next); return this.relayResponse(next); }
  closeRelay(auth: DeviceAuth, id: string) { const lease = this.get<StoredRelay>('relay', id); if (!lease || lease.deviceId !== auth.device.id) throw missing(); this.put('relay', id, { ...lease, state: 'revoked' }); return this.getRelay(id)!; }
  relayAuth(value: string): RelayAuth { const token = this.token(value, 'relay'); const auth = this.fromToken(token); const lease = token?.leaseId && this.getRelay(token.leaseId); if (!lease || lease.deviceId !== auth.device.id || lease.state !== 'active') throw authError(); return { ...auth, lease }; }
  relayConnectionValid(id: string, deviceId: string): boolean { const lease = this.get<StoredRelay>('relay', id); const device = this.getDevice(deviceId); const family = lease && this.get<Family>('family', lease.familyId); return !!lease && lease.deviceId === deviceId && lease.state === 'active' && lease.expiresAt > Date.now() && device?.status === 'active' && !!family && !family.revoked && family.expiresAt > Date.now() && !!this.base.getMember(device.memberId)?.active; }
  inference(value: string): InferenceAuth { const token = this.token(value, 'inference'); const auth = this.fromToken(token); this.requireScope(auth, 'consumer'); const lease = token?.leaseId && this.getRun(token.leaseId); if (!lease || lease.deviceId !== auth.device.id || lease.state !== 'active') throw authError(); const session = this.ownedSession(auth, lease.sessionId); const grant = this.assertSessionGrant(session); if (session.state !== 'open') throw new ShareError('SHARE_SESSION_CLOSED', '会话已关闭。', 409); return { ...auth, lease, session, grant }; }
  assertInferenceReady(auth: InferenceAuth, model: string) { this.assertSessionGrant(this.ownedSession(auth, auth.session.id)); if (!auth.session.modelScope.includes(model)) throw new ShareError('SHARE_MODEL_NOT_ALLOWED', '模型不属于当前会话。', 403); if (this.getSession(auth.session.id)?.frozen) throw new ShareError('SHARE_DELIVERY_PENDING', '当前会话有待核实的交付或执行结果。', 409); const policy = this.policyMeta(auth.session.sourceId); if (!policy || !['mock', 'subscription'].includes(this.base.getSource(auth.session.sourceId)?.kind ?? '')) throw new ShareError('SHARE_CAPABILITY_UNAVAILABLE', '当前来源不支持桌面推理通道。', 501); if (policy.appliedRevision !== policy.revision) throw new ShareError('SHARE_POLICY_PENDING', '贡献者尚未确认最新本地规则。', 409); }
  requestMeta(id: string): RequestMeta | null { return fromRow<RequestMeta>(this.base.db.prepare('SELECT data FROM client_requests WHERE request_id=?').get(id)); }
  private listRequestMeta() { return this.base.db.prepare('SELECT data FROM client_requests').all().map(row => fromRow<RequestMeta>(row)!); }
  private saveRequestMeta(meta: RequestMeta) { this.base.db.prepare('INSERT OR REPLACE INTO client_requests VALUES(?,?,?,?,?,?)').run(meta.id, meta.deviceId, meta.sessionId, meta.leaseId, meta.operationId, JSON.stringify(meta)); }
  request(id: string): ClientRequest | null { const meta = this.requestMeta(id), request = this.base.getRequest(id); return meta && request ? { ...request, sessionId: meta.sessionId, leaseId: meta.leaseId, deviceId: meta.deviceId, operationId: meta.operationId, consumerDelivery: meta.consumerDelivery } : null; }
  operation(deviceId: string, sessionId: string, operationId: string): ClientRequest | null { const row = this.base.db.prepare('SELECT request_id FROM client_requests WHERE device_id=? AND session_id=? AND operation_id=?').get(deviceId, sessionId, operationId); return row ? this.request(String(row.request_id)) : null; }
  sessionRequests(sessionId: string) { return this.base.db.prepare('SELECT request_id FROM client_requests WHERE session_id=?').all(sessionId).map(row => this.request(String(row.request_id))!).filter(Boolean); }
  deviceRequests(deviceId: string) { return this.base.db.prepare('SELECT request_id FROM client_requests WHERE device_id=?').all(deviceId).map(row => this.request(String(row.request_id))!).filter(Boolean); }
  outstandingDelivery(auth: InferenceAuth) { return this.listRequestMeta().filter(meta => { const request = this.base.getRequest(meta.id); return request?.memberId === auth.member.id && request.sourceId === auth.session.sourceId && isTerminal(request.state) && meta.consumerDelivery !== 'transport_finished' && meta.resolvedAt === null; }).map(meta => this.request(meta.id)!); }
  assertOperationBody(requestId: string, bytes: Buffer, operation: 'responses' | 'compact') { if (this.requestMeta(requestId)?.bodyHash !== hash(bytes) || this.base.getRequest(requestId)?.operation !== operation) throw new ShareError('SHARE_OPERATION_CONFLICT', '同一操作编号不能对应不同请求。', 409); }
  createRequest(auth: InferenceAuth, operationId: string, bytes: Buffer, model: string, operation: 'responses' | 'compact'): RequestRecord {
    return this.base.transaction(() => {
      this.assertInferenceReady(auth, model);
      const old = this.operation(auth.device.id, auth.session.id, operationId);
      if (old) throw new ShareError(this.requestMeta(old.id)?.bodyHash !== hash(bytes) ? 'SHARE_OPERATION_CONFLICT' : 'SHARE_OPERATION_EXISTS', '该操作编号已登记，不会再次调用上游。', 409);
      if (this.sessionRequests(auth.session.id).some(request => !isTerminal(request.state))) throw new ShareError('SHARE_BUSY', '当前会话已有排队或执行中的请求。', 429);
      if (this.outstandingDelivery(auth).some(request => request.consumerDelivery !== 'pending')) throw new ShareError('SHARE_DELIVERY_PENDING', '同成员同来源仍有待核实交付。', 409);
      if (this.base.queuedForSource(auth.session.sourceId).some(request => request.memberId === auth.member.id)) throw new ShareError('SHARE_BUSY', '该成员在此来源已有排队请求。', 429);
      const request = this.base.createRequest({ grantId: auth.grant.id, memberId: auth.member.id, sourceId: auth.session.sourceId, model, operation }, { sessionIsolation: true, withinTransaction: true });
      this.saveRequestMeta({ id: request.id, deviceId: auth.device.id, sessionId: auth.session.id, leaseId: auth.lease.id, operationId, bodyHash: hash(bytes), consumerDelivery: 'pending', resolvedAt: null }); return request;
    });
  }
  dispatchDeliveryBlockers(requestId: string) { const current = this.base.getRequest(requestId); if (!current || !this.requestMeta(requestId)) return []; return this.listRequestMeta().filter(meta => { const request = this.base.getRequest(meta.id); return meta.id !== requestId && request?.memberId === current.memberId && request.sourceId === current.sourceId && isTerminal(request.state) && meta.consumerDelivery !== 'transport_finished' && meta.resolvedAt === null; }).map(meta => this.request(meta.id)!); }
  resolveUnsent(requestId: string) { const meta = this.requestMeta(requestId); if (!meta) return; this.saveRequestMeta({ ...meta, resolvedAt: Date.now() }); const session = this.getSession(meta.sessionId); if (session && !this.sessionRequests(session.id).some(request => request.id !== requestId && (request.state === 'UNKNOWN' || request.consumerDelivery !== 'transport_finished') && this.requestMeta(request.id)?.resolvedAt === null)) this.put('session', session.id, { ...session, frozen: false }); }
  assertDispatch(id: string) { const meta = this.requestMeta(id); if (!meta) return; const device = this.getDevice(meta.deviceId), lease = this.get<StoredRun>('run', meta.leaseId), session = this.getSession(meta.sessionId); const family = lease && this.get<Family>('family', lease.familyId); if (device?.status !== 'active' || !lease || lease.state !== 'active' || lease.expiresAt <= Date.now() || !family || family.revoked || family.expiresAt <= Date.now() || session?.state !== 'open') throw new ShareError('SHARE_LEASE_REVOKED', '运行授权已撤销或到期。', 403); if (device.memberId !== session.memberId) throw missing(); this.assertSessionGrant(session); const policy = this.policyMeta(session.sourceId); if (!policy || policy.revision !== policy.appliedRevision) throw new ShareError('SHARE_POLICY_PENDING', '本地规则尚未同步。', 409); }
  bindResources(requestId: string, ids: string[]) { const meta = this.requestMeta(requestId); if (!meta) return; const request = this.base.getRequest(requestId)!; for (const id of ids) { const prior = this.base.db.prepare('SELECT session_id FROM client_resources WHERE source_id=? AND resource_id=?').get(request.sourceId, id); if (prior && prior.session_id !== meta.sessionId) throw new ShareError('SHARE_RESOURCE_CONFLICT', '响应资源属于另一会话。', 502); this.base.db.prepare('INSERT OR IGNORE INTO client_resources VALUES(?,?,?)').run(request.sourceId, id, meta.sessionId); } }
  assertResource(sourceId: string, sessionId: string, id: string) { const owner = this.base.db.prepare('SELECT session_id FROM client_resources WHERE source_id=? AND resource_id=?').get(sourceId, id); if (!owner || owner.session_id !== sessionId) throw new ShareError('SHARE_RESOURCE_FORBIDDEN', '响应历史不属于当前固定会话。', 403); }
  freezeRequest(id: string, outcome: 'lost' | 'unknown') { const meta = this.requestMeta(id); if (!meta) return false; this.saveRequestMeta({ ...meta, consumerDelivery: outcome }); const session = this.getSession(meta.sessionId); if (session && meta.resolvedAt === null) this.put('session', session.id, { ...session, frozen: true }); return true; }
  deliveryAck(auth: DeviceAuth, requestId: string, operationId: string, outcome: 'transport_finished' | 'lost') {
    const meta = this.requestMeta(requestId), request = this.base.getRequest(requestId); if (!meta || !request || meta.deviceId !== auth.device.id || meta.operationId !== operationId) throw missing();
    if (!isTerminal(request.state)) throw new ShareError('SHARE_DELIVERY_EARLY', '请求尚未终结，请稍后确认交付。', 409);
    if (meta.consumerDelivery === 'lost' && outcome !== 'lost') throw new ShareError('SHARE_DELIVERY_CONFLICT', '已有交付丢失证据，需要人工核实。', 409);
    this.saveRequestMeta({ ...meta, consumerDelivery: outcome });
    if (request.state === 'CANCELLED_NOT_SENT') { this.resolveUnsent(requestId); return this.request(requestId)!; }
    if (outcome === 'lost') this.freezeRequest(requestId, 'lost');
    else if (request.state !== 'UNKNOWN' && !this.sessionRequests(meta.sessionId).some(other => (other.state === 'UNKNOWN' || isTerminal(other.state) && other.consumerDelivery !== 'transport_finished') && !this.requestMeta(other.id)?.resolvedAt)) { const session = this.getSession(meta.sessionId)!; this.put('session', session.id, { ...session, frozen: false }); }
    return this.request(requestId)!;
  }
  resolveSession(auth: DeviceAuth, id: string) { const session = this.ownedSession(auth, id); const requests = this.sessionRequests(id); if (requests.some(request => !isTerminal(request.state))) throw new ShareError('SHARE_BUSY', '会话仍有执行中的请求。', 409); for (const request of requests) { const meta = this.requestMeta(request.id)!; this.saveRequestMeta({ ...meta, resolvedAt: Date.now() }); } this.put('session', id, { ...session, frozen: false }); this.base.audit(auth.member.id, 'session.resolve', id); return this.getSession(id)!; }
}
