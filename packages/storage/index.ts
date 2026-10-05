import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { EMPTY_USAGE, ShareError, isTerminal, type Member, type Source, type Grant, type RequestRecord, type RequestState, type Operation, type SharePolicy, type AdapterKind } from '../protocol/index.js';

export type CredentialKind = 'control' | 'session' | 'grant' | 'relay' | 'invitation';
export interface Credential { hash: string; kind: CredentialKind; memberId: string; sourceId: string | null; grantId: string | null; expiresAt: number | null; revoked: boolean; csrfToken: string | null }
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const makeToken = (kind: string) => `st_${kind}_${randomBytes(32).toString('base64url')}`;
const parse = <T>(row: unknown): T | null => row ? JSON.parse((row as { data: string }).data) as T : null;
const terminalSql = "'COMPLETED','FAILED_KNOWN','CANCELLED_NOT_SENT','UNKNOWN'";
const sourceBindingKey = (source: Pick<Source, 'ownerId' | 'kind' | 'accountBinding'>) => JSON.stringify([source.ownerId, source.kind, source.accountBinding]);

/** A synchronous, single-process ledger. Prompt and response bodies never enter this store. */
export class Store {
  readonly db: DatabaseSync;
  private runtimeLease: string | null = null;
  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS members(id TEXT PRIMARY KEY, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS credentials(hash TEXT PRIMARY KEY, kind TEXT NOT NULL, member_id TEXT NOT NULL REFERENCES members(id), data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY, binding TEXT NOT NULL UNIQUE, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id), source_id TEXT NOT NULL REFERENCES sources(id), data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id), source_id TEXT NOT NULL REFERENCES sources(id), state TEXT NOT NULL, created_at INTEGER NOT NULL, data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS requests_source_state ON requests(source_id,state);
      CREATE INDEX IF NOT EXISTS requests_grant_state ON requests(grant_id,state);
      CREATE TABLE IF NOT EXISTS resource_bindings(source_id TEXT NOT NULL, response_id TEXT NOT NULL, grant_id TEXT NOT NULL, PRIMARY KEY(source_id,response_id));
      CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY, actor_id TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS hub_runtime(singleton INTEGER PRIMARY KEY CHECK(singleton=1),process_id INTEGER NOT NULL,instance_id TEXT NOT NULL);
    `);
  }
  acquireHubLease() {
    if (this.runtimeLease) return;
    this.transaction(() => {
      const current = this.db.prepare('SELECT process_id FROM hub_runtime WHERE singleton=1').get();
      if (current) {
        let alive = true;
        try { process.kill(Number(current.process_id), 0); } catch (error) { alive = (error as NodeJS.ErrnoException).code !== 'ESRCH'; }
        if (alive) throw new ShareError('SHARE_HUB_ALREADY_RUNNING', '已有 Hub 进程使用该数据库，请先关闭原实例。', 409);
      }
      const lease = randomUUID();
      this.db.prepare('INSERT OR REPLACE INTO hub_runtime VALUES(1,?,?)').run(process.pid, lease);
      this.runtimeLease = lease;
    });
  }
  close() { if (this.runtimeLease) this.db.prepare('DELETE FROM hub_runtime WHERE instance_id=?').run(this.runtimeLease); this.db.close(); }
  transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.db.exec('COMMIT'); return result; } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  createMember(name: string, role: Member['role'] = 'member'): Member {
    const member: Member = { id: randomUUID(), name, role, active: true, createdAt: Date.now() };
    this.db.prepare('INSERT INTO members VALUES(?,?)').run(member.id, JSON.stringify(member)); return member;
  }
  getMember(id: string) { return parse<Member>(this.db.prepare('SELECT data FROM members WHERE id=?').get(id)); }
  deactivateMember(id: string) { const member = this.getMember(id); if (member) this.db.prepare('UPDATE members SET data=? WHERE id=?').run(JSON.stringify({ ...member, active: false }), id); }
  listMembers() { return this.db.prepare('SELECT data FROM members').all().map(row => parse<Member>(row)!); }
  ensureAdmin(token: string) {
    let admin = this.listMembers().find(member => member.role === 'admin' && member.active);
    admin ??= this.createMember('管理员', 'admin');
    // The configured bootstrap secret is the only bootstrap credential accepted after restart.
    for (const row of this.db.prepare("SELECT data FROM credentials WHERE kind='control' AND member_id=?").all(admin.id)) {
      const cred = parse<Credential>(row)!;
      if (cred.hash !== digest(token)) this.revokeCredential(cred.hash);
    }
    this.saveCredential({ hash: digest(token), kind: 'control', memberId: admin.id, sourceId: null, grantId: null, expiresAt: null, revoked: false, csrfToken: null });
    return admin;
  }
  private saveCredential(cred: Credential) { this.db.prepare('INSERT OR REPLACE INTO credentials VALUES(?,?,?,?)').run(cred.hash, cred.kind, cred.memberId, JSON.stringify(cred)); }
  issueCredential(kind: CredentialKind, memberId: string, options: { sourceId?: string; grantId?: string; expiresAt?: number | null } = {}) {
    const token = makeToken(kind);
    const credential: Credential = { hash: digest(token), kind, memberId, sourceId: options.sourceId ?? null, grantId: options.grantId ?? null, expiresAt: options.expiresAt ?? null, revoked: false, csrfToken: kind === 'session' ? makeToken('csrf') : null };
    this.saveCredential(credential); return { token, credential };
  }
  authenticate(token: string, kind: CredentialKind): Credential | null {
    if (!token || token.length > 512) return null;
    const credential = parse<Credential>(this.db.prepare('SELECT data FROM credentials WHERE hash=? AND kind=?').get(digest(token), kind));
    if (!credential || credential.revoked || (credential.expiresAt !== null && credential.expiresAt <= Date.now()) || !this.getMember(credential.memberId)?.active) return null;
    return credential;
  }
  revokeCredential(hash: string) { const cred = parse<Credential>(this.db.prepare('SELECT data FROM credentials WHERE hash=?').get(hash)); if (cred) this.saveCredential({ ...cred, revoked: true }); }
  redeemInvitation(token: string, name: string) {
    return this.transaction(() => {
      const invitation = this.authenticate(token, 'invitation');
      if (!invitation) throw new ShareError('SHARE_INVITATION_INVALID', '邀请无效、已使用或已过期。', 401);
      this.revokeCredential(invitation.hash);
      const member = this.createMember(name);
      return { member, ...this.issueCredential('control', member.id) };
    });
  }
  createSource(input: { name: string; ownerId: string; kind: AdapterKind; accountBinding: string; policy: SharePolicy }): Source {
    // Read the immutable source fields as well as writing the new key: standalone Store callers
    // can encounter pre-migration rows whose binding still uses the old account-wide format.
    if (this.db.prepare("SELECT id FROM sources WHERE json_extract(data,'$.ownerId')=? AND json_extract(data,'$.kind')=? AND json_extract(data,'$.accountBinding')=?").get(input.ownerId, input.kind, input.accountBinding)) throw new ShareError('SHARE_SOURCE_EXISTS', '当前成员已为该账户创建来源。', 409);
    const source: Source = { ...input, id: randomUUID(), paused: false, frozen: false, fence: 0, quota: null, capabilities: null, online: false, lastSeen: null, createdAt: Date.now() };
    this.db.prepare('INSERT INTO sources VALUES(?,?,?)').run(source.id, sourceBindingKey(source), JSON.stringify(source)); return source;
  }
  getSource(id: string) { return parse<Source>(this.db.prepare('SELECT data FROM sources WHERE id=?').get(id)); }
  listSources() { return this.db.prepare('SELECT data FROM sources').all().map(row => parse<Source>(row)!); }
  accountSiblingSources(sourceId: string): Source[] {
    const source = this.getSource(sourceId); if (!source) throw new ShareError('SHARE_NOT_FOUND', '来源不存在。', 404);
    return this.db.prepare("SELECT data FROM sources WHERE id<>? AND json_extract(data,'$.kind')=? AND json_extract(data,'$.accountBinding')=?").all(sourceId, source.kind, source.accountBinding).map(row => parse<Source>(row)!);
  }
  /** New identities own separate sources, but cannot bypass another source's live/unknown work. */
  assertAccountIdle(sourceId: string): void {
    const hasClientRequests = !!this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='client_requests'").get();
    for (const sibling of this.accountSiblingSources(sourceId)) {
      if (sibling.frozen) throw new ShareError('SHARE_RESULT_UNKNOWN', '同一订阅的其他来源有待核实结果，请先在原设备核实。', 409);
      if (sibling.online) throw new ShareError('SHARE_RELAY_BUSY', '同一订阅正在另一来源提供共享，请先停止原设备共享。', 409);
      for (const request of this.listSourceRequests(sibling.id)) {
        if (!isTerminal(request.state)) throw new ShareError('SHARE_RELAY_BUSY', '同一订阅的其他来源仍有请求未完成，请等待结束。', 409);
        const meta = hasClientRequests ? parse<{ resolvedAt: number | null; consumerDelivery: string }>(this.db.prepare('SELECT data FROM client_requests WHERE request_id=?').get(request.id)) : null;
        if (meta) {
          if (meta.resolvedAt === null && (request.state === 'UNKNOWN' || request.state !== 'CANCELLED_NOT_SENT' && meta.consumerDelivery !== 'transport_finished')) throw new ShareError('SHARE_RESULT_UNKNOWN', '同一订阅的其他来源有待核实结果，请先在原设备核实。', 409);
        } else if (request.state === 'UNKNOWN' && this.getGrant(request.grantId)?.frozen) {
          // Legacy acknowledgement clears the source and grant freeze flags; historical UNKNOWN
          // records themselves remain unchanged and must not permanently prevent a new source.
          throw new ShareError('SHARE_RESULT_UNKNOWN', '同一订阅的其他来源有待核实结果，请先核实原授权。', 409);
        }
      }
    }
  }
  updateSource(id: string, patch: Partial<Omit<Source, 'id' | 'ownerId' | 'kind' | 'accountBinding'>>) {
    const old = this.getSource(id); if (!old) throw new ShareError('SHARE_NOT_FOUND', '来源不存在。', 404);
    const value = { ...old, ...patch }; this.db.prepare('UPDATE sources SET data=? WHERE id=?').run(JSON.stringify(value), id); return value;
  }
  createGrant(input: { memberId: string; sourceId: string; label: string; models: string[]; expiresAt?: number | null }): Grant {
    const grant: Grant = { ...input, id: randomUUID(), revoked: false, frozen: false, expiresAt: input.expiresAt ?? null, createdAt: Date.now() };
    this.db.prepare('INSERT INTO grants VALUES(?,?,?,?)').run(grant.id, grant.memberId, grant.sourceId, JSON.stringify(grant)); return grant;
  }
  getGrant(id: string) { return parse<Grant>(this.db.prepare('SELECT data FROM grants WHERE id=?').get(id)); }
  listGrants() { return this.db.prepare('SELECT data FROM grants').all().map(row => parse<Grant>(row)!); }
  updateGrant(id: string, patch: Partial<Pick<Grant, 'revoked' | 'frozen'>>) {
    const old = this.getGrant(id); if (!old) throw new ShareError('SHARE_NOT_FOUND', '授权不存在。', 404);
    const value = { ...old, ...patch }; this.db.prepare('UPDATE grants SET data=? WHERE id=?').run(JSON.stringify(value), id); return value;
  }
  getRequest(id: string) { return parse<RequestRecord>(this.db.prepare('SELECT data FROM requests WHERE id=?').get(id)); }
  listRequests(limit = 200) { return this.db.prepare('SELECT data FROM requests ORDER BY created_at DESC,rowid DESC LIMIT ?').all(limit).map(row => parse<RequestRecord>(row)!); }
  listVisibleRequests(member: Member, limit = 200) {
    if (member.role === 'admin') return this.listRequests(limit);
    return this.db.prepare("SELECT data FROM requests WHERE json_extract(requests.data,'$.memberId')=? OR source_id IN (SELECT id FROM sources WHERE json_extract(data,'$.ownerId')=?) ORDER BY created_at DESC,rowid DESC LIMIT ?")
      .all(member.id, member.id, limit).map(row => parse<RequestRecord>(row)!);
  }
  requestStats(member: Member) {
    const clause = member.role === 'admin' ? '1=1' : "(json_extract(requests.data,'$.memberId')=? OR source_id IN (SELECT id FROM sources WHERE json_extract(data,'$.ownerId')=?))";
    const row = this.db.prepare(`SELECT
      COALESCE(SUM(CASE WHEN state='COMPLETED' THEN 1 ELSE 0 END),0) AS completed,
      COALESCE(SUM(CASE WHEN state='UNKNOWN' THEN 1 ELSE 0 END),0) AS unknown,
      COALESCE(SUM(json_extract(data,'$.usage.inputTokens')),0) AS inputTokens,
      COALESCE(SUM(json_extract(data,'$.usage.outputTokens')),0) AS outputTokens
      FROM requests WHERE ${clause}`).get(...(member.role === 'admin' ? [] : [member.id, member.id]))!;
    return { completed: Number(row.completed), unknown: Number(row.unknown), inputTokens: Number(row.inputTokens), outputTokens: Number(row.outputTokens) };
  }
  listSourceRequests(sourceId: string) { return this.db.prepare('SELECT data FROM requests WHERE source_id=? ORDER BY created_at,rowid').all(sourceId).map(row => parse<RequestRecord>(row)!); }
  activeForSource(sourceId: string) { return parse<RequestRecord>(this.db.prepare(`SELECT data FROM requests WHERE source_id=? AND state NOT IN (${terminalSql},'QUEUED') LIMIT 1`).get(sourceId)); }
  queuedForSource(sourceId: string) { return this.db.prepare("SELECT data FROM requests WHERE source_id=? AND state='QUEUED' ORDER BY created_at,rowid").all(sourceId).map(row => parse<RequestRecord>(row)!); }
  createRequest(input: { grantId: string; memberId: string; sourceId: string; model: string; operation: Operation }, options: { withinTransaction?: boolean; sessionIsolation?: boolean } = {}): RequestRecord {
    const allocate = () => {
      if (!options.sessionIsolation && this.db.prepare(`SELECT id FROM requests WHERE grant_id=? AND state NOT IN (${terminalSql}) LIMIT 1`).get(input.grantId)) throw new ShareError('SHARE_BUSY', '该接入凭据已有排队或执行中的请求。', 429);
      const busy = this.activeForSource(input.sourceId) !== null;
      if (busy && this.queuedForSource(input.sourceId).length >= 3) throw new ShareError('SHARE_BUSY', '来源队列已满。', 429);
      const source = this.getSource(input.sourceId)!;
      const request: RequestRecord = { ...input, id: randomUUID(), state: busy ? 'QUEUED' : 'RESERVED', fence: source.fence, createdAt: Date.now(), startedAt: null, finishedAt: null, delivery: 'pending', cancelRequested: false, errorCode: null, usage: { ...EMPTY_USAGE } };
      this.db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?)').run(request.id, request.grantId, request.sourceId, request.state, request.createdAt, JSON.stringify(request)); return request;
    };
    return options.withinTransaction ? allocate() : this.transaction(allocate);
  }
  updateRequest(id: string, patch: Partial<Pick<RequestRecord, 'state' | 'fence' | 'startedAt' | 'finishedAt' | 'delivery' | 'cancelRequested' | 'errorCode' | 'usage'>>) {
    const old = this.getRequest(id); if (!old) throw new ShareError('SHARE_NOT_FOUND', '请求不存在。', 404);
    const value = { ...old, ...patch }; this.db.prepare('UPDATE requests SET state=?,data=? WHERE id=?').run(value.state, JSON.stringify(value), id); return value;
  }
  bindResources(sourceId: string, grantId: string, ids: string[]) {
    for (const id of ids) {
      const old = this.db.prepare('SELECT grant_id FROM resource_bindings WHERE source_id=? AND response_id=?').get(sourceId, id);
      if (old && old.grant_id !== grantId) throw new ShareError('SHARE_RESOURCE_CONFLICT', '上游资源绑定冲突。', 502);
      this.db.prepare('INSERT OR IGNORE INTO resource_bindings VALUES(?,?,?)').run(sourceId, id, grantId);
    }
  }
  assertResourceOwnership(sourceId: string, grantId: string, responseId: string) {
    const row = this.db.prepare('SELECT grant_id FROM resource_bindings WHERE source_id=? AND response_id=?').get(sourceId, responseId);
    if (!row || row.grant_id !== grantId) throw new ShareError('SHARE_RESOURCE_FORBIDDEN', '响应历史不属于当前固定授权。', 403);
  }
  audit(actorId: string, action: string, targetId: string) { this.db.prepare('INSERT INTO audit_events(actor_id,action,target_id,created_at) VALUES(?,?,?,?)').run(actorId, action, targetId, Date.now()); }
  recoverInterrupted() {
    return this.transaction(() => {
      for (const source of this.listSources()) this.updateSource(source.id, { online: false });
      const interrupted = this.db.prepare(`SELECT data FROM requests WHERE state NOT IN (${terminalSql})`).all().map(row => parse<RequestRecord>(row)!);
      for (const req of interrupted) {
        const safe = req.state === 'QUEUED' || req.state === 'RESERVED';
        this.updateRequest(req.id, { state: safe ? 'CANCELLED_NOT_SENT' : 'UNKNOWN', delivery: safe ? 'lost' : 'unknown', finishedAt: Date.now(), errorCode: 'SHARE_HUB_RESTARTED' });
        if (!safe) { this.updateSource(req.sourceId, { frozen: true }); this.updateGrant(req.grantId, { frozen: true }); }
      }
      return interrupted;
    });
  }
}
