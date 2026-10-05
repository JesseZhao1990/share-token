import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, chmodSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import WebSocket from 'ws';
import { checkAdmission } from '../../packages/policy/index.js';
import { CHUNK_BYTES, EMPTY_USAGE, MAX_BODY_BYTES, MAX_BUFFER_BYTES, ShareError, capabilitiesSchema, hubFrameSchema, isTerminal, policySchema, quotaSchema, type Capabilities, type HubFrame, type QuotaSnapshot, type RelayFrame, type SharePolicy, type Terminal, type Usage } from '../../packages/protocol/index.js';
import { ResponseObserver, type UpstreamAdapter } from '../../packages/upstream/index.js';
import { hubTlsOptions } from '../../packages/hub-client/trust.js';

export interface RelayOptions {
  hubUrl: string; token?: string; tokenProvider?: () => Promise<string>; sourceId: string; nodeId: string; dbPath: string;
  policy: SharePolicy; adapter: UpstreamAdapter; heartbeatMs?: number; initialPaused?: boolean;
  policyApprovalHash?: string; onSnapshot?: (snapshot: RelaySnapshot) => void;
  /** A public leaf certificate scoped only to this private HTTPS Hub. */
  hubCertificate?: string;
}
export interface RelaySnapshot {
  sourceId: string; nodeId: string; connected: boolean; paused: boolean; draining: boolean; closed: boolean;
  activeRequestId: string | null; activeState: string | null; unknownCount: number;
  freezeReasons: Array<'identity' | 'unknown'>; quota: QuotaSnapshot | null;
  policy: SharePolicy; policyRevision: number; policyHash: string;
  lastErrorCode: string | null;
}
export interface RelayHandle {
  close(): Promise<void>; pause(paused: boolean): void; waitUntilReady(): Promise<void>;
  drain(): void; stopNow(reason?: string): void; resume(): void; snapshot(): RelaySnapshot;
  onSnapshot(listener: (snapshot: RelaySnapshot) => void): () => void;
  updatePolicy(policy: SharePolicy, options?: { confirmExpansion?: boolean }): RelaySnapshot;
  resolveUnknown(options: { acknowledge: true }): { acknowledged: number; warning: string };
}

interface Attempt {
  requestId: string; fence: number; controller: AbortController; intent: boolean;
  credit: number; seq: number; wake: (() => void) | null; timeout: ReturnType<typeof setTimeout> | null;
}
interface StoredAttempt { request_id: string; body_hash: string; state: string; usage_json: string; response_ids_json: string; error_code: string | null }

/** Foreground outbound relay. No model tool or command is executed in this process. */
export async function createRelay(options: RelayOptions): Promise<RelayHandle> {
  let policy = structuredClone(policySchema.parse(options.policy));
  const boundCapability = capabilitiesSchema.parse(await options.adapter.inspect());
  if (!boundCapability.verified || !boundCapability.responses) throw new ShareError('SHARE_CAPABILITY_UNAVAILABLE', 'The selected adapter is unverified or cannot provide Responses; no relay was started.', 501);
  const url = new URL(options.hubUrl);
  const tls = options.hubCertificate === undefined ? undefined : hubTlsOptions({ version: 1, hubUrl: options.hubUrl, certificatePem: options.hubCertificate });
  if (url.username || url.password || url.search || url.hash) throw new ShareError('SHARE_HUB_URL_INVALID', 'Hub URL must not include credentials, query, or fragment');
  if (url.protocol === 'http:') url.protocol = 'ws:';
  if (url.protocol === 'https:') url.protocol = 'wss:';
  if (!['ws:', 'wss:'].includes(url.protocol) || (url.protocol === 'ws:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new ShareError('SHARE_HUB_URL_INVALID', 'Relay requires WSS or loopback WS');
  if (url.pathname === '/' || url.pathname === '') url.pathname = '/relay/v1';
  if (options.dbPath !== ':memory:') mkdirSync(dirname(options.dbPath), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(options.dbPath);
  if (options.dbPath !== ':memory:') chmodSync(options.dbPath, 0o600);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=3000;
    CREATE TABLE IF NOT EXISTS relay_control (singleton INTEGER PRIMARY KEY CHECK(singleton=1), data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS relay_runtime (singleton INTEGER PRIMARY KEY CHECK(singleton=1), process_id INTEGER NOT NULL, instance_id TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS relay_acknowledgements (request_id TEXT PRIMARY KEY, acknowledged_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS relay_binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), source_id TEXT NOT NULL, account_binding TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS relay_attempts (request_id TEXT PRIMARY KEY, body_hash TEXT NOT NULL, state TEXT NOT NULL, usage_json TEXT NOT NULL,
      response_ids_json TEXT NOT NULL DEFAULT '[]', error_code TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);`);
  const instanceId = randomUUID();
  try {
    db.exec('BEGIN IMMEDIATE');
    const runtime = db.prepare('SELECT process_id FROM relay_runtime WHERE singleton=1').get() as { process_id: number } | undefined;
    if (runtime && processAlive(runtime.process_id)) throw new ShareError('SHARE_RELAY_ALREADY_RUNNING', 'This relay journal is already open by an active relay process', 409);
    db.prepare('INSERT OR REPLACE INTO relay_runtime VALUES(1,?,?)').run(process.pid, instanceId);
    db.exec('COMMIT');
  } catch (error) { try { db.exec('ROLLBACK'); } catch {} db.close(); throw error; }
  const binding = db.prepare('SELECT source_id,account_binding FROM relay_binding WHERE singleton=1').get() as { source_id: string; account_binding: string } | undefined;
  if (binding && (binding.source_id !== options.sourceId || binding.account_binding !== boundCapability.accountBinding)) { db.prepare('DELETE FROM relay_runtime WHERE instance_id=?').run(instanceId); db.close(); throw new ShareError('SHARE_ACCOUNT_CHANGED', 'Relay journal belongs to a different source or account. Create a new source and journal.', 409); }
  if (!binding) db.prepare('INSERT INTO relay_binding VALUES(1,?,?)').run(options.sourceId, boundCapability.accountBinding);
  // A durable sending intent is never replayed after process restart.
  db.prepare("UPDATE relay_attempts SET state='UNKNOWN',error_code='SHARE_RELAY_RESTARTED',updated_at=? WHERE state NOT IN ('COMPLETED','FAILED_KNOWN','CANCELLED_NOT_SENT','UNKNOWN')").run(Date.now());
  const savedRow = db.prepare('SELECT data FROM relay_control WHERE singleton=1').get() as { data: string } | undefined;
  const saved = savedRow ? JSON.parse(savedRow.data) as { paused: boolean; identityFrozen: boolean; policy: SharePolicy; policyRevision: number } : null;
  let policyRevision = saved?.policyRevision ?? 1;
  if (saved && policyHash(saved.policy) !== policyHash(policy)) {
    if (isPolicyExpansion(saved.policy, policy) && options.policyApprovalHash !== policyHash(policy)) {
      db.prepare('DELETE FROM relay_runtime WHERE instance_id=?').run(instanceId); db.close();
      throw new ShareError('SHARE_POLICY_CONFIRMATION_REQUIRED', 'Expanding the saved local policy requires explicit local confirmation', 409);
    }
    policyRevision++;
  }
  let frozen = hasUnacknowledged(db) || (saved?.identityFrozen ?? false);
  let identityFrozen = saved?.identityFrozen ?? false;
  let paused = options.initialPaused ?? saved?.paused ?? false, closed = false, fence = 0, reconnectMs = 250;
  let draining = false;
  let lastQuota: QuotaSnapshot | null = null;
  let lastErrorCode: string | null = null;
  let lastUnknownCount = 0;
  const listeners = new Set<(snapshot: RelaySnapshot) => void>();
  if (options.onSnapshot) listeners.add(options.onSnapshot);
  const persistControl = () => { if (!closed) db.prepare('INSERT OR REPLACE INTO relay_control VALUES(1,?)').run(JSON.stringify({ paused, identityFrozen, policy, policyRevision })); };
  persistControl();
  let socket: WebSocket | null = null;
  let active: Attempt | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  const snapshot = (): RelaySnapshot => {
    if (!closed) lastUnknownCount = Number(db.prepare("SELECT COUNT(*) AS n FROM relay_attempts a LEFT JOIN relay_acknowledgements k ON a.request_id=k.request_id WHERE a.state='UNKNOWN' AND k.request_id IS NULL").get()!.n);
    const activeRow = active && !closed ? db.prepare('SELECT state FROM relay_attempts WHERE request_id=?').get(active.requestId) as { state: string } | undefined : undefined;
    return structuredClone({ sourceId: options.sourceId, nodeId: options.nodeId, connected: !closed && fence > 0 && socket?.readyState === WebSocket.OPEN,
      paused, draining, closed, activeRequestId: active?.requestId ?? null, activeState: activeRow?.state ?? null,
      unknownCount: lastUnknownCount, freezeReasons: [...(identityFrozen ? ['identity' as const] : []), ...(lastUnknownCount ? ['unknown' as const] : [])],
      quota: lastQuota, policy, policyRevision, policyHash: policyHash(policy), lastErrorCode });
  };
  const emit = () => { const state = snapshot(); for (const listener of listeners) { try { listener(state); } catch {} } };
  let heartbeatBusy = false;
  let firstReady = false;
  let resolveReady!: () => void;
  let rejectReady!: (error: Error) => void;
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  // The handle can be returned before callers await readiness; suppress process-level unhandled rejection.
  void ready.catch(() => {});
  const firstReadyTimer = setTimeout(() => { if (!firstReady) rejectReady(new ShareError('SHARE_HUB_UNAVAILABLE', 'Relay did not receive a valid welcome within 10 seconds', 503)); }, 10_000);

  const get = (id: string): StoredAttempt | undefined => db.prepare('SELECT * FROM relay_attempts WHERE request_id=?').get(id) as StoredAttempt | undefined;
  const persist = (id: string, state: string, usage: Usage = { ...EMPTY_USAGE }, ids: string[] = [], errorCode: string | null = null) => {
    db.prepare('UPDATE relay_attempts SET state=?,usage_json=?,response_ids_json=?,error_code=?,updated_at=? WHERE request_id=?').run(state, JSON.stringify(usage), JSON.stringify(ids), errorCode, Date.now(), id);
    if (errorCode) lastErrorCode = errorCode;
  };
  const send = (frame: RelayFrame): boolean => {
    if (!socket || socket.readyState !== WebSocket.OPEN) return false;
    if (socket.bufferedAmount > MAX_BUFFER_BYTES + CHUNK_BYTES * 2) { socket.close(1008, 'Bounded transport exceeded'); return false; }
    const target = socket;
    target.send(JSON.stringify(frame), error => { if (error) target.terminate(); });
    return true;
  };
  const status = (id: string, currentFence: number) => {
    const row = get(id);
    send({ v: 1, type: 'status.result', requestId: id, fence: currentFence, state: row?.state as 'UNKNOWN' ?? 'NOT_FOUND', usage: row ? JSON.parse(row.usage_json) as Usage : { ...EMPTY_USAGE }, responseIds: row ? JSON.parse(row.response_ids_json) as string[] : [] });
  };
  const finish = (attempt: Attempt, state: Terminal, usage: Usage = { ...EMPTY_USAGE }, ids: string[] = [], errorCode: string | null = null) => {
    if (closed) return;
    persist(attempt.requestId, state, usage, ids, errorCode);
    frozen = identityFrozen || hasUnacknowledged(db);
    if (fence === attempt.fence) send({ v: 1, type: 'response.end', requestId: attempt.requestId, fence: attempt.fence, state, usage, responseIds: ids, errorCode });
    else if (fence) send({ v: 1, type: 'status.result', requestId: attempt.requestId, fence, state, usage, responseIds: ids });
    emit();
  };
  const release = (attempt: Attempt) => {
    if (attempt.timeout) clearTimeout(attempt.timeout);
    attempt.wake?.(); attempt.wake = null;
    if (active === attempt) active = null;
    if (!active && draining) draining = false;
    emit();
  };
  const readQuota = async (): Promise<QuotaSnapshot> => {
    try { lastQuota = quotaSchema.parse(await options.adapter.readQuota()); }
    catch { lastQuota = { fetchedAt: Date.now(), status: 'unknown', origin: 'unknown', windows: [] }; }
    if (!closed) emit(); return lastQuota;
  };
  const heartbeat = async () => {
    if (closed || !fence || heartbeatBusy) return;
    heartbeatBusy = true;
    try { const quota = await readQuota(); if (!closed && fence) send({ v: 1, type: 'heartbeat', fence, quota, paused: paused || frozen }); }
    finally { heartbeatBusy = false; }
  };
  const waitCredit = async (attempt: Attempt, size: number) => {
    while (attempt.credit < size) {
      attempt.controller.signal.throwIfAborted();
      await new Promise<void>(resolve => { attempt.wake = resolve; });
      attempt.wake = null;
    }
    attempt.controller.signal.throwIfAborted();
    attempt.credit -= size;
  };

  const openRequest = async (frame: Extract<HubFrame, { type: 'request.open' }>) => {
    const previous = get(frame.requestId);
    const decoded = decodeBody(frame.body);
    const digest = createHash('sha256').update(decoded).digest('hex');
    if (previous) {
      if (previous.body_hash !== digest) { frozen = true; identityFrozen = true; persistControl(); emit(); socket?.close(1008, 'Request id body conflict'); return; }
      status(frame.requestId, frame.fence); return;
    }
    // The synchronous insert and active slot precede all asynchronous inspections.
    db.prepare('INSERT INTO relay_attempts(request_id,body_hash,state,usage_json,created_at,updated_at) VALUES(?,?,?,?,?,?)').run(frame.requestId, digest, 'ACCEPTED', JSON.stringify(EMPTY_USAGE), Date.now(), Date.now());
    const attempt: Attempt = { requestId: frame.requestId, fence: frame.fence, controller: new AbortController(), intent: false, credit: 0, seq: 0, wake: null, timeout: null };
    if (active || paused || frozen) { finish(attempt, 'CANCELLED_NOT_SENT', { ...EMPTY_USAGE }, [], frozen ? 'SHARE_RESULT_UNKNOWN' : 'SHARE_SOURCE_PAUSED'); return; }
    active = attempt; emit();
    send({ v: 1, type: 'request.accepted', requestId: frame.requestId, fence: frame.fence });
    let observer: ResponseObserver | null = null;
    try {
      if (frame.sourceId !== options.sourceId) throw new ShareError('SHARE_SOURCE_MISMATCH', 'Source mismatch');
      const body = JSON.parse(decoded.toString('utf8')) as Record<string, unknown>;
      if (!body || Array.isArray(body) || body.model !== frame.model) throw new ShareError('SHARE_REQUEST_INVALID', 'Request model mismatch');
      if (Date.now() >= frame.deadline) throw new ShareError('SHARE_REQUEST_EXPIRED', 'Request expired before dispatch');
      attempt.timeout = setTimeout(() => { attempt.controller.abort(new Error('Request deadline')); attempt.wake?.(); }, Math.min(frame.deadline - Date.now(), policy.maxRequestMs));
      const identity = capabilitiesSchema.parse(await options.adapter.inspect());
      if (!identity.verified || identity.accountBinding !== boundCapability.accountBinding || identity.kind !== boundCapability.kind) {
        frozen = true; identityFrozen = true; persistControl(); emit();
        throw new ShareError('SHARE_ACCOUNT_CHANGED', 'Actual adapter identity no longer matches this source');
      }
      if (!identity.models.includes(frame.model) || !identity[frame.operation]) throw new ShareError('SHARE_CAPABILITY_UNAVAILABLE', 'Requested model or operation is unavailable');
      const quota = await readQuota();
      const expectedOrigin = { mock: 'mock', api_fixture: 'fixture', subscription: 'codex' }[identity.kind];
      if (quota.origin !== expectedOrigin) throw new ShareError('SHARE_QUOTA_STALE', 'Quota origin does not match the bound adapter');
      checkAdmission({ policy, quota, memberId: frame.memberId, model: frame.model, bodyBytes: decoded.byteLength });
      if (paused || frozen || closed || fence !== attempt.fence || socket?.readyState !== WebSocket.OPEN) throw new ShareError('SHARE_SOURCE_PAUSED', 'Sharing paused before upstream dispatch');
      attempt.controller.signal.throwIfAborted();
      // This durable intent is committed synchronously before any upstream network call.
      persist(frame.requestId, 'UPSTREAM_STARTED'); attempt.intent = true; emit();
      send({ v: 1, type: 'attempt.started', requestId: frame.requestId, fence: frame.fence });
      const response = await options.adapter.open({ requestId: frame.requestId, operation: frame.operation, model: frame.model, body: decoded }, attempt.controller.signal);
      observer = new ResponseObserver((response.headers['content-type'] ?? '').includes('text/event-stream'), frame.operation);
      attempt.controller.signal.throwIfAborted();
      persist(frame.requestId, 'STREAMING'); emit();
      if (!send({ v: 1, type: 'response.head', requestId: frame.requestId, fence: frame.fence, status: response.status, headers: safeHeaders(response.headers) })) throw new Error('Relay disconnected');
      for await (const chunk of response.body) {
        for (let offset = 0; offset < chunk.byteLength; offset += CHUNK_BYTES) {
          const piece = chunk.subarray(offset, Math.min(offset + CHUNK_BYTES, chunk.byteLength));
          await waitCredit(attempt, piece.byteLength);
          observer.feed(piece);
          if (!send({ v: 1, type: 'response.chunk', requestId: frame.requestId, fence: frame.fence, seq: attempt.seq++, data: Buffer.from(piece).toString('base64') })) throw new Error('Relay disconnected');
        }
      }
      const terminal = observer.finish(response.status);
      finish(attempt, terminal, observer.usage, [...observer.responseIds], terminal === 'UNKNOWN' ? 'SHARE_RESULT_UNKNOWN' : null);
    } catch (error) {
      if (!closed) {
        const row = get(attempt.requestId);
        // A disconnect handler may already have conservatively persisted UNKNOWN.
        const observedTerminal = observer && !observer.malformed ? observer.terminal : null;
        if (!row || !isTerminal(row.state) || (row.state === 'UNKNOWN' && observedTerminal)) finish(attempt, observedTerminal ?? (attempt.intent ? 'UNKNOWN' : 'CANCELLED_NOT_SENT'), observer?.usage ?? { ...EMPTY_USAGE }, observer ? [...observer.responseIds] : [], observedTerminal ? null : error instanceof ShareError ? error.code : attempt.intent ? 'SHARE_RESULT_UNKNOWN' : 'SHARE_REQUEST_REJECTED');
      }
    } finally {
      // open() may already own a prefetched upstream reader before response.head or
      // for-await can run. End its lifetime even when that response is never consumed.
      attempt.controller.abort(new Error('Relay attempt finished'));
      release(attempt);
    }
  };

  const onFrame = (raw: WebSocket.RawData) => {
    let frame: HubFrame;
    try { frame = hubFrameSchema.parse(JSON.parse(raw.toString())); }
    catch { socket?.close(1008, 'Invalid protocol'); return; }
    if (frame.type === 'welcome') {
      if (fence || frame.sourceId !== options.sourceId) { socket?.close(1008, 'Invalid welcome'); return; }
      fence = frame.fence; reconnectMs = 250;
      if (!firstReady) { firstReady = true; clearTimeout(firstReadyTimer); resolveReady(); }
      emit(); void heartbeat(); return;
    }
    if (!fence || frame.fence !== fence) return;
    if (frame.type === 'status.query') { status(frame.requestId, fence); return; }
    if (frame.type === 'request.open') { void openRequest(frame).catch(() => { frozen = true; identityFrozen = true; persistControl(); emit(); socket?.close(1008, 'Invalid request'); }); return; }
    if (active?.requestId !== frame.requestId) return;
    if (frame.type === 'window.update') {
      if (active.credit + frame.bytes > MAX_BUFFER_BYTES) { active.controller.abort(new Error('Credit exceeded')); active.wake?.(); socket?.close(1008, 'Credit exceeded'); return; }
      active.credit += frame.bytes; active.wake?.();
    } else if (frame.type === 'cancel.request') { active.controller.abort(new Error('Cancellation requested')); active.wake?.(); }
  };
  const connect = async () => {
    if (closed) return;
    const quota = await readQuota();
    if (closed) return;
    const token = options.tokenProvider ? await options.tokenProvider() : options.token;
    if (!token || /\s/.test(token)) throw new ShareError('SHARE_AUTH_INVALID', 'A valid relay credential is required', 401);
    if (closed) return;
    const ws = new WebSocket(url, { ...(tls ? { ...tls, agent: false as const } : {}), followRedirects: false, headers: { Authorization: `Bearer ${token}` }, maxPayload: Math.ceil(MAX_BODY_BYTES / 3) * 4 + 65536, perMessageDeflate: false, handshakeTimeout: 8000 });
    socket = ws; fence = 0;
    ws.on('open', () => { if (ws !== socket || closed) return; send({ v: 1, type: 'hello', nodeId: options.nodeId, sourceId: options.sourceId, capabilities: boundCapability, quota }); });
    ws.on('message', data => { if (ws === socket && !closed) onFrame(data); });
    ws.on('error', () => {});
    ws.on('close', code => {
      if (ws !== socket || closed) return;
      fence = 0;
      if (active) {
        const attempt = active;
        attempt.controller.abort(new Error('Relay disconnected')); attempt.wake?.();
        const row = get(attempt.requestId);
        if (row && !isTerminal(row.state)) {
          const state = attempt.intent ? 'UNKNOWN' : 'CANCELLED_NOT_SENT';
          persist(attempt.requestId, state, { ...EMPTY_USAGE }, [], 'SHARE_RELAY_DISCONNECTED');
          if (state === 'UNKNOWN') frozen = true;
        }
      }
      emit();
      if (code === 1008 || code >= 4000) { if (!firstReady) rejectReady(new ShareError('SHARE_RELAY_REJECTED', 'Hub rejected the relay identity or protocol', 403)); return; }
      reconnectTimer = setTimeout(() => { void connect().catch(() => {}); }, reconnectMs);
      reconnectMs = Math.min(reconnectMs * 2, 5000);
    });
  };
  const heartbeatTimer = setInterval(() => { void heartbeat(); }, options.heartbeatMs ?? 15_000);
  void connect().catch(() => { rejectReady(new ShareError('SHARE_HUB_UNAVAILABLE', 'Unable to connect relay', 503)); });
  const drain = () => { if (closed) return; paused = true; draining = !!active; persistControl(); emit(); void heartbeat(); };
  const stopNow = (reason = 'Local sharing stopped') => {
    if (closed) return; paused = true; draining = false; persistControl();
    if (active) { active.controller.abort(new Error(reason)); active.wake?.(); }
    emit(); void heartbeat();
  };
  const resume = () => {
    if (closed) throw new ShareError('SHARE_RELAY_STOPPED', 'Relay is closed', 409);
    if (identityFrozen || hasUnacknowledged(db)) throw new ShareError('SHARE_SOURCE_FROZEN', 'Resolve the blocking source condition before resuming sharing', 409);
    paused = false; draining = false; lastErrorCode = null; persistControl(); emit(); void heartbeat();
  };
  emit();
  return {
    waitUntilReady: () => ready, snapshot, drain, stopNow, resume,
    onSnapshot: listener => { listeners.add(listener); listener(snapshot()); return () => { listeners.delete(listener); }; },
    updatePolicy: (nextPolicy, updateOptions = {}) => {
      if (closed) throw new ShareError('SHARE_RELAY_STOPPED', 'Relay is closed', 409);
      const next = policySchema.parse(nextPolicy);
      if (isPolicyExpansion(policy, next) && updateOptions.confirmExpansion !== true) throw new ShareError('SHARE_POLICY_CONFIRMATION_REQUIRED', 'Policy expansion requires explicit local confirmation', 409);
      if (policyHash(policy) !== policyHash(next)) { policy = structuredClone(next); policyRevision++; persistControl(); }
      emit(); void heartbeat(); return snapshot();
    },
    resolveUnknown: acknowledgement => {
      if (closed) throw new ShareError('SHARE_RELAY_STOPPED', 'Relay is closed', 409);
      if (active) throw new ShareError('SHARE_REQUEST_ACTIVE', 'Stop or wait for the active relay attempt before acknowledging unknown requests', 409);
      const result = acknowledgeUnknown(db, acknowledgement.acknowledge);
      frozen = identityFrozen || hasUnacknowledged(db);
      emit(); void heartbeat(); return result;
    },
    pause: value => { if (value) stopNow('Local sharing paused'); else resume(); },
    close: async () => {
      if (closed) return;
      if (active) {
        const row = get(active.requestId);
        if (row && !isTerminal(row.state)) persist(active.requestId, active.intent ? 'UNKNOWN' : 'CANCELLED_NOT_SENT', { ...EMPTY_USAGE }, [], 'SHARE_RELAY_STOPPED');
        active.controller.abort(new Error('Relay stopped')); active.wake?.(); release(active);
      }
      closed = true; clearInterval(heartbeatTimer); clearTimeout(firstReadyTimer); if (reconnectTimer) clearTimeout(reconnectTimer);
      if (!firstReady) rejectReady(new ShareError('SHARE_RELAY_STOPPED', 'Relay stopped before ready', 503));
      if (socket) { const ws = socket; await new Promise<void>(resolve => { const timer = setTimeout(() => { ws.terminate(); resolve(); }, 200); ws.once('close', () => { clearTimeout(timer); resolve(); }); if (ws.readyState === WebSocket.CLOSED) { clearTimeout(timer); resolve(); } else ws.close(); }); }
      db.prepare('DELETE FROM relay_runtime WHERE instance_id=?').run(instanceId);
      db.close(); emit(); listeners.clear();
    },
  };
}
function decodeBody(value: string): Buffer {
  if (!value || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new ShareError('SHARE_REQUEST_INVALID', 'Invalid base64 request');
  const body = Buffer.from(value, 'base64');
  if (!body.byteLength || body.byteLength > MAX_BODY_BYTES || body.toString('base64') !== value) throw new ShareError('SHARE_BODY_TOO_LARGE', 'Invalid or oversized request');
  return body;
}
function safeHeaders(input: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) if (['content-type', 'cache-control', 'x-request-id', 'retry-after', 'x-share-adapter'].includes(key.toLowerCase()) && value.length <= 8192) out[key.toLowerCase()] = value;
  return out;
}

const UNKNOWN_WARNING = 'The old request remains UNKNOWN and may still be executing upstream. Acknowledging risk does not cancel, refund, or replay it. Hub unfreezing is a separate explicit operation.';
function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code !== 'ESRCH'; }
}
function hasUnacknowledged(db: DatabaseSync): boolean {
  return !!db.prepare("SELECT 1 FROM relay_attempts a LEFT JOIN relay_acknowledgements k ON a.request_id=k.request_id WHERE a.state='UNKNOWN' AND k.request_id IS NULL LIMIT 1").get();
}
function acknowledgeUnknown(db: DatabaseSync, acknowledge: boolean): { acknowledged: number; warning: string } {
  if (acknowledge !== true) throw new ShareError('SHARE_RISK_ACKNOWLEDGEMENT_REQUIRED', UNKNOWN_WARNING, 409);
  const result = db.prepare("INSERT OR IGNORE INTO relay_acknowledgements(request_id,acknowledged_at) SELECT request_id,? FROM relay_attempts WHERE state='UNKNOWN'").run(Date.now());
  return { acknowledged: Number(result.changes), warning: UNKNOWN_WARNING };
}
/** Offline, explicit operator action. Never edits the unknown request's terminal state. */
export function resolveRelayUnknown(dbPath: string, acknowledge: boolean): { acknowledged: number; warning: string } {
  if (dbPath === ':memory:' || !existsSync(dbPath)) throw new ShareError('SHARE_RELAY_JOURNAL_MISSING', 'An existing relay journal is required for acknowledgement', 404);
  const db = new DatabaseSync(dbPath, { open: true });
  try {
    db.exec('PRAGMA busy_timeout=3000; BEGIN IMMEDIATE;');
    const runtime = db.prepare('SELECT process_id FROM relay_runtime WHERE singleton=1').get() as { process_id: number } | undefined;
    if (runtime && processAlive(runtime.process_id)) throw new ShareError('SHARE_RELAY_ALREADY_RUNNING', 'Stop the relay before using offline acknowledgement; the process may still have an active request.', 409);
    if (db.prepare("SELECT 1 FROM relay_attempts WHERE state NOT IN ('COMPLETED','FAILED_KNOWN','CANCELLED_NOT_SENT','UNKNOWN') LIMIT 1").get()) throw new ShareError('SHARE_UNRECOVERED_ATTEMPT', 'Restart and stop the relay first to reconcile interrupted sending intentions.', 409);
    const result = acknowledgeUnknown(db, acknowledge);
    db.exec('COMMIT'); return result;
  } catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
  finally { db.close(); }
}

/** Deterministic digest of a validated policy; no credential or request content is included. */
export function policyHash(value: SharePolicy): string {
  const parsed = policySchema.parse(value);
  return createHash('sha256').update(JSON.stringify({ ...parsed, allowedMemberIds: [...parsed.allowedMemberIds].sort(), models: [...parsed.models].sort(), schedule: parsed.schedule ? { ...parsed.schedule, days: [...parsed.schedule.days].sort() } : null })).digest('hex');
}
/** Conservative permission comparison. A changed timezone is always a possible expansion. */
export function isPolicyExpansion(before: SharePolicy, after: SharePolicy): boolean {
  if (after.allowedMemberIds.some(id => !before.allowedMemberIds.includes(id)) || after.models.some(model => !before.models.includes(model))) return true;
  if ((!before.enabled && after.enabled) || after.reservePercent < before.reservePercent || after.startMarginPercent < before.startMarginPercent || after.maxRequestMs > before.maxRequestMs || after.maxBodyBytes > before.maxBodyBytes || after.quotaMaxAgeMs > before.quotaMaxAgeMs) return true;
  if (before.expiresAt !== null && (after.expiresAt === null || after.expiresAt > before.expiresAt)) return true;
  if (!before.schedule) return false;
  if (!after.schedule || before.schedule.timeZone !== after.schedule.timeZone) return true;
  const oldMinutes = scheduleMinutes(before.schedule); const newMinutes = scheduleMinutes(after.schedule);
  return [...newMinutes].some(minute => !oldMinutes.has(minute));
}
function scheduleMinutes(schedule: NonNullable<SharePolicy['schedule']>): Set<number> {
  const minutes = new Set<number>();
  const number = (time: string) => Number(time.slice(0, 2)) * 60 + Number(time.slice(3));
  const start = number(schedule.start); let end = number(schedule.end); if (end <= start) end += 1440;
  for (const day of schedule.days) for (let minute = start; minute < end; minute++) minutes.add((day * 1440 + minute) % 10080);
  return minutes;
}

export function inspectRelayJournal(dbPath: string): { unknownCount: number; identityFrozen: boolean; paused: boolean } | null {
  if (!existsSync(dbPath)) return null;
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const row = db.prepare('SELECT data FROM relay_control WHERE singleton=1').get() as { data: string } | undefined;
    const control = row ? JSON.parse(row.data) as { identityFrozen?: boolean; paused?: boolean } : {};
    const count = db.prepare("SELECT COUNT(*) AS n FROM relay_attempts a LEFT JOIN relay_acknowledgements k ON a.request_id=k.request_id WHERE a.state='UNKNOWN' AND k.request_id IS NULL").get()!;
    return { unknownCount: Number(count.n), identityFrozen: control.identityFrozen === true, paused: control.paused === true };
  } finally { db.close(); }
}
