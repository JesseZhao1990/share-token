import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { z } from 'zod';
import { quotaSchema, type QuotaSnapshot } from '../protocol/index.js';

export function unknownQuota(origin: QuotaSnapshot['origin'] = 'codex', now = Date.now()): QuotaSnapshot {
  return { fetchedAt: now, status: 'unknown', origin, windows: [] };
}
// Field names verified against `codex app-server generate-ts` from CLI 0.153.4.
// Unknown schema fields and uninterpreted spending buckets fail closed.
const windowSchema = z.object({ usedPercent: z.number().min(0).max(100), windowDurationMins: z.number().positive(), resetsAt: z.number().int().nonnegative().nullable() }).strict();
const bucketSchema = z.object({
  limitId: z.string().min(1).max(100).nullable().optional(), limitName: z.string().nullable().optional(),
  primary: windowSchema.nullable(), secondary: windowSchema.nullable(),
  credits: z.object({ hasCredits: z.boolean(), unlimited: z.boolean(), balance: z.string().nullable() }).strict().nullable().optional(),
  individualLimit: z.null().optional(), spendControlReached: z.literal(false).nullable().optional(),
  planType: z.string().nullable().optional(), rateLimitReachedType: z.null().optional(),
}).strict();
const resultSchema = z.object({
  rateLimits: bucketSchema,
  rateLimitsByLimitId: z.record(z.string().min(1).max(100), bucketSchema).nullable().optional(),
  rateLimitResetCredits: z.unknown().optional(), accountId: z.string().nullable().optional(), rateLimitUpsell: z.unknown().optional(),
}).strict();

export function normalizeCodexQuota(raw: unknown, now = Date.now()): QuotaSnapshot {
  const parsed = resultSchema.safeParse(raw);
  if (!parsed.success) return unknownQuota('codex', now);
  const result = parsed.data;
  const buckets = result.rateLimitsByLimitId === null || result.rateLimitsByLimitId === undefined
    ? [[result.rateLimits.limitId ?? 'legacy', result.rateLimits] as const]
    : Object.entries(result.rateLimitsByLimitId);
  if (!buckets.length || buckets.length > 16) return unknownQuota('codex', now);
  const windows: QuotaSnapshot['windows'] = [];
  for (const [key, bucket] of buckets) {
    if (bucket.limitId && bucket.limitId !== key && key !== 'legacy') return unknownQuota('codex', now);
    if (bucket.credits?.hasCredits || bucket.credits?.unlimited) return unknownQuota('codex', now);
    if (!bucket.primary && !bucket.secondary) return unknownQuota('codex', now);
    for (const name of ['primary', 'secondary'] as const) {
      const window = bucket[name];
      if (window) windows.push({ limitId: `${key}:${name}`, ...window });
    }
  }
  const normalized = quotaSchema.safeParse({ fetchedAt: now, status: 'available', origin: 'codex', windows });
  return normalized.success ? normalized.data : unknownQuota('codex', now);
}

export interface CodexQuotaReaderOptions { binary?: string; timeoutMs?: number }
/** One-shot, read-only JSON-RPC client; no auth files or model/agent RPCs are used. */
export class CodexQuotaReader {
  constructor(private readonly options: CodexQuotaReaderOptions = {}) {}
  async read(): Promise<QuotaSnapshot> {
    try { return normalizeCodexQuota(await this.readRaw()); }
    catch { return unknownQuota('codex'); }
  }
  private readRaw(): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.options.binary ?? 'codex', ['app-server', '--listen', 'stdio://'], { cwd: tmpdir(), stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
      let done = false;
      let initialized = false;
      let buffer = '';
      const timer = setTimeout(() => finish(new Error('Quota read timed out')), this.options.timeoutMs ?? 10_000);
      const finish = (error?: Error, value?: unknown) => {
        if (done) return; done = true; clearTimeout(timer);
        child.stdin.end(); child.kill('SIGTERM');
        const killTimer = setTimeout(() => { if (child.exitCode === null) child.kill('SIGKILL'); }, 1000);
        killTimer.unref(); child.once('exit', () => clearTimeout(killTimer));
        if (error) reject(error); else resolve(value);
      };
      const send = (value: object) => { child.stdin.write(`${JSON.stringify(value)}\n`); };
      child.once('spawn', () => send({ id: 1, method: 'initialize', params: { clientInfo: { name: 'share_token_quota_reader', title: 'Share Token read-only quota reader', version: '0.1.0' }, capabilities: { experimentalApi: false, requestAttestation: false } } }));
      child.stdin.on('error', () => finish(new Error('Quota transport unavailable')));
      child.once('error', () => finish(new Error('Codex app server unavailable')));
      child.once('exit', () => { if (!done) finish(new Error('Quota reader exited before response')); });
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => {
        if (done) return;
        buffer += chunk;
        if (buffer.length > 1024 * 1024) { finish(new Error('Quota protocol response too large')); return; }
        let newline: number;
        while (!done && (newline = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
          let frame: Record<string, unknown>;
          try { frame = JSON.parse(line); if (!frame || typeof frame !== 'object' || Array.isArray(frame)) throw new Error('Invalid RPC frame'); } catch { finish(new Error('Invalid quota protocol')); return; }
          if (frame.id === 1 && !initialized) {
            if (frame.error || !frame.result) { finish(new Error('Quota initialization failed')); return; }
            initialized = true; send({ method: 'initialized' }); send({ id: 2, method: 'account/rateLimits/read' });
          } else if (frame.id === 2 && initialized) {
            if (frame.error) finish(new Error('Quota read unavailable')); else finish(undefined, frame.result);
          }
          // All notifications and incoming server requests are ignored. No login,
          // reset-credit, shell, tool, or turn RPC is ever sent by this component.
        }
      });
    });
  }
}
