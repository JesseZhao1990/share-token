import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { ShareError, type Capabilities, type Operation, type QuotaSnapshot } from '../protocol/index.js';
export { experimentalSubscriptionEnabled, assertExperimentalSubscriptionEnabled, EXPERIMENTAL_SUBSCRIPTION_ENV } from './experimental.js';
export { ResponseObserver } from './observer.js';
export { CodexQuotaReader, normalizeCodexQuota, unknownQuota } from './quota.js';
export { CodexSubscriptionAccount, SubscriptionAdapter } from './subscription.js';
export type { CodexSubscriptionAccountOptions, SubscriptionAccountStatus, SubscriptionAdapterOptions } from './subscription.js';

export interface UpstreamRequest { requestId: string; operation: Operation; model: string; body: Uint8Array }
export interface UpstreamResponse { status: number; headers: Record<string, string>; body: AsyncIterable<Uint8Array> }
export interface UpstreamAdapter {
  inspect(): Promise<Capabilities>;
  readQuota(): Promise<QuotaSnapshot>;
  open(request: UpstreamRequest, signal: AbortSignal): Promise<UpstreamResponse>;
}
export interface MockOptions {
  accountBinding?: string; models?: string[]; delayMs?: number;
  mode?: 'normal' | 'truncate' | 'error' | 'hang'; text?: string; usedPercent?: number; toolName?: string;
}

/** Synthetic protocol fixture. It does not call a model or execute any tool. */
export class MockAdapter implements UpstreamAdapter {
  calls = 0;
  constructor(readonly options: MockOptions = {}) {}
  async inspect(): Promise<Capabilities> {
    return { kind: 'mock', verified: true, accountBinding: this.options.accountBinding ?? 'mock:local', models: this.options.models ?? ['mock-codex'], responses: true, compact: true };
  }
  async readQuota(): Promise<QuotaSnapshot> {
    return { fetchedAt: Date.now(), status: 'available', origin: 'mock', windows: [{ limitId: 'mock:primary', usedPercent: this.options.usedPercent ?? 10, windowDurationMins: 300, resetsAt: Math.floor(Date.now() / 1000) + 3600 }] };
  }
  async open(request: UpstreamRequest, signal: AbortSignal): Promise<UpstreamResponse> {
    signal.throwIfAborted();
    this.calls++;
    const body = JSON.parse(Buffer.from(request.body).toString('utf8')) as Record<string, unknown>;
    const id = `resp_mock_${randomUUID().replaceAll('-', '')}`;
    const itemId = `item_mock_${randomUUID().replaceAll('-', '')}`;
    const usage = { input_tokens: 12, output_tokens: 8, total_tokens: 20, input_tokens_details: { cached_tokens: 0 }, output_tokens_details: { reasoning_tokens: 0 } };
    if (this.options.mode === 'error') return { status: 429, headers: { 'content-type': 'application/json', 'x-share-adapter': 'mock' }, body: single(Buffer.from(JSON.stringify({ error: { code: 'mock_rate_limit', message: 'Synthetic mock rejection' } })), signal) };
    if (request.operation === 'compact') {
      const output = { id, object: 'response.compaction', created_at: Math.floor(Date.now() / 1000), output: [{ id: itemId, type: 'compaction', encrypted_content: 'mock-only-not-portable' }], usage };
      return { status: 200, headers: { 'content-type': 'application/json', 'x-share-adapter': 'mock' }, body: single(Buffer.from(JSON.stringify(output)), signal) };
    }
    const tools = Array.isArray(body.tools) ? body.tools : [];
    const functionTool = tools.find((t: unknown) => typeof t === 'object' && t !== null && (t as Record<string, unknown>).type === 'function' && (t as Record<string, unknown>).name === this.options.toolName) as Record<string, unknown> | undefined;
    const hasToolOutput = Array.isArray(body.input) && body.input.some((item: unknown) => typeof item === 'object' && item !== null && (item as Record<string, unknown>).type === 'function_call_output');
    const text = this.options.text ?? (hasToolOutput ? 'Mock fixture: received the consumer-side tool result. No real model was called.' : 'Mock fixture response · 这是合成输出，未调用真实模型。');
    const outputItem = functionTool && !hasToolOutput
      ? { id: itemId, type: 'function_call', status: 'completed', call_id: `call_mock_${randomUUID().replaceAll('-', '')}`, name: String(functionTool.name), arguments: '{}' }
      : { id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text, annotations: [] }] };
    const completed = { id, object: 'response', created_at: Math.floor(Date.now() / 1000), status: 'completed', model: request.model, output: [outputItem], usage, error: null, incomplete_details: null, metadata: { share_adapter: 'mock' } };
    if (body.stream !== true) return { status: 200, headers: { 'content-type': 'application/json', 'x-share-adapter': 'mock' }, body: single(Buffer.from(JSON.stringify(completed)), signal) };
    const events: Record<string, unknown>[] = [
      { type: 'response.created', response: { ...completed, status: 'in_progress', output: [], usage: null } },
      { type: 'response.in_progress', response: { ...completed, status: 'in_progress', output: [], usage: null } },
      { type: 'response.output_item.added', output_index: 0, item: { ...outputItem, status: 'in_progress', ...(outputItem.type === 'function_call' ? { arguments: '' } : { content: [] }) } },
    ];
    if (outputItem.type === 'function_call') {
      events.push({ type: 'response.function_call_arguments.delta', item_id: itemId, output_index: 0, delta: '{}' });
      events.push({ type: 'response.function_call_arguments.done', item_id: itemId, output_index: 0, arguments: '{}' });
    } else {
      events.push({ type: 'response.content_part.added', item_id: itemId, output_index: 0, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } });
      events.push({ type: 'response.output_text.delta', item_id: itemId, output_index: 0, content_index: 0, delta: text });
      events.push({ type: 'response.output_text.done', item_id: itemId, output_index: 0, content_index: 0, text });
      events.push({ type: 'response.content_part.done', item_id: itemId, output_index: 0, content_index: 0, part: { type: 'output_text', text, annotations: [] } });
    }
    events.push({ type: 'response.output_item.done', output_index: 0, item: outputItem });
    if (this.options.mode !== 'truncate') events.push({ type: 'response.completed', response: completed });
    const options = this.options;
    return { status: 200, headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', 'x-share-adapter': 'mock' }, body: (async function* () {
      if (options.mode === 'hang') { await delay(900_000, undefined, { signal }); return; }
      let sequence = 0;
      for (const event of events) {
        signal.throwIfAborted();
        if (options.delayMs) await delay(options.delayMs, undefined, { signal });
        yield Buffer.from(`event: ${event.type}\ndata: ${JSON.stringify({ ...event, sequence_number: sequence++ })}\n\n`);
      }
    })() };
  }
}

export interface HttpAdapterOptions {
  baseUrl: string; apiKeyEnv: string; accountBinding: string; models: string[];
  quotaReader?: { read(): Promise<QuotaSnapshot> };
}
/** Explicit API fixture only. Never a fallback for an unavailable subscription. */
export class HttpAdapter implements UpstreamAdapter {
  private readonly base: URL;
  private readonly initialCredentialHash: string | null;
  constructor(private readonly options: HttpAdapterOptions) {
    this.base = new URL(options.baseUrl);
    const initialKey = process.env[options.apiKeyEnv];
    this.initialCredentialHash = initialKey ? createHash('sha256').update(initialKey).digest('hex') : null;
    if (this.base.username || this.base.password || this.base.search || this.base.hash) throw new ShareError('SHARE_FIXTURE_URL_INVALID', 'Fixture base URL must not contain credentials, query, or fragment');
    if (this.base.protocol !== 'https:' && !(this.base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(this.base.hostname))) throw new ShareError('SHARE_FIXTURE_URL_INVALID', 'API fixtures require HTTPS or a loopback HTTP server');
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(options.apiKeyEnv)) throw new ShareError('SHARE_FIXTURE_KEY_INVALID', 'Use a local environment variable name for the API key');
  }
  async inspect(): Promise<Capabilities> {
    const key = process.env[this.options.apiKeyEnv];
    return { kind: 'api_fixture', verified: !!key && createHash('sha256').update(key).digest('hex') === this.initialCredentialHash, accountBinding: this.options.accountBinding, models: [...this.options.models], responses: true, compact: true };
  }
  async readQuota(): Promise<QuotaSnapshot> {
    if (this.options.quotaReader) return this.options.quotaReader.read();
    return { fetchedAt: Date.now(), status: 'unknown', origin: 'fixture', windows: [] };
  }
  async open(request: UpstreamRequest, signal: AbortSignal): Promise<UpstreamResponse> {
    const key = process.env[this.options.apiKeyEnv];
    if (key && createHash('sha256').update(key).digest('hex') !== this.initialCredentialHash) throw new ShareError('SHARE_ACCOUNT_CHANGED', 'API fixture credential changed; create a new adapter and review its account binding', 409);
    if (!key) throw new ShareError('SHARE_UPSTREAM_AUTH_REQUIRED', 'The API fixture local key is unavailable', 503);
    const url = new URL(this.base);
    url.pathname = `${url.pathname.replace(/\/$/, '')}/responses${request.operation === 'compact' ? '/compact' : ''}`;
    const result = await fetch(url, { method: 'POST', redirect: 'error', signal, headers: { 'content-type': 'application/json', 'accept-encoding': 'identity', authorization: `Bearer ${key}` }, body: Buffer.from(request.body) });
    if (result.status >= 400) {
      // Providers may echo the rejected API key or other credential details in
      // error bodies. Never pass those bytes to the consumer or the Hub.
      await result.body?.cancel().catch(() => {});
      const headers: Record<string, string> = { 'content-type': 'application/json', 'x-share-adapter': 'api_fixture' };
      const retryAfter = result.headers.get('retry-after');
      if (retryAfter && /^\d{1,6}$/.test(retryAfter)) headers['retry-after'] = retryAfter;
      const error = { error: { code: 'SHARE_UPSTREAM_REJECTED', message: 'The API fixture provider rejected this request. Provider error details are withheld to protect local credentials.' } };
      return { status: result.status, headers, body: single(Buffer.from(JSON.stringify(error)), signal) };
    }
    const headers: Record<string, string> = {};
    for (const name of ['content-type', 'cache-control', 'x-request-id', 'retry-after']) {
      const value = result.headers.get(name); if (value !== null) headers[name] = value;
    }
    headers['x-share-adapter'] = 'api_fixture';
    return { status: result.status, headers, body: (async function* () {
      if (!result.body) return;
      const reader = result.body.getReader();
      try {
        for (;;) { signal.throwIfAborted(); const next = await reader.read(); if (next.done) break; yield next.value; }
      } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    })() };
  }
}
export { HttpAdapter as ApiFixtureAdapter };

async function* single(bytes: Uint8Array, signal: AbortSignal): AsyncIterable<Uint8Array> { signal.throwIfAborted(); yield bytes; }
