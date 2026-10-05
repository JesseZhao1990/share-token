import { EMPTY_USAGE, MAX_BODY_BYTES, idSchema, type Operation, type Terminal, type Usage } from '../protocol/index.js';

/** Metadata-only observer. Bytes are forwarded unchanged by the relay. */
export class ResponseObserver {
  readonly responseIds = new Set<string>();
  readonly completedItemIds = new Set<string>();
  usage: Usage = { ...EMPTY_USAGE };
  terminal: Terminal | null = null;
  malformed = false;
  private decoder = new TextDecoder('utf-8', { fatal: true });
  private buffer = '';
  private dataLines: string[] = [];
  private eventSize = 0;
  private jsonBytes = 0;
  private json: Uint8Array[] = [];

  constructor(private readonly streaming: boolean, private readonly operation: Operation = 'responses') {}

  feed(chunk: Uint8Array): void {
    if (this.malformed) return;
    try {
      if (!this.streaming) {
        this.jsonBytes += chunk.byteLength;
        if (this.jsonBytes > MAX_BODY_BYTES) throw new Error('metadata buffer exceeded');
        this.json.push(chunk.slice());
        return;
      }
      this.buffer += this.decoder.decode(chunk, { stream: true });
      if (this.buffer.length > MAX_BODY_BYTES) throw new Error('metadata buffer exceeded');
      this.consumeLines(false);
    } catch { this.malformed = true; }
  }

  finish(status: number): Terminal {
    if (!this.malformed) {
      try {
        if (this.streaming) {
          this.buffer += this.decoder.decode();
          this.consumeLines(true);
        } else {
          const value: unknown = JSON.parse(Buffer.concat(this.json).toString('utf8'));
          this.observeResponse(value);
          const obj = record(value);
          if (this.operation === 'compact' && obj?.object === 'response.compaction' && idSchema.safeParse(obj.id).success && Array.isArray(obj.output) && obj.output.length > 0) this.terminal = 'COMPLETED';
        }
      } catch { this.malformed = true; }
    }
    this.json = [];
    // HTTP rejection is a known failed attempt, independent of error-body shape.
    if (status >= 400) return 'FAILED_KNOWN';
    // A transport EOF or [DONE] alone is never proof of completion.
    return this.malformed ? 'UNKNOWN' : this.terminal ?? 'UNKNOWN';
  }

  private consumeLines(eof: boolean): void {
    let newline: number;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline).replace(/\r$/, '');
      this.buffer = this.buffer.slice(newline + 1);
      this.line(line);
    }
    // Incomplete final SSE events are intentionally not dispatched at EOF.
    if (eof && this.buffer.trim()) this.malformed = true;
  }

  private line(line: string): void {
    if (!line) {
      if (this.dataLines.length) {
        const data = this.dataLines.join('\n');
        if (data !== '[DONE]') this.observeEvent(JSON.parse(data));
      }
      this.dataLines = [];
      this.eventSize = 0;
      return;
    }
    this.eventSize += line.length;
    if (this.eventSize > MAX_BODY_BYTES) throw new Error('metadata event exceeded');
    if (line.startsWith('data:')) this.dataLines.push(line.slice(5).replace(/^ /, ''));
  }

  private addId(id: unknown): void {
    if (idSchema.safeParse(id).success && this.responseIds.size < 512) this.responseIds.add(id as string);
  }

  private observeEvent(value: unknown): void {
    const event = record(value);
    if (!event) throw new Error('invalid event');
    const response = record(event.response);
    if (response) this.observeResponse(response);
    const item = record(event.item);
    if (item) {
      this.addId(item.id);
      if (event.type === 'response.output_item.done' && typeof item.id === 'string') this.completedItemIds.add(item.id);
    }
    if (event.type === 'response.completed' && response?.status === 'completed' && idSchema.safeParse(response.id).success && Array.isArray(response.output)) this.terminal = 'COMPLETED';
    else if (event.type === 'response.completed') this.malformed = true;
    if (event.type === 'response.failed' || event.type === 'response.incomplete' || event.type === 'error') this.terminal = 'FAILED_KNOWN';
  }

  private observeResponse(value: unknown): void {
    const response = record(value);
    if (!response) return;
    this.addId(response.id);
    if (Array.isArray(response.output)) {
      for (const item of response.output) this.addId(record(item)?.id);
    }
    const usage = record(response.usage);
    if (usage) {
      this.usage = {
        inputTokens: token(usage.input_tokens), outputTokens: token(usage.output_tokens),
        cachedTokens: token(record(usage.input_tokens_details)?.cached_tokens),
        reasoningTokens: token(record(usage.output_tokens_details)?.reasoning_tokens),
      };
    }
    if (!this.streaming && response.status === 'completed' && idSchema.safeParse(response.id).success && Array.isArray(response.output)) this.terminal = 'COMPLETED';
    if (!this.streaming && (response.status === 'failed' || response.status === 'incomplete' || response.status === 'cancelled')) this.terminal = 'FAILED_KNOWN';
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function token(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
