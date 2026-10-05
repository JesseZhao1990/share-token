import { z } from 'zod';

export const PROTOCOL_VERSION = 1;
export const MAX_BODY_BYTES = 8 * 1024 * 1024;
export const CHUNK_BYTES = 32 * 1024;
export const MAX_BUFFER_BYTES = 1024 * 1024;
export const idSchema = z.string().min(1).max(128).regex(/^[a-zA-Z0-9_.:-]+$/);
export const adapterKindSchema = z.enum(['mock', 'api_fixture', 'subscription']);
export type AdapterKind = z.infer<typeof adapterKindSchema>;
export const capabilitiesSchema = z.object({
  kind: adapterKindSchema,
  verified: z.boolean(),
  accountBinding: z.string().min(1).max(256),
  models: z.array(z.string().min(1).max(128)).min(1).max(32),
  responses: z.boolean(), compact: z.boolean(),
}).strict();
export type Capabilities = z.infer<typeof capabilitiesSchema>;
export const quotaSchema = z.object({
  fetchedAt: z.number().int().nonnegative(),
  status: z.enum(['available', 'unknown']),
  origin: z.enum(['mock', 'codex', 'fixture', 'unknown']),
  windows: z.array(z.object({
    limitId: z.string().min(1).max(128),
    usedPercent: z.number().min(0).max(100),
    windowDurationMins: z.number().positive(),
    resetsAt: z.number().int().nonnegative().nullable(),
  }).strict()).max(32),
}).strict();
export type QuotaSnapshot = z.infer<typeof quotaSchema>;
export const policySchema = z.object({
  allowedMemberIds: z.array(idSchema).max(100).default([]),
  models: z.array(z.string().min(1).max(128)).min(1).max(32),
  reservePercent: z.number().min(0).max(95).default(20),
  startMarginPercent: z.number().min(0).max(50).default(5),
  quotaMaxAgeMs: z.number().int().min(1000).max(600000).default(120000),
  maxRequestMs: z.number().int().min(1000).max(900000).default(900000),
  maxBodyBytes: z.number().int().min(1024).max(MAX_BODY_BYTES).default(MAX_BODY_BYTES),
  enabled: z.boolean().default(true),
  expiresAt: z.number().int().positive().nullable().default(null),
  schedule: z.object({
    timeZone: z.string().min(1).max(64),
    days: z.array(z.number().int().min(0).max(6)).min(1).max(7),
    start: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/),
    end: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/),
  }).strict().nullable().default(null),
}).strict();
export type SharePolicy = z.infer<typeof policySchema>;
export const usageSchema = z.object({
  inputTokens: z.number().int().nonnegative().nullable(),
  outputTokens: z.number().int().nonnegative().nullable(),
  cachedTokens: z.number().int().nonnegative().nullable(),
  reasoningTokens: z.number().int().nonnegative().nullable(),
}).strict();
export type Usage = z.infer<typeof usageSchema>;
export const EMPTY_USAGE: Usage = { inputTokens: null, outputTokens: null, cachedTokens: null, reasoningTokens: null };
export const terminalSchema = z.enum(['COMPLETED', 'FAILED_KNOWN', 'CANCELLED_NOT_SENT', 'UNKNOWN']);
export type Terminal = z.infer<typeof terminalSchema>;
export type RequestState = 'QUEUED' | 'RESERVED' | 'DISPATCHED' | 'ACCEPTED' | 'UPSTREAM_STARTED' | 'STREAMING' | Terminal;
export const operationSchema = z.enum(['responses', 'compact']);
export type Operation = z.infer<typeof operationSchema>;
const base = { v: z.literal(1) };
const requestBase = { ...base, requestId: idSchema, fence: z.number().int().positive() };

export const hubFrameSchema = z.discriminatedUnion('type', [
  z.object({ ...base, type: z.literal('welcome'), fence: z.number().int().positive(), sourceId: idSchema }).strict(),
  z.object({ ...requestBase, type: z.literal('request.open'), sourceId: idSchema, grantId: idSchema,
    memberId: idSchema, operation: operationSchema, model: z.string().min(1).max(128),
    body: z.string().max(Math.ceil(MAX_BODY_BYTES / 3) * 4), deadline: z.number().int().positive(),
  }).strict(),
  z.object({ ...requestBase, type: z.literal('window.update'), bytes: z.number().int().positive().max(MAX_BUFFER_BYTES) }).strict(),
  z.object({ ...requestBase, type: z.literal('cancel.request'), reason: z.string().max(128) }).strict(),
  z.object({ ...requestBase, type: z.literal('status.query') }).strict(),
]);
export type HubFrame = z.infer<typeof hubFrameSchema>;
export const relayFrameSchema = z.discriminatedUnion('type', [
  z.object({ ...base, type: z.literal('hello'), nodeId: idSchema, sourceId: idSchema,
    capabilities: capabilitiesSchema, quota: quotaSchema }).strict(),
  z.object({ ...base, type: z.literal('heartbeat'), fence: z.number().int().positive(), quota: quotaSchema, paused: z.boolean() }).strict(),
  z.object({ ...requestBase, type: z.literal('request.accepted') }).strict(),
  z.object({ ...requestBase, type: z.literal('attempt.started') }).strict(),
  z.object({ ...requestBase, type: z.literal('response.head'), status: z.number().int().min(100).max(599),
    headers: z.record(z.string().max(100), z.string().max(8192)) }).strict(),
  z.object({ ...requestBase, type: z.literal('response.chunk'), seq: z.number().int().nonnegative(),
    data: z.string().max(Math.ceil(CHUNK_BYTES / 3) * 4 + 4) }).strict(),
  z.object({ ...requestBase, type: z.literal('response.end'), state: terminalSchema,
    usage: usageSchema, responseIds: z.array(idSchema).max(512).default([]), errorCode: z.string().max(100).nullable().default(null) }).strict(),
  z.object({ ...requestBase, type: z.literal('status.result'), state: z.enum(['NOT_FOUND', 'ACCEPTED', 'UPSTREAM_STARTED', 'STREAMING', 'COMPLETED', 'FAILED_KNOWN', 'CANCELLED_NOT_SENT', 'UNKNOWN']),
    usage: usageSchema, responseIds: z.array(idSchema).max(512).default([]) }).strict(),
]);
export type RelayFrame = z.infer<typeof relayFrameSchema>;

export interface Member { id: string; name: string; role: 'admin' | 'member'; active: boolean; createdAt: number }
export interface Source { id: string; name: string; ownerId: string; kind: AdapterKind; accountBinding: string;
  policy: SharePolicy; paused: boolean; frozen: boolean; fence: number; quota: QuotaSnapshot | null;
  capabilities: Capabilities | null; online: boolean; lastSeen: number | null; createdAt: number }
export interface Grant { id: string; memberId: string; sourceId: string; label: string; models: string[];
  revoked: boolean; frozen: boolean; expiresAt: number | null; createdAt: number }
export interface RequestRecord { id: string; grantId: string; memberId: string; sourceId: string; model: string; operation: Operation;
  state: RequestState; fence: number; createdAt: number; startedAt: number | null; finishedAt: number | null;
  delivery: 'pending' | 'streaming' | 'transport_finished' | 'lost' | 'unknown'; cancelRequested: boolean;
  errorCode: string | null; usage: Usage }
export interface Dashboard { member: Member; sources: Source[]; grants: Grant[]; requests: RequestRecord[]; members: Member[];
  stats: { completed: number; unknown: number; inputTokens: number; outputTokens: number } }

export class ShareError extends Error {
  constructor(public code: string, message: string, public status = 400) { super(message); this.name = 'ShareError'; }
}
export const isTerminal = (state: string): state is Terminal => terminalSchema.safeParse(state).success;
