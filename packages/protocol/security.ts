import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { ShareError } from './index.js';

export const randomToken = (prefix = 'st'): string => `${prefix}_${randomBytes(32).toString('base64url')}`;
export const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex');
export function equalToken(a: string, b: string): boolean { return timingSafeEqual(Buffer.from(hashToken(a)), Buffer.from(hashToken(b))); }
export function safeError(error: unknown): { code: string; message: string; status: number } {
  return error instanceof ShareError ? { code: error.code, message: error.message, status: error.status }
    : { code: 'SHARE_INTERNAL_ERROR', message: '服务暂时无法完成请求，请通过请求编号检查状态。', status: 500 };
}
export function assertSafeUrl(input: string, allowLoopback = true): URL {
  let url: URL;
  try { url = new URL(input); } catch { throw new ShareError('SHARE_URL_INVALID', '服务地址不是有效 URL。'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.hash || url.search || !['https:', 'wss:', ...(allowLoopback && loopback ? ['http:', 'ws:'] : [])].includes(url.protocol)) {
    throw new ShareError('SHARE_URL_INVALID', '远程连接必须使用 HTTPS/WSS，URL 不得包含凭据或查询参数。');
  }
  return url;
}
