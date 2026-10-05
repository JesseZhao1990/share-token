import { timingSafeEqual, X509Certificate } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { Readable } from 'node:stream';
import { checkServerIdentity, type ConnectionOptions, type PeerCertificate, type TLSSocket } from 'node:tls';
import { ShareError } from '../protocol/index.js';

/** Public connection data. It must never contain a private key or device credential. */
export interface HubTrustProfile { version: 1; hubUrl: string; certificatePem: string; label?: string }
export interface ValidatedHubTrustProfile extends HubTrustProfile { fingerprint256: string }

function invalid(message: string): never { throw new ShareError('SHARE_HUB_TRUST_INVALID', message); }

/** Only canonical RFC 1918 IPv4 origins are eligible for this narrowly scoped trust mechanism. */
export function validateHubTrustProfile(input: unknown): ValidatedHubTrustProfile {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid('Hub 连接文件格式无效。');
  const value = input as Record<string, unknown>;
  if (value.version !== 1 || typeof value.hubUrl !== 'string' || typeof value.certificatePem !== 'string') invalid('Hub 连接文件版本或字段无效。');
  const match = /^https:\/\/((?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3})(?::([1-9]\d{0,4}))?\/?$/.exec(value.hubUrl);
  if (!match) invalid('证书连接文件仅支持内网 IPv4 的 HTTPS 根地址。');
  const ip = match[1]!; const octets = ip.split('.').map(Number);
  if (octets.some(part => part > 255) || !(octets[0] === 10 || octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31 || octets[0] === 192 && octets[1] === 168)
    || match[2] && Number(match[2]) > 65535) invalid('证书连接文件需要规范的内网 IPv4 地址和有效端口。');
  if (value.label !== undefined && (typeof value.label !== 'string' || value.label.length > 80 || /[\u0000-\u001f\u007f]/.test(value.label))) invalid('Hub 标签格式无效。');
  if (value.certificatePem.length > 16384) invalid('Hub 证书文件过大。');
  const pem = value.certificatePem.trim();
  const block = /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END CERTIFICATE-----$/.exec(pem);
  if (!block) invalid('连接文件必须仅包含一张公开证书，不能包含证书链或私钥。');
  let certificate: X509Certificate;
  try { certificate = new X509Certificate(pem); } catch { invalid('Hub X.509 证书无效。'); }
  const der = Buffer.from(block[1]!.replace(/[\r\n]/g, ''), 'base64');
  if (!der.equals(certificate.raw)) invalid('Hub 证书编码无效。');
  const now = Date.now();
  if (!Number.isFinite(Date.parse(certificate.validFrom)) || !Number.isFinite(Date.parse(certificate.validTo))
    || now < Date.parse(certificate.validFrom) || now >= Date.parse(certificate.validTo)) invalid('Hub 证书已过期或尚未生效。');
  if (certificate.ca || !certificate.verify(certificate.publicKey) || certificate.issuer !== certificate.subject) invalid('连接文件需要专用于此 Hub 的自签服务器证书，不能使用 CA 证书。');
  if (certificate.checkIP(ip) !== ip) invalid('Hub 证书 IP SAN 与连接地址不匹配。');
  if (!certificate.keyUsage?.includes('1.3.6.1.5.5.7.3.1')) invalid('Hub 证书必须允许 TLS 服务器认证。');
  if (!validKeyUsage(certificate.raw)) invalid('Hub 证书的密钥用途必须允许数字签名，不能签发其他证书。');
  return { version: 1, hubUrl: new URL(value.hubUrl).origin, certificatePem: certificate.toString(),
    ...(value.label === undefined ? {} : { label: value.label as string }), fingerprint256: certificate.fingerprint256 };
}

/** Reusable TLS options for the HTTPS data plane and WSS relay, with an exact leaf pin. */
export function hubTlsOptions(input: HubTrustProfile): Pick<ConnectionOptions, 'ca' | 'rejectUnauthorized' | 'minVersion' | 'checkServerIdentity'> {
  const profile = validateHubTrustProfile(input);
  const raw = new X509Certificate(profile.certificatePem).raw;
  const ip = new URL(profile.hubUrl).hostname;
  return { ca: profile.certificatePem, rejectUnauthorized: true, minVersion: 'TLSv1.2', checkServerIdentity(host, peer) {
    if (host !== ip) return new Error('Hub TLS origin mismatch');
    const error = checkServerIdentity(host, peer);
    if (error) return error;
    return checkPeerPin(peer, raw);
  } };
}

function checkPeerPin(peer: PeerCertificate, raw: Buffer): Error | undefined {
  if (!peer.raw || peer.raw.byteLength !== raw.byteLength || !timingSafeEqual(peer.raw, raw)) return new Error('Hub TLS certificate pin mismatch');
  return undefined;
}

/** A minimal fetch transport scoped to one Hub. It never changes global trust or follows redirects. */
export function createHubFetch(input: HubTrustProfile): typeof fetch {
  const profile = validateHubTrustProfile(input);
  const raw = new X509Certificate(profile.certificatePem).raw;
  return (async (target: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    if (target instanceof Request) throw new TypeError('Pinned Hub fetch requires a URL and explicit request options');
    let url: URL;
    try { url = new URL(target); } catch { throw new TypeError('Invalid Hub request URL'); }
    if (url.origin !== profile.hubUrl || url.username || url.password || url.hash || url.protocol !== 'https:') throw new TypeError('Pinned Hub request cannot leave its configured origin');
    const tls = hubTlsOptions(profile);
    const headers = new Headers(init.headers);
    if (headers.has('host') || headers.has('connection') || headers.has('transfer-encoding') || headers.has('upgrade')) throw new TypeError('Unsupported Hub transport header');
    const method = (init.method ?? 'GET').toUpperCase();
    if (!/^[A-Z]+$/.test(method)) throw new TypeError('Invalid Hub request method');
    let body: Buffer | undefined;
    if (init.body !== undefined && init.body !== null) {
      if (typeof init.body === 'string') body = Buffer.from(init.body);
      else if (init.body instanceof Uint8Array) body = Buffer.from(init.body);
      else throw new TypeError('Pinned Hub fetch supports only string or byte request bodies');
      if (method === 'GET' || method === 'HEAD') throw new TypeError('GET and HEAD requests cannot have a body');
      if (headers.has('content-length') && headers.get('content-length') !== String(body.byteLength)) throw new TypeError('Hub request content length mismatch');
      headers.set('content-length', String(body.byteLength));
    } else if (headers.has('content-length') && headers.get('content-length') !== '0') throw new TypeError('Hub request content length mismatch');
    const requestHeaders: Record<string, string> = {}; headers.forEach((value, name) => { requestHeaders[name] = value; });
    init.signal?.throwIfAborted();
    return new Promise<Response>((resolve, reject) => {
      let incoming: import('node:http').IncomingMessage | undefined;
      const abort = () => { const error = new DOMException('The Hub request was aborted', 'AbortError'); request.destroy(error); incoming?.destroy(error); };
      const cleanup = () => init.signal?.removeEventListener('abort', abort);
      const request = httpsRequest(url, { ...tls, agent: false, method, headers: requestHeaders }, response => {
        incoming = response;
        const socket = response.socket as TLSSocket;
        const pinError = checkPeerPin(socket.getPeerCertificate(), raw);
        if (!socket.authorized || pinError) { response.destroy(); request.destroy(); cleanup(); reject(pinError ?? new Error('Hub TLS connection is unauthorized')); return; }
        const responseHeaders = new Headers();
        for (let i = 0; i < response.rawHeaders.length; i += 2) responseHeaders.append(response.rawHeaders[i]!, response.rawHeaders[i + 1]!);
        const status = response.statusCode ?? 502;
        if (status < 200 || status > 599) { response.destroy(); request.destroy(); cleanup(); reject(new Error('Invalid Hub HTTP status')); return; }
        response.once('close', cleanup);
        const stream = method === 'HEAD' || [204, 205, 304].includes(status) ? null
          : Readable.toWeb(response, { strategy: { highWaterMark: 64 * 1024, size: chunk => (chunk as Uint8Array).byteLength } }) as ReadableStream<Uint8Array>;
        if (!stream) response.resume();
        const result = new Response(stream, { status, statusText: response.statusMessage, headers: responseHeaders });
        Object.defineProperty(result, 'url', { value: url.href });
        resolve(result);
      });
      request.on('error', error => { cleanup(); reject(error); });
      request.on('close', () => { if (!incoming) cleanup(); });
      init.signal?.addEventListener('abort', abort, { once: true });
      if (init.signal?.aborted) { abort(); return; }
      request.end(body);
    });
  }) as typeof fetch;
}

// Node exposes extended key usage, but not the keyUsage bits. Read only that DER extension.
function validKeyUsage(der: Buffer): boolean {
  type Part = { tag: number; start: number; end: number };
  const part = (offset: number, limit: number): Part => {
    const tag = der[offset++]; let length = der[offset++];
    if (tag === undefined || length === undefined) throw new Error('Truncated DER');
    if (length & 0x80) { const count = length & 0x7f; if (!count || count > 4 || offset + count > limit) throw new Error('Invalid DER length'); length = 0; for (let i = 0; i < count; i++) length = length * 256 + der[offset++]!; }
    if (offset + length > limit) throw new Error('Truncated DER value');
    return { tag, start: offset, end: offset + length };
  };
  const children = (value: Part): Part[] => { const values: Part[] = []; for (let offset = value.start; offset < value.end;) { const next = part(offset, value.end); values.push(next); offset = next.end; } return values; };
  try {
    const outer = part(0, der.length); const tbs = children(outer)[0]!;
    const extensionContainer = children(tbs).find(value => value.tag === 0xa3);
    if (!extensionContainer) return false;
    const extensions = children(children(extensionContainer)[0]!);
    const constraints = extensions.find(extension => { const oid = children(extension)[0]!; return oid.tag === 6 && der.subarray(oid.start, oid.end).equals(Buffer.from([0x55, 0x1d, 0x13])); });
    if (!constraints) return false;
    const constraintsEncoded = children(constraints).at(-1)!;
    if (constraintsEncoded.tag !== 4) return false;
    const constraintSequence = part(constraintsEncoded.start, constraintsEncoded.end);
    if (constraintSequence.tag !== 0x30 || constraintSequence.end !== constraintsEncoded.end) return false;
    const constraintValues = children(constraintSequence);
    if (constraintValues.length && (constraintValues.length !== 1 || constraintValues[0]!.tag !== 1 || constraintValues[0]!.end - constraintValues[0]!.start !== 1 || der[constraintValues[0]!.start] !== 0)) return false;
    const keyUsage = extensions.find(extension => { const oid = children(extension)[0]!; return oid.tag === 6 && der.subarray(oid.start, oid.end).equals(Buffer.from([0x55, 0x1d, 0x0f])); });
    if (!keyUsage) return false;
    const encoded = children(keyUsage).at(-1)!;
    if (encoded.tag !== 4) return false;
    const bits = part(encoded.start, encoded.end);
    if (bits.tag !== 3 || bits.end !== encoded.end || bits.end - bits.start < 2 || der[bits.start]! > 7) return false;
    const firstByte = der[bits.start + 1]!;
    return (firstByte & 0x80) !== 0 && (firstByte & 0x06) === 0;
  } catch { return false; }
}
