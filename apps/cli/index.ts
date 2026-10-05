#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { resolve, join, dirname } from 'node:path';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { z } from 'zod';
import { createHub } from '../hub/index.js';
import { createRelay, resolveRelayUnknown } from '../relay/index.js';
import { MockAdapter, HttpAdapter, SubscriptionAdapter, CodexSubscriptionAccount, assertExperimentalSubscriptionEnabled } from '../../packages/upstream/index.js';
import { policySchema, quotaSchema, ShareError, type Member, type Source, type Grant } from '../../packages/protocol/index.js';
import { randomToken, assertSafeUrl, safeError } from '../../packages/protocol/security.js';
import { generateProfile, codexOverrides } from './profile.js';
import { readSecret, writePrivate } from './files.js';
import { readPrivateSharedCodeFile, saveSharedCodeVerifier } from '../../packages/storage/shared-code.js';

const help = `Share Token · 自建模拟推理网关\n\n需要 Node.js 24 LTS。\n\n命令：\n  init [--data-dir DIR]                         创建本地管理员凭据\n  hub [--data-dir DIR] [--host HOST] [--port N]  启动 Hub\n  shared-code set [--data-dir DIR] [--code-file FILE]     设置 8 位配对码（默认读取标准输入）\n  shared-code rotate [--data-dir DIR] [--code-file FILE]  更新配对码，已连接设备不受影响\n  relay --config FILE                          启动本地中继\n  resolve-unknown --config FILE --acknowledge-risk  核实后解除本机 UNKNOWN 冻结\n  demo [--port N] [--data-dir DIR]              一次启动隔离的模拟 Hub + Relay\n  profile --base-url URL --model ID --out FILE  生成独立 Codex 配置，不包含凭据\n  run --base-url URL --model ID --token-file FILE [--cwd DIR]  启动原生 Codex\n  run --profile NAME --token-file FILE         使用已安装的 Codex profile\n\n  subscription-login --codex-home DIR [--codex-binary FILE]  独立登录 Codex 订阅\n  subscription-status --codex-home DIR         查看订阅状态、模型和额度\n  subscription-logout --codex-home DIR         退出独立订阅登录\n\n默认仅开放模拟模型。订阅命令属于默认关闭的实验适配，必须显式设置 SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION=1；技术开关不代表获得上游授权。参见 docs/EXPERIMENTAL_SUBSCRIPTION.md。\n`;

const relayConfigSchema = z.object({
  hubUrl: z.string(), tokenFile: z.string(), sourceId: z.string().min(1), nodeId: z.string().min(1),
  dbPath: z.string(), policy: policySchema,
  adapter: z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('mock'), accountBinding: z.string(), models: z.array(z.string()).min(1), text: z.string().optional() }).strict(),
    z.object({ kind: z.literal('api_fixture'), accountBinding: z.string(), models: z.array(z.string()).min(1), baseUrl: z.string(), apiKeyEnv: z.string(), quotaFile: z.string() }).strict(),
    z.object({ kind: z.literal('subscription'), codexHome: z.string().min(1), binary: z.string().min(1).optional(), accountBinding: z.string().min(1), models: z.array(z.string().min(1)).min(1).max(32) }).strict(),
  ]),
}).strict();

function staticDir(): string {
  const compiled = fileURLToPath(new URL('../../web', import.meta.url));
  return existsSync(join(compiled, 'index.html')) ? compiled : resolve('dist/web');
}

async function main() {
  const { positionals, values } = parseArgs({ allowPositionals: true, options: {
    'data-dir': { type: 'string' }, host: { type: 'string' }, port: { type: 'string' },
    config: { type: 'string' }, 'base-url': { type: 'string' }, model: { type: 'string' }, out: { type: 'string' }, 'code-file': { type: 'string' },
    'codex-home': { type: 'string' }, 'codex-binary': { type: 'string' },
    profile: { type: 'string' }, 'token-file': { type: 'string' }, cwd: { type: 'string' }, help: { type: 'boolean', short: 'h' }, 'acknowledge-risk': { type: 'boolean' },
  } });
  const command = positionals[0];
  if (values.help || !command) { process.stdout.write(help); return; }
  if (positionals.length > (command === 'shared-code' ? 2 : 1)) throw new ShareError('SHARE_ARGS_INVALID', '命令格式无效，请使用 --help。');
  const dataDir = resolve(values['data-dir'] ?? '.share-token');
  const port = Number(values.port ?? '4387');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new ShareError('SHARE_ARGS_INVALID', '端口必须为 0–65535 整数。');
  const need = (name: keyof typeof values): string => { const value = values[name]; if (typeof value !== 'string' || !value) throw new ShareError('SHARE_ARGS_INVALID', `缺少 --${name}`); return value; };
  if (command === 'shared-code') {
    const action = positionals[1];
    if (action !== 'set' && action !== 'rotate') throw new ShareError('SHARE_ARGS_INVALID', '请使用 shared-code set 或 shared-code rotate，并通过标准输入或 --code-file 传入配对码。');
    let code: string;
    if (values['code-file']) code = await readPrivateSharedCodeFile(resolve(values['code-file']));
    else {
      if (process.stdin.isTTY) throw new ShareError('SHARE_ARGS_INVALID', '请通过管道标准输入或权限为 0600 的 --code-file 文件传入 8 位配对码；不要把配对码写入命令参数。');
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of process.stdin) { const data = Buffer.from(chunk); size += data.length; if (size > 128) throw new ShareError('SHARE_SHARED_CODE_INVALID', '配对码需要 8 位数字。'); chunks.push(data); }
      code = Buffer.concat(chunks).toString('utf8');
    }
    await saveSharedCodeVerifier(join(dataDir, 'shared-code.json'), code, action === 'rotate');
    process.stdout.write(`配对码已${action === 'rotate' ? '更新' : '设置'}，只保存了校验摘要。新连接立即生效，已连接设备保持连接。\n`);
    return;
  }
  if (['subscription-login', 'subscription-status', 'subscription-logout'].includes(command)) {
    assertExperimentalSubscriptionEnabled();
    const account = new CodexSubscriptionAccount({ codexHome: resolve(need('codex-home')), binary: values['codex-binary'] });
    const stopped = new AbortController();
    installShutdown(async () => { stopped.abort(); await account.close(); });
    try {
      if (command === 'subscription-logout') { await account.logout(); process.stdout.write('已退出本应用独立的 Codex 订阅登录。\n'); return; }
      if (command === 'subscription-status') { process.stdout.write(JSON.stringify(await account.inspect(), null, 2) + '\n'); return; }
      const initial = await account.inspect();
      if (initial.authenticated) { process.stdout.write(JSON.stringify(initial, null, 2) + '\n'); return; }
      const login = await account.startLogin();
      process.stdout.write(`请在浏览器打开官方登录地址：\n${login.authUrl}\n登录只写入指定的独立目录，不会启动共享或推理。\n`);
      const deadline = Date.now() + 10 * 60_000;
      while (!stopped.signal.aborted && Date.now() < deadline) {
        const status = await account.inspect();
        if (status.authenticated) { process.stdout.write(JSON.stringify(status, null, 2) + '\n'); return; }
        await new Promise<void>(resolveWait => setTimeout(resolveWait, 1500));
      }
      await account.cancelLogin();
      if (!stopped.signal.aborted) throw new ShareError('SHARE_LOGIN_TIMEOUT', '登录等待超时，请重新开始登录。', 408);
    } finally { await account.close(); }
    return;
  }
  if (command === 'init') {
    await writePrivate(join(dataDir, 'admin.token'), randomToken('st_admin') + '\n');
    process.stdout.write(`管理员凭据已保存到 ${join(dataDir, 'admin.token')}（0600）。\n运行 npm run cli -- hub 启动。\n`);
    return;
  }
  if (command === 'profile') {
    const out = resolve(need('out'));
    await writePrivate(out, generateProfile(need('base-url'), need('model')));
    process.stdout.write(`配置已写入 ${out}。没有修改原有 Codex 配置。\n`);
    return;
  }
  if (command === 'run') {
    const profile = values.profile;
    if (profile && (!/^[a-zA-Z0-9_-]+$/.test(profile) || values['base-url'] || values.model)) throw new ShareError('SHARE_ARGS_INVALID', '已有 profile 与直接指定入口互斥，名称只能包含字母、数字、下划线或连字符。');
    const args = profile ? ['--profile', profile, '-c', 'shell_environment_policy.filters.SHARE_TOKEN_ACCESS_KEY="exclude"']
      : codexOverrides(need('base-url'), need('model')).flatMap(value => ['-c', value]);
    const token = await readSecret(resolve(need('token-file')));
    const child = spawn('codex', args, {
      cwd: values.cwd ? resolve(values.cwd) : process.cwd(), stdio: 'inherit', env: { ...process.env, SHARE_TOKEN_ACCESS_KEY: token },
    });
    child.once('error', () => { process.stderr.write('无法启动 Codex，请确认 CLI 已安装。\n'); process.exitCode = 1; });
    child.once('exit', (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0); });
    return;
  }
  if (command === 'hub') {
    const hub = await createHub({ dbPath: join(dataDir, 'hub.sqlite'), adminToken: await readSecret(join(dataDir, 'admin.token')),
      host: values.host ?? '127.0.0.1', port, staticDir: staticDir(), sharedCodePath: join(dataDir, 'shared-code.json') });
    process.stdout.write(`Share Token Hub: ${hub.url}\n管理凭据文件：${join(dataDir, 'admin.token')}\n`);
    installShutdown(() => hub.close()); return;
  }
  if (command === 'relay' || command === 'resolve-unknown') {
    const configFile = resolve(need('config'));
    const config = relayConfigSchema.parse(JSON.parse(await readFile(configFile, 'utf8')));
    const relative = (path: string) => resolve(dirname(configFile), path);
    if (command === 'resolve-unknown') {
      const result = resolveRelayUnknown(relative(config.dbPath), values['acknowledge-risk'] === true);
      process.stdout.write(`已记录 ${result.acknowledged} 条 UNKNOWN 人工确认。\n${result.warning}\n`);
      return;
    }
    assertSafeUrl(config.hubUrl);
    const subscription = config.adapter.kind === 'subscription'
      ? new CodexSubscriptionAccount({ codexHome: relative(config.adapter.codexHome), binary: config.adapter.binary }) : null;
    const adapter = config.adapter.kind === 'mock' ? new MockAdapter(config.adapter)
      : config.adapter.kind === 'subscription' ? new SubscriptionAdapter({ account: subscription!, models: config.adapter.models, accountBinding: config.adapter.accountBinding })
      : new HttpAdapter({ ...config.adapter,
        quotaReader: { read: async () => quotaSchema.parse(JSON.parse(await readFile(relative(config.adapter.kind === 'api_fixture' ? config.adapter.quotaFile : ''), 'utf8'))) },
      });
    let relay: Awaited<ReturnType<typeof createRelay>> | undefined;
    try {
      relay = await createRelay({ hubUrl: config.hubUrl, token: await readSecret(relative(config.tokenFile)),
        sourceId: config.sourceId, nodeId: config.nodeId, dbPath: relative(config.dbPath), policy: config.policy, adapter });
      await relay.waitUntilReady();
    } catch (error) { await relay?.close(); await subscription?.close(); throw error; }
    process.stdout.write(`Relay 已连接：${config.nodeId}，通道 ${config.adapter.kind}\n`);
    installShutdown(async () => { await relay?.close(); await subscription?.close(); }); return;
  }
  if (command === 'demo') {
    await mkdir(dataDir, { recursive: true, mode: 0o700 });
    const demoDir = await mkdtemp(join(dataDir, 'demo-'));
    const token = randomToken('st_demo_admin');
    await writePrivate(join(demoDir, 'admin.token'), token + '\n');
    const hub = await createHub({ dbPath: join(demoDir, 'hub.sqlite'), adminToken: token, host: '127.0.0.1', port, staticDir: staticDir() });
    let relay: Awaited<ReturnType<typeof createRelay>> | undefined;
    try {
      const api = async <T>(path: string, body?: unknown): Promise<T> => {
        const response = await fetch(hub.url + path, { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
        if (!response.ok) throw new ShareError('SHARE_DEMO_SETUP', `模拟环境初始化失败（HTTP ${response.status}）。`);
        return response.json() as Promise<T>;
      };
      const { member } = await api<{ member: Member }>('/control/session');
      const policy = policySchema.parse({ allowedMemberIds: [member.id], models: ['mock-codex'] });
      const { source, relayToken } = await api<{ source: Source; relayToken: string }>('/control/sources', { name: '本机模拟来源', kind: 'mock', accountBinding: 'mock:local', policy });
      const { grant, token: accessToken } = await api<{ grant: Grant; token: string }>('/control/grants', { sourceId: source.id, label: '本机 Codex 验证', models: ['mock-codex'] });
      await writePrivate(join(demoDir, 'consumer.token'), accessToken + '\n');
      await writePrivate(join(demoDir, 'relay.token'), relayToken + '\n');
      await writePrivate(join(demoDir, 'friends-demo.config.toml'), generateProfile(`${hub.url}/v1`, 'mock-codex'));
      await writePrivate(join(demoDir, 'demo.json'), JSON.stringify({ hubUrl: hub.url, sourceId: source.id, grantId: grant.id, memberId: member.id,
        adminTokenFile: join(demoDir, 'admin.token'), consumerTokenFile: join(demoDir, 'consumer.token') }, null, 2));
      await writePrivate(join(demoDir, 'relay.json'), JSON.stringify({ hubUrl: hub.url, tokenFile: 'relay.token', sourceId: source.id, nodeId: 'local-demo',
        dbPath: 'relay.sqlite', policy, adapter: { kind: 'mock', accountBinding: 'mock:local', models: ['mock-codex'], text: '共享转发链路已连通。这是模拟模型响应，不消耗个人订阅额度。' } }, null, 2));
      relay = await createRelay({ hubUrl: hub.url, token: relayToken, sourceId: source.id, nodeId: 'local-demo', dbPath: join(demoDir, 'relay.sqlite'), policy,
        adapter: new MockAdapter({ accountBinding: 'mock:local', models: ['mock-codex'], text: '共享转发链路已连通。这是模拟模型响应，不消耗个人订阅额度。' }) });
      await relay.waitUntilReady();
      process.stdout.write(`模拟环境已启动：${hub.url}\n通道：mock（不是个人订阅）\n管理凭据：${join(demoDir, 'admin.token')}\n接入配置：${join(demoDir, 'friends-demo.config.toml')}\n环境信息：${join(demoDir, 'demo.json')}\n`);
      installShutdown(async () => { await relay?.close(); await hub.close(); });
    } catch (error) { await relay?.close(); await hub.close(); throw error; }
    return;
  }
  throw new ShareError('SHARE_ARGS_INVALID', `未知命令：${command}`);
}

function installShutdown(close: () => Promise<void> | void) {
  let closing = false;
  const stop = () => { if (closing) return; closing = true; Promise.resolve(close()).catch(() => { process.exitCode = 1; }); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
}

main().catch(error => {
  if (error instanceof z.ZodError) process.stderr.write('配置不符合 schema，请检查字段、模型与额度规则。\n');
  else if (error && typeof error === 'object' && 'code' in error && error.code === 'EEXIST') process.stderr.write('目标文件已存在，未覆盖原有内容。\n');
  else process.stderr.write(`${safeError(error).message}\n`);
  process.exitCode = 1;
});
