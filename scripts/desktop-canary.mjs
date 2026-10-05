import { _electron as electron } from 'playwright';
import { access, mkdtemp, mkdir, rm, writeFile, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHub } from '../dist/apps/hub/index.js';
import { WorkerProcess } from '../dist/apps/desktop/main/worker.js';
// This verification always exercises the public default, even if the caller enabled experiments.
delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
const root = process.cwd();
const packaged = process.argv[2] ? resolve(process.argv[2]) : null;
const expectedVersion = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
const screenshotName = name => `${name}${packaged ? '-packaged' : ''}.png`;
const sha256 = value => createHash('sha256').update(value).digest('hex');
async function verifyBundle(appPath) {
  assert.equal(appPath, resolve(dirname(packaged), '../Resources/app'));
  const metadata = JSON.parse(await readFile(join(appPath, 'package.json'), 'utf8'));
  assert.equal(metadata.version, expectedVersion);
  assert.equal(metadata.main, 'dist/apps/desktop/main/index.js');
  const manifest = JSON.parse(await readFile(join(appPath, 'runtime/manifest.json'), 'utf8'));
  const runtimeHash = sha256(await readFile(join(appPath, 'runtime/node')));
  assert.equal(runtimeHash, manifest.sha256, 'Bundled runtime must match its SHA-256 manifest.');
  assert.equal(runtimeHash, sha256(await readFile(join(root, 'node_modules/node/bin/node'))), 'Bundled runtime must match the pinned build runtime.');
  const runtimeVersion = (await promisify(execFile)(join(appPath, 'runtime/node'), ['--version'])).stdout.trim();
  assert.equal(runtimeVersion, manifest.version);
  assert.match(runtimeVersion, /^v24\./);
  assert.equal(manifest.platform, process.platform); assert.equal(manifest.arch, process.arch);
  const assets = [];
  async function compare(relative) {
    const items = await readdir(join(root, 'dist', relative), { withFileTypes: true });
    const packagedItems = await readdir(join(appPath, 'dist', relative), { withFileTypes: true });
    assert.deepEqual(packagedItems.map(item => item.name).sort(), items.map(item => item.name).sort(), `Bundle directory mismatch: ${relative}`);
    for (const item of items) {
      const path = join(relative, item.name);
      if (item.isDirectory()) await compare(path);
      else { assert.ok(item.isFile(), 'Only regular build artifacts are expected.'); const hash = sha256(await readFile(join(root, 'dist', path))); assert.equal(sha256(await readFile(join(appPath, 'dist', path))), hash, `Bundle asset mismatch: ${path}`); assets.push(`${path}:${hash}`); }
    }
  }
  await compare('');
  for (const path of ['node_modules/ws/package.json', 'node_modules/zod/package.json', 'node_modules/node-pty/package.json', 'runtime/Node-LICENSE.txt', 'dist/apps/desktop/preload.cjs']) assert.ok((await readFile(join(appPath, path))).length > 0, `${path} must be packaged`);
  return { packageVersion: metadata.version, runtimeVersion, runtimeSha256: runtimeHash, bundleFilesCompared: assets.length, bundleDistSha256: sha256(assets.sort().join('\n')), channel: manifest.channel };
}
const dir = await mkdtemp(join(tmpdir(), 'share-desktop-canary-'));
await mkdir(join(dir, 'profile')); await mkdir(join(dir, 'codex')); await mkdir(join(dir, 'project'));
const fakeCodex = join(dir, 'synthetic-codex');
const appServerMarker = join(dir, 'unexpected-app-server');
await writeFile(fakeCodex, `#!/usr/bin/env node
if (process.argv.includes('app-server')) { require('node:fs').writeFileSync(${JSON.stringify(appServerMarker)}, 'unexpected'); process.exit(99); }
if (process.argv.includes('--version')) { console.log('codex-cli 0.153.4'); process.exit(0); }
if (!process.stdin.isTTY || !process.stdout.isTTY || !process.env.SHARE_TOKEN_ACCESS_KEY) process.exit(11);
const overrides = process.argv.filter((value, index, args) => args[index - 1] === '-c');
const read = key => JSON.parse(overrides.find(value => value.startsWith(key + '='))?.slice(key.length + 1) ?? 'null');
const base = read('model_providers.friends_share.base_url'), model = read('model');
if (!base || !new URL(base).hostname.match(/^(127\\.0\\.0\\.1|localhost)$/) || model !== 'mock-codex') process.exit(12);
console.log('SYNTHETIC_PTY_READY');
process.stdin.setEncoding('utf8');
process.stdin.on('data', data => { if (data.includes('canary-input')) { console.log('SYNTHETIC_PTY_INPUT_OK'); process.exit(0); } });
(async () => {
  const response = await fetch(base + '/responses', { method: 'POST', headers: { authorization: 'Bearer ' + process.env.SHARE_TOKEN_ACCESS_KEY, 'content-type': 'application/json' }, body: JSON.stringify({ model, stream: true, store: false, input: [] }) });
  const text = await response.text();
  if (response.status !== 200 || !text.includes('Mock fixture') || !text.includes('response.completed')) process.exit(13);
  console.log('MOCK_INFERENCE_VERIFIED');
})().catch(() => process.exit(14));
`, { mode: 0o700 });
const disabledError = { code: 'SHARE_EXPERIMENTAL_SUBSCRIPTION_DISABLED', status: 403 };
const worker = new WorkerProcess(join(root, 'node_modules/node/bin/node'), join(root, 'dist/apps/client-worker/host.js'), 'donor');
try {
  await assert.rejects(worker.request('subscription.init', { binary: fakeCodex, codexHome: join(dir, 'profile/subscription/codex') }), disabledError);
  await assert.rejects(worker.request('subscription.status'), disabledError);
  await assert.rejects(worker.request('subscription.login'), disabledError);
} finally { await worker.close(); }
await assert.rejects(access(appServerMarker), { code: 'ENOENT' });
await assert.rejects(access(join(dir, 'profile/subscription')), { code: 'ENOENT' });
const admin = 'test_' + randomBytes(32).toString('hex');
const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: admin, port: 0 });
const login = await fetch(hub.url + '/control/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({token:admin}) });
const cookie = login.headers.get('set-cookie').split(';')[0]; const {csrfToken} = await login.json();
let app; let window;
try {
  app = await electron.launch({...(packaged ? {executablePath:packaged} : {}),args:[...(packaged ? [] : ['.']), '--user-data-dir='+join(dir,'profile')],env:{...process.env,SHARE_TOKEN_TEST_DATA_DIR:join(dir,'profile'),CODEX_HOME:join(dir,'codex')},timeout:30000});
  await app.evaluate(({shell}) => { globalThis.__shareCanaryExternalOrigins = []; shell.openExternal = async url => { globalThis.__shareCanaryExternalOrigins.push(new URL(url).origin); }; });
  const identity = await app.evaluate(({ app }) => ({ appVersion: app.getVersion(), appPath: app.getAppPath(), isPackaged: app.isPackaged }));
  assert.equal(identity.appVersion, expectedVersion); assert.equal(identity.isPackaged, !!packaged);
  const bundle = packaged ? await verifyBundle(identity.appPath) : null;
  window = await app.firstWindow(); const errors=[];
  window.on('pageerror',error=>errors.push(error.message));
  await mkdir(join(root,'artifacts/desktop-evidence'),{recursive:true});
  await window.getByRole('button',{name:'提供共享',exact:true}).waitFor({timeout:15000});
  await window.getByTestId('open-source-preview-notice').waitFor();
  assert.match(await window.getByTestId('open-source-preview-notice').innerText(), /当前为模拟预览/);
  assert.equal(await window.locator('aside').count(),0,'Startup must choose a purpose before showing operational navigation');
  assert.equal(await window.getByLabel('Hub 地址',{exact:true}).count(),0,'No connection form before purpose selection');
  await window.screenshot({path:join(root,'artifacts/desktop-evidence',screenshotName('welcome'))});
  await window.getByRole('button',{name:'提供共享',exact:true}).click();
  await window.getByText('更多连接方式',{exact:true}).click();
  await window.getByLabel('Hub 地址',{exact:true}).fill(hub.url);
  await window.getByLabel('设备名称',{exact:true}).fill('桌面验收设备');
  await window.getByRole('button',{name:'连接并配对',exact:true}).click();
  await window.locator('.pair-code').waitFor({timeout:15000});
  const userCode=await window.locator('.pair-code').innerText();
  const approved=await fetch(`${hub.url}/control/v2/device-pairings/${userCode}/approve`,{method:'POST',headers:{cookie,'x-csrf-token':csrfToken,'content-type':'application/json'},body:JSON.stringify({approvedScopes:['consumer','donor']})});
  assert.equal(approved.status,200,await approved.text());
  await window.waitForFunction(async () => (await window.shareToken.state()).connected,undefined,{timeout:15000});
  assert.equal(await window.getByRole('navigation').getByRole('button',{name:'使用共享',exact:true}).count(),0,'Donor navigation must not mix consumer workflow');
  await window.getByRole('button',{name:'保存本机规则',exact:true}).waitFor();
  assert.equal(await window.getByRole('button',{name:'选择订阅用 Codex',exact:true}).count(),0,'Default mock must not expose subscription login');
  const defaultState=await window.evaluate(()=>window.shareToken.state());
  assert.equal(defaultState.experimentalSubscriptionEnabled,false);
  assert.equal(defaultState.subscription,null);
  assert.equal(defaultState.subscriptionReady,false);
  for (const method of ['subscriptionLogin','subscriptionStatus','subscriptionLogout']) {
    const message=await window.evaluate(async name=>{try{await window.shareToken[name]();return '';}catch(error){return error.message;}},method);
    assert.match(message,/实验订阅适配默认关闭/);
  }
  const bypassMessage=await window.evaluate(async memberId=>{try{await window.shareToken.saveSharing({name:'Forbidden subscription',kind:'subscription',policy:{models:['gpt-fixture'],allowedMemberIds:[memberId]}});return '';}catch(error){return error.message;}},defaultState.member.id);
  assert.match(bypassMessage,/实验订阅适配默认关闭/);
  assert.equal(hub.store.listSources().length,0);
  await assert.rejects(access(join(dir,'profile/subscription')), {code:'ENOENT'});
  await assert.rejects(access(appServerMarker), {code:'ENOENT'});
  console.log(JSON.stringify({checkpoint:'subscription-default-disabled',workerIpcRejected:true,authenticated:false,appServerStarted:false,credentialRead:false,oauthOpened:false,upstreamInferenceRequests:0}));
  await window.getByRole('navigation').getByRole('button',{name:'设置',exact:true}).click();
  await window.getByText('开发测试设置',{exact:true}).click();
  assert.equal(await window.getByLabel('共享来源类型',{exact:true}).inputValue(),'mock');
  // Check the native option: Playwright disabled-state matching follows its enclosing label to the enabled select.
  assert.equal(await window.getByLabel('共享来源类型',{exact:true}).locator('option[value="subscription"]').evaluate(option=>option.disabled),true);
  await window.screenshot({path:join(root,'artifacts/desktop-evidence',screenshotName('subscription-default-disabled'))});
  await window.getByRole('button',{name:'返回共享设置',exact:true}).click();
  await window.getByRole('button',{name:'保存本机规则',exact:true}).click();
  await window.getByRole('button',{name:'开始分享',exact:true}).waitFor();
  await window.getByRole('button',{name:'开始分享',exact:true}).click();
  await window.waitForFunction(async()=> (await window.shareToken.state()).sharing.status==='sharing',undefined,{timeout:20000});
  const state=await window.evaluate(()=>window.shareToken.state());
  await window.screenshot({path:join(root,'artifacts/desktop-evidence',screenshotName('donor'))});
  await window.getByRole('button',{name:'切换用途',exact:true}).click();
  assert.equal((await window.evaluate(()=>window.shareToken.state())).sharing.status,'sharing','Changing purpose must not stop background sharing');
  await window.getByRole('button',{name:'使用共享',exact:true}).click();
  assert.equal(await window.getByRole('navigation').getByRole('button',{name:'提供共享',exact:true}).count(),0,'Consumer navigation must not mix donor workflow');
  await window.getByLabel('来源',{exact:true}).selectOption(state.sharing.config.sourceId);
  await window.getByRole('button',{name:'下一步：选择项目',exact:true}).click();
  await app.evaluate(({dialog},project)=>{dialog.showOpenDialog=async()=>({canceled:false,filePaths:[project]});},join(dir,'project'));
  await window.getByRole('button',{name:'选择项目目录',exact:true}).click();
  await app.evaluate(({dialog},binary)=>{dialog.showOpenDialog=async()=>({canceled:false,filePaths:[binary]});},fakeCodex);
  await window.getByText('没有找到 Codex 程序？',{exact:true}).click();
  await window.getByRole('button',{name:'手动选择 Codex',exact:true}).click();
  await window.getByRole('button',{name:'下一步：准备启动',exact:true}).click();
  await window.screenshot({path:join(root,'artifacts/desktop-evidence',screenshotName('consumer'))});
  const terminalPromise=app.waitForEvent('window',{timeout:20000});
  await window.getByRole('button',{name:'启动 Codex',exact:true}).click();
  const terminal=await terminalPromise;
  await terminal.locator('.terminal-mount .xterm').waitFor({timeout:10000});
  await terminal.waitForFunction(async()=> (await window.shareToken.terminalAttach()).backlog.includes('MOCK_INFERENCE_VERIFIED'),undefined,{timeout:15000});
  const attachment=await terminal.evaluate(()=>window.shareToken.terminalAttach());
  assert.match(attachment.backlog,/SYNTHETIC_PTY_READY/);
  assert.equal(hub.store.listRequests().length,1,'Only one synthetic Responses request must traverse the mock Relay');
  assert.equal(hub.store.listRequests()[0].model,'mock-codex');
  assert.equal(hub.store.listRequests()[0].state,'COMPLETED');
  await terminal.evaluate(()=>window.shareToken.terminalResize(100,35));
  await terminal.evaluate(()=>window.shareToken.terminalWrite('canary-input\r'));
  await terminal.waitForFunction(async()=> (await window.shareToken.terminalAttach()).backlog.includes('SYNTHETIC_PTY_INPUT_OK'),undefined,{timeout:10000});
  const restricted=await terminal.evaluate(async()=>{try{await window.shareToken.state();return false;}catch{return true;}});assert.equal(restricted,true);
  await terminal.screenshot({path:join(root,'artifacts/desktop-evidence',screenshotName('terminal'))});
  console.log(JSON.stringify({checkpoint:'synthetic-native-terminal',terminalOpened:true,mockInferenceRequests:1,interactiveInput:true,resize:true,realModelRequests:0}));
  await window.evaluate(sessionId=>window.shareToken.stopSession(sessionId),attachment.sessionId);
  await window.getByRole('button',{name:'切换用途',exact:true}).click();
  await window.getByRole('button',{name:'提供共享',exact:true}).click();
  await window.getByRole('button',{name:'暂停接单',exact:true}).click();
  await window.waitForFunction(async()=> !(await window.shareToken.state()).sharing.desiredSharing,undefined,{timeout:15000});
  const paused=await window.evaluate(()=>window.shareToken.state());
  const externalOrigins=await app.evaluate(()=>globalThis.__shareCanaryExternalOrigins);
  assert.deepEqual(externalOrigins,[hub.url],'No OAuth/login or real inference may be exercised');
  const encrypted=await readFile(join(dir,'profile/local-secrets/device.encrypted'));assert.equal(encrypted.includes(Buffer.from('refreshToken')),false);
  const savedSource=paused.sharing.config.sourceId;
  assert.equal(paused.sharing.config.kind,'mock');
  await assert.rejects(access(appServerMarker), {code:'ENOENT'});
  await assert.rejects(access(join(dir,'profile/subscription')), {code:'ENOENT'});
  // Close the owned app through the explicit product action, accepting only our test dialog.
  await app.evaluate(({dialog})=>{dialog.showMessageBox=async()=>({response:1,checkboxChecked:false});});
  const appClosed=app.waitForEvent('close',{timeout:15000});
  await window.evaluate(()=>window.shareToken.quit());
  await appClosed; app=null;
  assert.equal(hub.store.getSource(savedSource).online,false);
  const report={appVersion:identity.appVersion,bundle,time:new Date().toISOString(),packaged:!!packaged,platform:process.platform,arch:process.arch,channel:'default-mock-relay-and-synthetic-native-pty',checks:[...(packaged ? ['package metadata matches appVersion', 'bundled Node SHA-256 and version', 'all bundled dist resources match built artifacts'] : []),'startup purpose selection before connection','role-specific navigation and progressive steps','background sharing persists across purpose switch','actual Electron render','S256 browser-session control approval','locally encrypted credentials','desktop local donor worker + relay online','synthetic CLI in real owned PTY with mock Responses and interactive input','terminal window rejects management IPC','pause sharing','subscription defaults disabled without app-server or credential directory','subscription IPC and rules rejected by main process','production worker independently rejects subscription IPC','no OAuth or real inference','explicit quit cleans workers and relay'],pageErrors:errors,subscriptionDefaultDisabledTested:true,subscriptionAccountInspectionTested:false,subscriptionInferenceTested:false,syntheticCliOnly:true,realModelRequests:0,mockInferenceRequests:1};
  assert.deepEqual(errors,[]);await writeFile(join(root,`artifacts/desktop-evidence/report${packaged ? '-packaged' : ''}.json`),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
} catch(error) {
  if(window) console.log('Desktop failure visible state:', (await window.locator('body').innerText().catch(()=>'' )).slice(-1800));
  throw error;
} finally {
  if(app){const process=app.process();await app.evaluate(({app})=>app.exit(0)).catch(()=>{});await new Promise(r=>{if(process.exitCode!==null)return r();process.once('exit',r);setTimeout(r,3000).unref();});}
  await hub.close();await rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
