import test from 'node:test';
import assert from 'node:assert/strict';
import { sessionPresentation, terminalSessionStatus } from '../apps/desktop/renderer/session-view.js';
import type { LocalSession } from '../apps/desktop/renderer/api.js';

const session = (patch: Partial<LocalSession>): LocalSession => ({ sessionId: 'test-session', sourceId: 'test-source', model: 'test-model', state: 'running', ...patch });

test('launch failures show the controller message and recovery action without an empty terminal', () => {
  const value = session({ state: 'failed', terminalStarted: false, pid: null, message: '无法启动本机终端。请更新应用后重试。', error: 'older fallback' });
  const view = sessionPresentation(value);
  assert.equal(view.label, '启动失败'); assert.equal(view.message, value.message);
  assert.equal(view.canOpenTerminal, false); assert.equal(view.canStop, false); assert.equal(view.canCheckSetup, true); assert.equal(view.problem, true);
  assert.equal(terminalSessionStatus(value), '启动失败 · 无法启动本机终端。请更新应用后重试。');
});

test('exited terminals retain their output action even after pid is cleared', () => {
  const failed = sessionPresentation(session({ state: 'failed', terminalStarted: true, pid: null, exitCode: 7, message: 'Codex 已退出，退出码为 7。' }));
  assert.equal(failed.label, '异常退出'); assert.equal(failed.canOpenTerminal, true); assert.equal(failed.terminalActionLabel, '查看终端输出'); assert.equal(failed.canStop, false); assert.equal(failed.canCheckSetup, true);
  const stopped = sessionPresentation(session({ state: 'stopped', terminalStarted: true, pid: null, exitCode: 0 }));
  assert.equal(stopped.label, '已结束'); assert.equal(stopped.canOpenTerminal, true); assert.equal(stopped.terminalActionLabel, '查看终端输出'); assert.equal(stopped.canStop, false); assert.equal(stopped.problem, false);
  const neverStarted = sessionPresentation(session({ state: 'stopped', terminalStarted: false, pid: null }));
  assert.equal(neverStarted.canOpenTerminal, false);
  const userStopped = sessionPresentation(session({ state: 'stopped', terminalStarted: true, pid: null, exitSignal: 15 }));
  assert.equal(userStopped.label, '已结束'); assert.equal(userStopped.problem, false); assert.equal(userStopped.message, '');
});

test('older snapshots remain readable without mistaking a missing pid for lost output', () => {
  const failed = sessionPresentation(session({ state: 'failed', error: '旧版保存的启动原因' }));
  assert.equal(failed.message, '旧版保存的启动原因'); assert.equal(failed.canOpenTerminal, false); assert.equal(failed.label, '启动失败');
  const stopped = sessionPresentation(session({ state: 'stopped', pid: null })); assert.equal(stopped.canOpenTerminal, true); assert.equal(stopped.canStop, false);
  const exited = sessionPresentation(session({ state: 'failed', pid: null, exitCode: 2 })); assert.equal(exited.canOpenTerminal, true); assert.equal(exited.label, '异常退出'); assert.match(exited.message, /退出码为 2/);
  const pendingStop = sessionPresentation(session({ state: 'failed', pid: 321 })); assert.equal(pendingStop.canStop, true);
});

test('session and terminal views translate every controller state and preserve attention reasons', () => {
  for (const [state, label, canStop] of [
    ['starting', '正在启动', true], ['running', '运行中', true], ['requesting', '正在请求', true],
    ['attention', '需要处理', true], ['stopping', '正在停止', false], ['stopped', '已结束', false],
  ] as const) {
    const value = session({ state }); const view = sessionPresentation(value);
    assert.equal(view.label, label); assert.equal(view.canStop, canStop); assert.equal(terminalSessionStatus(value), label);
  }
  const attention = session({ state: 'attention', message: '本机 Codex 退出尚未确认。', terminalStarted: true, pid: 222 });
  assert.equal(sessionPresentation(attention).problem, true); assert.match(terminalSessionStatus(attention), /退出尚未确认/);
  assert.equal(sessionPresentation(session({ state: 'NEW_UNKNOWN_STATE' })).label, '状态待确认');
  assert.equal(terminalSessionStatus(), '正在读取会话状态…');
});

test('signal termination is actionable and blank diagnostic messages receive a useful fallback', () => {
  const signal = sessionPresentation(session({ state: 'failed', terminalStarted: true, pid: null, exitSignal: 9, message: '  ' }));
  assert.match(signal.message, /信号 9/); assert.equal(signal.canCheckSetup, true);
  const failed = sessionPresentation(session({ state: 'failed', terminalStarted: false, message: '  ' }));
  assert.match(failed.message, /检查程序和项目目录/); assert.equal(failed.canOpenTerminal, false);
});


test('safe controller diagnostics retain the real exit code in session and terminal feedback', () => {
  const failed = session({ state: 'failed', terminalStarted: true, pid: null, exitCode: 23,
    message: 'Codex 异常退出。请查看终端输出中的具体错误，检查后重新启动会话。' });
  const view = sessionPresentation(failed);
  assert.match(view.message, /查看终端输出/); assert.match(view.message, /退出码为 23/);
  assert.match(terminalSessionStatus(failed), /异常退出.*退出码为 23/);
  const detailed = session({ ...failed, message: 'Codex 已退出，退出码为 23。' });
  assert.equal(sessionPresentation(detailed).message, detailed.message);
});
