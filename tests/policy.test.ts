import test from 'node:test';
import assert from 'node:assert/strict';
import { checkAdmission, withinSchedule } from '../packages/policy/index.js';
import { policySchema, type QuotaSnapshot } from '../packages/protocol/index.js';

const now = Date.parse('2026-09-21T14:00:00Z');
const policy = policySchema.parse({ allowedMemberIds: ['alice'], models: ['mock-codex'] });
const quota: QuotaSnapshot = { status: 'available', fetchedAt: now, origin: 'mock', windows: [
  { limitId: 'codex', usedPercent: 10, windowDurationMins: 300, resetsAt: now / 1000 + 300 },
  { limitId: 'codex-week', usedPercent: 20, windowDurationMins: 10080, resetsAt: now / 1000 + 50000 },
] };
const input = { policy, quota, memberId: 'alice', model: 'mock-codex', bodyBytes: 500, now };
test('all windows must retain headroom, not only the short one', () => {
  assert.doesNotThrow(() => checkAdmission(input));
  assert.throws(() => checkAdmission({ ...input, quota: { ...quota, windows: [quota.windows[0]!, { ...quota.windows[1]!, usedPercent: 76 }] } }), /保留线/);
});
test('missing, empty, future, stale and reset-passed observations are never treated as usable quota', () => {
  for (const candidate of [null, { ...quota, windows: [] }, { ...quota, fetchedAt: now - 120001 }, { ...quota, fetchedAt: now + 9000 }, { ...quota, status: 'unknown' as const },
    { ...quota, windows: [{ ...quota.windows[0]!, resetsAt: now / 1000 - 1 }] }]) {
    assert.throws(() => checkAdmission({ ...input, quota: candidate }));
  }
});
test('member, model, body, expiry and local pause are independently enforced', () => {
  assert.throws(() => checkAdmission({ ...input, memberId: 'mallory' }));
  assert.throws(() => checkAdmission({ ...input, model: 'other-model' }));
  assert.throws(() => checkAdmission({ ...input, bodyBytes: 9 * 1024 * 1024 }));
  assert.throws(() => checkAdmission({ ...input, policy: { ...policy, expiresAt: now } }));
  assert.throws(() => checkAdmission({ ...input, policy: { ...policy, enabled: false } }));
});
test('overnight periods use the starting weekday, explicit timezone and exclusive end', () => {
  const schedule = { days: [1], start: '22:00', end: '02:00', timeZone: 'Asia/Shanghai' };
  assert.equal(withinSchedule(schedule, Date.parse('2026-09-21T14:00:00Z')), true);
  assert.equal(withinSchedule(schedule, Date.parse('2026-09-21T17:30:00Z')), true);
  assert.equal(withinSchedule(schedule, Date.parse('2026-09-21T18:00:00Z')), false);
  assert.equal(withinSchedule(schedule, Date.parse('2026-09-20T17:30:00Z')), false);
  assert.throws(() => withinSchedule({ ...schedule, timeZone: 'Not/AZone' }, now));
});
