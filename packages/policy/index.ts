import { ShareError, type QuotaSnapshot, type SharePolicy } from '../protocol/index.js';

export interface AdmissionInput {
  policy: SharePolicy; quota: QuotaSnapshot | null; memberId: string;
  model: string; bodyBytes: number; now?: number;
}

/** A fail-closed admission decision, never a reservation of provider tokens. */
export function checkAdmission({ policy, quota, memberId, model, bodyBytes, now = Date.now() }: AdmissionInput): void {
  if (!policy.enabled) throw new ShareError('SHARE_SOURCE_PAUSED', '贡献者已暂停共享。', 503);
  if (!policy.allowedMemberIds.includes(memberId)) throw new ShareError('SHARE_MEMBER_NOT_ALLOWED', '贡献者尚未允许这位成员使用。', 403);
  if (!policy.models.includes(model)) throw new ShareError('SHARE_MODEL_NOT_ALLOWED', '当前来源未开放这个模型。', 400);
  if (!Number.isSafeInteger(bodyBytes) || bodyBytes < 1 || bodyBytes > policy.maxBodyBytes) throw new ShareError('SHARE_BODY_TOO_LARGE', '模型请求大小超出共享上限。', 413);
  if (policy.expiresAt !== null && policy.expiresAt <= now) throw new ShareError('SHARE_WINDOW_CLOSED', '共享授权已到期。', 403);
  if (policy.schedule && !withinSchedule(policy.schedule, now)) throw new ShareError('SHARE_WINDOW_CLOSED', '当前不在贡献者的共享时段。', 503);
  if (!quota || quota.status !== 'available' || quota.windows.length === 0 ||
      quota.fetchedAt > now + 5000 || quota.fetchedAt < now - policy.quotaMaxAgeMs) {
    throw new ShareError('SHARE_QUOTA_STALE', '额度数据未知或已过期，请等待贡献者刷新。', 503);
  }
  for (const window of quota.windows) {
    if (!Number.isFinite(window.usedPercent) || window.usedPercent < 0 || window.usedPercent > 100 ||
        !Number.isFinite(window.windowDurationMins) || window.windowDurationMins <= 0 ||
        (window.resetsAt !== null && window.resetsAt * 1000 <= now)) {
      throw new ShareError('SHARE_QUOTA_STALE', '额度窗口无法确认，请等待重新读取。', 503);
    }
    if (100 - window.usedPercent <= policy.reservePercent + policy.startMarginPercent) {
      throw new ShareError('SHARE_RESERVE_REACHED', '已达到贡献者设置的额度保留线。', 429);
    }
  }
}

export function withinSchedule(schedule: NonNullable<SharePolicy['schedule']>, now: number): boolean {
  let parts: Intl.DateTimeFormatPart[];
  try { parts = new Intl.DateTimeFormat('en-US', { timeZone: schedule.timeZone, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(now); }
  catch { throw new ShareError('SHARE_POLICY_INVALID', '共享时区无效。', 400); }
  const get = (kind: string) => parts.find(p => p.type === kind)?.value ?? '';
  const day = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(get('weekday'));
  const minute = Number(get('hour')) * 60 + Number(get('minute'));
  const toMinute = (v: string) => Number(v.slice(0, 2)) * 60 + Number(v.slice(3));
  const start = toMinute(schedule.start), end = toMinute(schedule.end);
  if (start === end) return schedule.days.includes(day);
  if (start < end) return schedule.days.includes(day) && minute >= start && minute < end;
  // After midnight belongs to the previous day's sharing window.
  return minute >= start ? schedule.days.includes(day) : minute < end && schedule.days.includes((day + 6) % 7);
}
