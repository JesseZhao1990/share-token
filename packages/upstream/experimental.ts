import { ShareError } from '../protocol/index.js';

export const EXPERIMENTAL_SUBSCRIPTION_ENV = 'SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION';
export const EXPERIMENTAL_SUBSCRIPTION_DISABLED_MESSAGE = '实验订阅适配默认关闭。当前只提供模拟验证；启用技术开关不代表获得上游授权。';

/** Local operator opt-in only. Hub, CLI config and renderer input cannot enable this. */
export function experimentalSubscriptionEnabled(): boolean {
  return process.env[EXPERIMENTAL_SUBSCRIPTION_ENV] === '1';
}

export function assertExperimentalSubscriptionEnabled(): void {
  if (!experimentalSubscriptionEnabled()) throw new ShareError('SHARE_EXPERIMENTAL_SUBSCRIPTION_DISABLED', EXPERIMENTAL_SUBSCRIPTION_DISABLED_MESSAGE, 403);
}
