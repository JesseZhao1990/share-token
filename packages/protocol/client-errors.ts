import { ShareError } from './index.js';

export interface ClientErrorPayload { code: string; message: string; status: number }
type Description = readonly [status: number, message: string];

// These messages cross process boundaries and may be shown in the renderer. Never substitute
// upstream error.message, response bodies, paths, stack traces, credentials, or arbitrary codes.
const descriptions: Readonly<Record<string, Description>> = Object.freeze({
  SHARE_CLIENT_ERROR: [500, '操作未完成。请先刷新状态；仍然失败时，到「设置」导出诊断信息。'],
  SHARE_DONOR_FAILED: [500, '共享设置未完成。请先刷新来源状态；仍然失败时，到「设置」导出诊断信息。'],
  SHARE_SOURCE_EXISTS: [409, '这个 Codex 账号已经有共享来源。请回到原来连接的设备管理该来源；如已重新配对，请联系空间管理员恢复来源归属，再保存规则。'],
  SHARE_SOURCE_OWNED_ELSEWHERE: [409, '这个订阅已绑定旧设备或其他成员。请让空间管理员迁移原共享来源后，再保存规则。'],
  SHARE_MEMBER_INVALID: [400, '允许名单里有已失效的朋友。请刷新成员列表，重新选择要共享的朋友，再保存规则。'],
  SHARE_POLICY_CONFLICT: [409, '共享规则已经发生变化。请刷新来源状态，核对并重新保存规则，再开始分享。'],
  SHARE_POLICY_PENDING: [409, '共享规则还未同步。请在提供共享的电脑上重新保存规则，再开始分享。'],
  SHARE_POLICY_CONFIRMATION_REQUIRED: [409, '扩大共享范围需要本机确认。请核对朋友、模型和保留额度后重新保存规则。'],
  SHARE_POLICY_DEVICE_MISMATCH: [409, '另一台电脑正在提供这个来源。请先在那台电脑停止共享，再在这里保存规则。'],
  SHARE_AUTH_INVALID: [401, '这台设备的连接身份已失效。请重新输入朋友空间的配对码连接。'],
  SHARE_REPAIR_REQUIRED: [401, '这台设备需要重新连接。请重新输入朋友空间的配对码。'],
  SHARE_REFRESH_REUSED: [401, '这台设备的登录状态已失效。请重新输入配对码连接朋友空间。'],
  SHARE_CREDENTIAL_INVALID: [401, '本机保存的连接身份无效。请重新输入配对码连接朋友空间。'],
  SHARE_CREDENTIAL_STORE_FAILED: [500, '无法保存本机登录状态。请检查应用数据目录的权限和剩余磁盘空间，再重新连接。'],
  SHARE_AUTH_RESPONSE_INVALID: [502, '朋友空间返回的设备身份无效。请更新应用或联系空间管理员，再重新连接。'],
  SHARE_PAIRING_REQUIRED: [401, '请先输入配对码连接朋友空间，再继续设置共享。'],
  SHARE_SCOPE_REQUIRED: [403, '这台设备未获当前用途的权限。请在「设置」断开设备，再用配对码重新连接。'],
  SHARE_FORBIDDEN: [403, '当前设备没有操作权限。请联系来源的提供者或空间管理员。'],
  SHARE_NOT_FOUND: [404, '来源不存在或当前设备无权访问。请刷新来源列表，或联系提供共享的朋友。'],
  SHARE_SOURCE_MISSING: [404, '原来的共享来源已不可用。请刷新来源列表；如刚重新连接，请联系空间管理员恢复来源归属。'],
  SHARE_SOURCE_OFFLINE: [503, '提供共享的电脑当前离线。请朋友打开应用并开始分享，再刷新来源。'],
  SHARE_SOURCE_FROZEN: [409, '这个来源有待核实的请求。请先查看使用记录，核实执行结果后再恢复共享。'],
  SHARE_GRANT_FORBIDDEN: [403, '你尚未获得这个来源或模型的授权。请朋友更新允许名单和模型后，再刷新来源。'],
  SHARE_GRANT_REVOKED: [403, '共享授权已撤销或到期。请联系提供共享的朋友重新授权。'],
  SHARE_HUB_CONNECTION_FAILED: [503, '无法连接朋友空间或确认操作结果。请检查内网连接和连接文件，刷新状态后再决定是否重试。'],
  SHARE_HUB_TLS_FAILED: [503, '朋友空间的证书验证失败。请检查电脑时间，并重新导入管理员提供的连接文件。'],
  SHARE_HUB_TRUST_INVALID: [400, '连接文件或证书无效。请重新导入管理员提供的内网连接文件，并检查电脑时间。'],
  SHARE_HUB_URL_INVALID: [400, '朋友空间地址无效。请重新导入管理员提供的连接文件。'],
  SHARE_HUB_MISMATCH: [409, '本机来源与当前朋友空间不匹配。请切回原来的空间，或重新配置这个空间的来源。'],
  SHARE_HUB_REDIRECT_REJECTED: [502, '朋友空间返回了其他地址，连接已停止。请向管理员确认并重新导入正确的连接文件。'],
  SHARE_HUB_RESPONSE_INVALID: [502, '朋友空间返回的信息不完整或格式不兼容。请刷新状态；仍失败时联系管理员检查服务。'],
  SHARE_HUB_REQUEST_FAILED: [502, '朋友空间未完成请求。请刷新状态；仍失败时联系管理员检查服务。'],
  SHARE_EXPERIMENTAL_SUBSCRIPTION_DISABLED: [403, '实验订阅适配默认关闭。当前只提供模拟验证；启用技术开关不代表获得上游授权。'],
  SHARE_SUBSCRIPTION_UNAVAILABLE: [409, '请先选择兼容的 Codex 程序，并登录本应用的订阅账号。'],
  SHARE_SUBSCRIPTION_AUTH_REQUIRED: [401, '订阅账号未登录或登录已失效。请在订阅账号步骤重新登录，再保存规则。'],
  SHARE_SUBSCRIPTION_UNVERIFIED: [409, '无法确认当前 Codex 订阅状态。请刷新账号状态，确认已登录并有可用模型。'],
  SHARE_ACCOUNT_CHANGED: [409, '当前 Codex 账号与来源绑定不一致。请停止共享，重新核对订阅账号，再保存来源。'],
  SHARE_MODEL_UNAVAILABLE: [409, '所选模型当前不可用。请刷新订阅账号状态，重新选择模型，再保存规则。'],
  SHARE_MODEL_NOT_ALLOWED: [403, '所选模型不在允许范围内。请重新选择模型，或请提供者更新共享规则。'],
  SHARE_QUOTA_STALE: [503, '暂时无法确认订阅额度。请刷新账号状态，看到最新额度后再开始分享。'],
  SHARE_RESERVE_REACHED: [429, '已达到你设置的额度保留线。请等待额度恢复，或调整保留规则。'],
  SHARE_RELAY_BUSY: [409, '另一台电脑正在提供这个来源。请先在那台电脑停止共享，再开始分享。'],
  SHARE_RELAY_LEASE_EXPIRED: [409, '共享连接已到期。请刷新来源状态，再重新开始分享。'],
  SHARE_LEASE_EXPIRED: [409, '当前连接授权已到期。请刷新状态并重新启动会话。'],
  SHARE_RELAY_JOURNAL_MISSING: [409, '本机缺少这个来源的执行记录。请核实使用记录，或联系空间管理员恢复来源。'],
  SHARE_RISK_ACKNOWLEDGEMENT_REQUIRED: [409, '请先在使用记录中核实未完成请求的结果，再确认恢复。'],
  SHARE_RESULT_UNKNOWN: [409, '请求可能已经执行，但结果尚未确认。请先核实使用记录，不要重复发送同一请求。'],
  SHARE_DELIVERY_PENDING: [409, '上一个请求的交付结果尚未确认。请先核实使用记录，再继续。'],
  SHARE_DONOR_CONFIG_INVALID: [409, '本机共享配置无效。请重新配置来源；仍失败时，到「设置」导出诊断信息。'],
  SHARE_DONOR_UNCONFIGURED: [409, '请先完成订阅账号和共享规则设置，再开始分享。'],
  SHARE_DONOR_BUSY: [409, '共享端正在处理其他操作。请等待完成；修改规则前请先停止共享。'],
  SHARE_DONOR_CLOSED: [409, '共享工作进程已关闭。请退出并重新打开应用，再刷新状态。'],
  SHARE_START_CANCELLED: [409, '本次启动已经取消。准备好后，请重新点击开始分享。'],
  SHARE_DESKTOP_CHANNEL_UNAVAILABLE: [501, '当前应用不支持这个来源类型。请选择 Codex 订阅，或使用模拟来源检查连接。'],
  SHARE_CAPABILITY_UNAVAILABLE: [501, '当前来源尚未确认模型能力。请提供者刷新订阅状态并重新开始分享。'],
  SHARE_CODEX_VERSION_UNSUPPORTED: [409, '订阅接入需要 Codex CLI 0.153.4。请重新选择兼容版本的 Codex 程序。'],
  SHARE_CODEX_NOT_FOUND: [404, '没有找到本机 Codex 程序。请安装后重新检测，或手动选择程序。'],
  SHARE_CODEX_NOT_EXECUTABLE: [400, '所选 Codex 文件无法执行。请重新选择已安装的 Codex 程序。'],
  SHARE_CODEX_PATH_INVALID: [400, '所选文件不是有效的 Codex 程序。请重新选择。'],
  SHARE_CODEX_DETECTION_FAILED: [500, '无法自动检测 Codex。请在应用中手动选择已安装的 Codex 程序。'],
  SHARE_PROJECT_INVALID: [400, '项目目录不可用。请重新选择你有访问权限的本机项目文件夹。'],
  SHARE_TERMINAL_RUNTIME_UNAVAILABLE: [500, '安装包中的终端组件无法加载。请使用完整解压后的最新版共享token重新打开。'],
  SHARE_TERMINAL_START_FAILED: [500, '本机 Codex 终端未能启动。请检查项目目录和 Codex 程序；仍失败时，到「设置」导出诊断信息。'],
  SHARE_CODEX_START_DENIED: [403, '系统未允许启动所选 Codex 程序。请确认程序可正常运行，并重新选择有访问权限的项目目录。'],
  SHARE_CODEX_EXITED: [500, 'Codex 异常退出。请查看终端输出中的具体错误，检查后重新启动会话。'],
  SHARE_TERMINAL_STOP_UNCONFIRMED: [409, '无法确认 Codex 已停止。请检查对应终端的运行状态后再继续。'],
  SHARE_INPUT_INVALID: [400, '输入内容不符合要求。请核对当前页面的选项后重新保存。'],
  SHARE_PATH_UNSUPPORTED: [400, '当前操作不受支持。请更新应用；仍失败时，到「设置」导出诊断信息。'],
  SHARE_CODE_INVALID: [400, '请输入和朋友约定的 8 位数字配对码。'],
  SHARE_SHARED_CODE_INVALID: [401, '配对码不正确。请核对朋友提供的 8 位数字后重试。'],
  SHARE_MATCHING_UNAVAILABLE: [409, '连接服务尚未支持自选配对码，请更新连接服务后重试。'],
  SHARE_MATCHING_CODE_CONFLICT: [409, '这次连接已经使用另一组配对码。请取消当前申请，再输入新的配对码。'],
  SHARE_CODE_DISABLED: [409, '这个空间尚未设置配对码。请联系创建空间的朋友。'],
  SHARE_SHARED_CODE_DISABLED: [409, '这个空间尚未设置配对码。请联系创建空间的朋友。'],
  SHARE_RATE_LIMITED: [429, '请求过于频繁。请等待一分钟后再试；配对时请先核对正确的配对码。'],
  SHARE_JOIN_BUSY: [409, '正在连接朋友空间，请等待当前操作完成。'],
  SHARE_JOIN_RESTART: [409, '上一次连接已结束。请重新点击加入空间。'],
  SHARE_ALREADY_CONNECTED: [409, '这台设备已经连接朋友空间。请返回应用继续操作。'],
  SHARE_PAIRING_ACTIVE: [409, '已有连接申请正在进行。请先完成或取消该申请，再重新连接。'],
  SHARE_PAIRING_INVALID: [502, '设备连接信息无效。请取消当前申请，再重新连接。'],
  SHARE_PAIRING_MISSING: [409, '当前没有连接申请。请重新输入配对码连接朋友空间。'],
  SHARE_PAIRING_ENDED: [409, '这次连接申请已结束或到期。请重新输入配对码连接。'],
  SHARE_PAIRING_USED: [409, '这次连接申请已使用。请刷新连接状态；仍未连接时重新输入配对码。'],
  EXPIRED_TOKEN: [400, '连接申请已到期。请重新输入配对码连接朋友空间。'],
  ACCESS_DENIED: [403, '这次连接申请已取消或拒绝。请重新发起连接。'],
  PAIRING_CANCELLED: [409, '这次连接已取消。准备好后请重新发起连接。'],
  AUTHORIZATION_PENDING: [400, '正在等待设备连接确认。请完成确认后返回应用。'],
  SLOW_DOWN: [429, '连接确认仍在处理中。请稍候再刷新状态。'],
  SHARE_WORKER_UNAVAILABLE: [503, '本机工作进程未连接。请退出并重新打开应用，再刷新状态。'],
  SHARE_WORKER_TIMEOUT: [504, '本机操作超时，结果尚未确认。请先刷新状态，再决定是否重试。'],
});

const aliases: Readonly<Record<string, string>> = Object.freeze({
  ECONNREFUSED: 'SHARE_HUB_CONNECTION_FAILED', ECONNRESET: 'SHARE_HUB_CONNECTION_FAILED', ENOTFOUND: 'SHARE_HUB_CONNECTION_FAILED', EHOSTUNREACH: 'SHARE_HUB_CONNECTION_FAILED',
  ETIMEDOUT: 'SHARE_HUB_CONNECTION_FAILED', UND_ERR_CONNECT_TIMEOUT: 'SHARE_HUB_CONNECTION_FAILED', UND_ERR_SOCKET: 'SHARE_HUB_CONNECTION_FAILED',
  ERR_TLS_CERT_ALTNAME_INVALID: 'SHARE_HUB_TLS_FAILED', CERT_HAS_EXPIRED: 'SHARE_HUB_TLS_FAILED', DEPTH_ZERO_SELF_SIGNED_CERT: 'SHARE_HUB_TLS_FAILED',
  SELF_SIGNED_CERT_IN_CHAIN: 'SHARE_HUB_TLS_FAILED', UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'SHARE_HUB_TLS_FAILED', UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'SHARE_HUB_TLS_FAILED',
});

export function serializeClientError(error: unknown): ClientErrorPayload {
  let code: unknown, status: unknown;
  try { if (error && typeof error === 'object') { code = (error as { code?: unknown }).code; status = (error as { status?: unknown }).status; } } catch { /* Untrusted accessors must not escape sanitization. */ }
  if (typeof code === 'string' && Object.hasOwn(aliases, code)) code = aliases[code];
  if (typeof code !== 'string' || !Object.hasOwn(descriptions, code)) code = 'SHARE_CLIENT_ERROR';
  const selected = descriptions[code as string]!;
  return { code: code as string, message: selected[1], status: code !== 'SHARE_CLIENT_ERROR' && typeof status === 'number' && Number.isInteger(status) && status >= 400 && status <= 599 ? status : selected[0] };
}

/** Restores a real ShareError while reapplying the local allowlist, even to forged IPC payloads. */
export function restoreClientError(payload: unknown): ShareError {
  const safe = serializeClientError(payload);
  return new ShareError(safe.code, safe.message, safe.status);
}
