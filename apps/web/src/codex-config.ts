/** Browser-only presentation helpers. Keep fields aligned with apps/cli/profile.ts. */
export function buildCodexTemplate(baseUrl: string, model: string): string {
  return `# Share Token 独立配置模板，不包含真实凭据。
# 下载此文件不会安装或创建 Codex 命名 profile。
# 请使用管理页提供的 Share Token CLI 启动命令；它会显式注入配置。
# 仅使用已通过兼容性验证的模型与客户端。
model = ${JSON.stringify(model)}
model_provider = "friends_share"
web_search = "disabled"

[model_providers.friends_share]
name = "Friends Share"
base_url = ${JSON.stringify(baseUrl.replace(/\/$/, ''))}
env_key = "SHARE_TOKEN_ACCESS_KEY"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
supports_standalone_web_search = false
request_max_retries = 0
stream_max_retries = 0
stream_idle_timeout_ms = 300000

# 不把网关凭据传入模型启动的 Shell 子进程。
[shell_environment_policy.filters]
SHARE_TOKEN_ACCESS_KEY = "exclude"
`;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** A POSIX-shell command template. The two local paths must be replaced before running. */
export function buildCodexLaunchCommand(baseUrl: string, model: string): string {
  return [
    'npm run cli -- run',
    `  --base-url ${shellQuote(baseUrl.replace(/\/$/, ''))}`,
    `  --model ${shellQuote(model)}`,
    "  --token-file '/absolute/path/consumer.token'",
    "  --cwd '/absolute/path/to/your-project'",
  ].join(' \\\n');
}
