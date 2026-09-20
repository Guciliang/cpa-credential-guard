# CPA Credential Guard

CPA Credential Guard 是一个面向 Codex 的 CLIProxyAPI 动态插件。它观察已完成的请求使用记录，识别明确的额度耗尽信号，并通过 CPA Host API 只修改凭证原生的 `disabled` 或 `proxy_url` 字段。插件**不会**替换 CPA 的凭证调度、路由、请求执行、拦截或重试行为。

## 构建

插件依赖已发布的 CPA v7 SDK 接口约定（`v7.2.157`）。Go 模块使用标准的公开模块下载路径，因此构建不依赖研究目录中的本地代码；离线部署时，请通过正常的 Go 代理或模块缓存预置已批准的模块。

```sh
make fmt
go test ./...
go vet ./...
make build
```

在 Linux 上，`make build` 会通过 `go build -buildmode=c-shared` 生成 `bin/cpa-credential-guard.so`；在 macOS 和 Windows 上分别生成 `.dylib` 和 `.dll` 文件。

## 发布与一键安装

本地编译用于开发和隔离的 CPA 测试。正常安装使用 GitHub Actions 构建与目标平台匹配的动态库，并发布 CPA 插件商店所需的 Release 资产。

发布工作流由类似 `v0.1.8` 的 Git tag 触发，并生成以下文件：

```text
cpa-credential-guard_0.1.8_linux_amd64.zip
cpa-credential-guard_0.1.8_linux_arm64.zip
cpa-credential-guard_0.1.8_darwin_amd64.zip
cpa-credential-guard_0.1.8_darwin_arm64.zip
cpa-credential-guard_0.1.8_windows_amd64.zip
checksums.txt
```

每个 zip 的根目录只包含一个动态库（`cpa-credential-guard.so`、`.dylib` 或 `.dll`）。CPA 会验证 SHA-256 校验和，并根据运行环境的操作系统和 CPU 架构解压对应的文件；CPA 所在机器不需要编译 Go 源码。

插件的 GitHub 仓库地址是：

```text
https://github.com/Guciliang/cpa-credential-guard
```

对于设置页面中的 **插件商店来源** 输入框，请填写 raw registry manifest 地址，而不是 GitHub 仓库地址：

```text
https://raw.githubusercontent.com/Guciliang/cpa-credential-guard/main/registry.json
```

该输入框每行接受一个插件商店 registry/manifest 地址。manifest 中包含上面的仓库元数据，CPA 会根据这些信息从仓库解析最新的 GitHub Release。如果你的 CPA 版本支持单独添加插件仓库，请将 GitHub 仓库地址填写到对应的“插件仓库”输入位置，而不是“插件商店来源”输入框。

插件页面的动态数据接口受 CPA 管理权限保护。页面默认在同源的 `cli-proxy-auth` 会话中读取 CPA 已保存的管理登录状态，并且只在内存中使用管理密钥发送 `Authorization: Bearer ...` 请求；插件不会显示、记录或持久化该密钥，也不会使用凭证令牌或 Cookie 代替管理密钥。如果页面提示未读取到管理密钥，请先返回 CPA 管理中心登录，启用“记住密码”，再刷新插件页面。

侧边栏的“连接 CPA”面板也支持手动认证：在“CPA 管理密钥”中粘贴 CPA Management Key，可选填写 CPA 管理地址后点击“连接 CPA”。手动密钥只在当前页面内存中生效，点击“清除手动密钥”或关闭页面后即从页面输入和内存中移除，不会写入 `localStorage`、`sessionStorage`、Cookie、URL、插件状态、日志或操作结果。手动密钥会覆盖自动会话，清除后会恢复自动检测；请求始终使用 `credentials: 'omit'` 和 Bearer 管理密钥。

如果 CPA 界面只显示 registry 中的插件，则还需要将本仓库登记到官方 CPA 插件商店 registry。官方商店只维护 registry 元数据，插件二进制文件仍然存放在本仓库的 GitHub Release 中。

发布新版本时，在工作流已经提交后执行：

```sh
git tag v0.1.8
git push origin v0.1.8
```

tag 和 push 命令会改变远程仓库，必须由仓库所有者执行。Docker 部署必须使用与容器操作系统和 CPU 架构匹配的构建产物，并且 `state_dir` 必须位于已持久化的 CPA 插件目录中。

## 配置

只有在 CPA 启用插件并且插件自身的 `enabled` 设置为 `true` 时，插件才会执行自动操作。默认配置遵循保守原则：只有存在明确额度证据时才将 429 判定为额度耗尽；默认关闭通用限流分类；仅支持 Codex 恢复；额度查询不会自动轮询；主动唤醒默认关闭；扫描间隔至少为十分钟；并使用有上限的退避时间。主动唤醒是高风险的真实 Codex 请求，只有用户明确打开对应开关后才会使用凭证令牌并可能消耗额度。

```yaml
enabled: false
state_dir: plugins/cpa-credential-guard-data
recovery_enabled: true
scan_interval: 10m
initial_backoff: 15m
max_backoff: 24h
probe_enabled: true
probe_provider: codex
probe_model: ""
probe_timeout: 10s
quota_detection_enabled: true
detect_http_429: true
classify_generic_rate_limit: false
proxy_management_enabled: true
initial_wakeup_enabled: false
reset_wakeup_enabled: false
wakeup_model: gpt-5.6-luna
wakeup_reasoning_effort: low
```

### 生效配置逐项说明

侧边栏的“生效配置”只显示安全投影；其中 `state_dir_configured` 是“是否已配置状态目录”的布尔值，不是状态目录路径本身。默认值和关闭后的影响如下：

| 配置投影/配置项 | 默认值 | 作用、单位与关闭影响 |
| --- | --- | --- |
| `enabled` | `false` | 插件总开关。关闭后不执行自动恢复、手动额度查询或主动唤醒，不改变 CPA 调度。 |
| `state_dir_configured` | 由 `state_dir` 决定 | 仅状态展示，表示状态目录已配置；路径不会返回页面。状态保存在 CPA 持久化插件目录中。 |
| `recovery_enabled` | `true` | 控制额度耗尽后的自动恢复；关闭后不自动恢复停用凭证，但不联动关闭主动唤醒。 |
| `scan_interval` | `10m` | 共享扫描检查间隔，单位为时间；它只负责检查/触发，不是 Codex 额度倒计时。 |
| `initial_backoff` | `15m` | 自动恢复或唤醒失败后的首次等待时间，单位为时间。 |
| `max_backoff` | `24h` | 自动恢复失败退避的最大等待时间，单位为时间。 |
| `probe_enabled` | `true` | 允许读取 `GET /backend-api/wham/usage`。关闭后恢复健康检查和“查询全部/查询额度”都返回“额度探测已关闭”。 |
| `probe_provider` | `codex` | 额度健康检查提供方，仅支持 Codex；属于状态展示。 |
| `probe_model_configured` | `false` | 只表示是否配置探测模型，不代表会发送模型请求；当前健康检查不发送推理内容。 |
| `probe_timeout` | `10s` | 每次额度健康检查的超时时间上限。 |
| `quota_detection_enabled` | `true` | 是否根据 CPA `UsageRecord` 分类额度耗尽；关闭后不因使用失败自动判定并停用凭证。 |
| `detect_http_429` | `true` | 是否把 HTTP 429 纳入额度证据分析；关闭后忽略该信号。 |
| `classify_generic_rate_limit` | `false` | 是否把通用限流错误分类为额度证据；关闭更保守，不据此停用凭证。 |
| `proxy_management_enabled` | `true` | 是否允许保存、检测和批量分配代理；关闭后这些代理操作不可用。 |
| `initial_wakeup_enabled` | `false` | 首次唤醒未使用凭证。开启后下一轮扫描可能为尚无真实使用证据的启用凭证发送一次固定的真实 Codex 请求；关闭不会影响另一个唤醒开关。 |
| `reset_wakeup_enabled` | `false` | 重置后自动唤醒。开启后仅对已知重置时间到达且身份仍匹配的凭证发送一次真实请求；关闭不会影响首次唤醒。 |
| `wakeup_model` | `gpt-5.6-luna` | 主动唤醒使用的服务端允许模型，不能填写任意上游地址；可能产生真实用量。 |
| `wakeup_reasoning_effort` | `low` | 主动唤醒思考等级，只允许服务端白名单值；固定最小提示词为 `Hello`，失败按有界策略处理。 |

两个唤醒开关互不隐式开启，健康检查、手动额度查询、主动唤醒和正常 CPA 业务请求是四类不同证据。

`state_dir` 是显式且持久化的状态目录。插件不会回退到临时目录、当前工作目录或 `AuthDir`。当 CPA 在 Docker 中使用自定义 `plugins.dir` 时，请将 `state_dir` 配置为持久化插件卷下的子目录，例如 `/data/plugins/cpa-credential-guard-data`，并确保该目录在容器重启之间保持挂载。状态目录为空、不安全、不可访问或配置无效时，插件会关闭自动写入功能，而不会选择其他目录代替。

## 安全边界

* 每次凭证写入都遵循 `host.auth.get` → 只修改一个顶层字段 → `host.auth.save` 的流程；其他未知字段在语义上保持不变。
* 恢复操作必须同时满足：存在持久化的插件所有权记录，以及内容和运行时变更校验未发生变化。对于人工修改或无法验证的状态，插件会转入人工复核，不会覆盖用户的修改。
* 恢复操作每次只执行一次有超时限制的凭证级 `GET https://chatgpt.com/backend-api/wham/usage` 请求。侧边栏打开状态页、插件安装和普通周期扫描不会自动查询全部额度；只有“查询全部额度”或单行“查询额度”按钮会触发额度查询。临时访问令牌不会被持久化、记录日志、显示给用户，也不会传递给代理测试。
* 代理测试使用独立的、有超时限制的 HTTP/SOCKS 传输，并依次访问基础连通性、OpenAI、Anthropic、Gemini、Grok 五个固定的非 Codex HTTPS 目标。代理测试不会接收 AuthIndex 或凭证 JSON，不发送 Authorization/Cookie，不接受浏览器提交的目标 URL；代理建立失败后也不会回退到直连。
* 开启任一主动唤醒开关后，插件才会在内存中读取对应凭证并向固定的 `https://chatgpt.com/backend-api/codex/responses` 发送一次受控真实请求，模型为 `gpt-5.6-luna`、思考等级默认为 `low`、提示词固定为 `Hello`。该请求可能消耗真实额度；令牌、请求/响应内容和原始错误不会写入日志、状态、管理响应或页面。
* 静态侧边栏资源不包含动态数据。经过认证的管理路由只返回代理备注、脱敏端点、安全状态和每项独立结果。
* 插件只声明 `usage_plugin` 和 `management_api` 能力，不注册 scheduler/router/executor/interceptor，也不实现自定义的 502 重试。

* 认证管理路由位于 `/v0/management/plugins/cpa-credential-guard/` 下，包括 `GET /status`、`GET/POST /proxy/profiles`、`POST /proxy/profiles/delete`、`POST /proxy/preview`、`POST /proxy/apply`、`POST /proxy/test`、`POST /quota/query` 和 `POST /recovery/scan`。`POST /quota/query` 只接受 `{}`（全部）或 `{ "auth_index": "..." }`（单项）。浏览器资源地址是 `/v0/resource/plugins/cpa-credential-guard/index.html`，其中不包含由服务器渲染的凭证数据。
* 代理备注目录和运行状态都位于 `state_dir`：目录中的代理配置以受限权限保存，前端和状态投影只显示备注与脱敏端点；给凭证分配代理时选择已保存的备注，不需要反复输入 URL。代理预览计划五分钟后过期，并且会根据最新的 Host API 快照重新校验；异构批量操作会返回每个项目独立的结果。原始代理 URL 不会返回给前端，也不会写入运行时所有权状态。

请参阅 `NOTICE.md` 了解 SDK、直接依赖和行为参考的许可说明。项目没有复制 Sub2API 的 LGPL 源码，也没有采用 `codex-429-autoban` 的调度器行为。
