# CPA Credential Guard 方案

> 中文显示名：**CPA 凭证卫士**  
> 英文/仓库名：**CPA Credential Guard** / `cpa-credential-guard`

## 1. 文档状态

- 当前阶段：方案确认，尚未开始实现
- 产品目录：`/workspace/cpa-plugin`
- 当前目录在本次记录前为空
- 目标运行环境：CLIProxyAPI（CPA）插件机制
- 第一版暂不修改 CPA 核心

## 2. 项目目标

制作一个以凭证额度生命周期管理为核心的 CPA 插件：

1. 检测凭证额度耗尽或相应的额度错误。
2. 检测到额度耗尽后，直接使用 CPA 原生凭证 `disabled` 状态停用凭证。
3. 定期检查额度是否恢复。
4. 恢复后自动启用凭证，并发送一次简单测试请求，让上游开始新的额度计时/窗口。
5. 支持批量给凭证设置代理。
6. 完全不修改用户在 CPA 中已有的凭证选择配置。
7. 第一版不实现自定义的同凭证 502 重试。

## 3. 已确认的行为边界

### 3.1 不改变 CPA 凭证使用方式

插件不得修改或重写：

- `routing.strategy`
- `fill-first`、`round-robin` 等策略配置
- 凭证优先级/权重
- Session affinity 配置
- CPA 配置文件中的其他调度设置

这里的要求是“插件不修改用户配置”，而不是要求插件在凭证被禁用后继续精确复刻 CPA 的原始调度算法。

正常情况下插件不接管凭证选择，继续交给 CPA 原生调度。凭证被设置为原生 `disabled=true` 后，由 CPA 自己将其排除。

### 3.2 使用 CPA 原生 disabled

不维护一套仅供插件 scheduler 使用的独立封禁池，也不在插件内部长期过滤凭证。

额度耗尽后的处理：

```text
请求完成
  -> UsagePlugin 检测到额度耗尽/429/额度信号
  -> 找到对应凭证文件
  -> 仅将该凭证 JSON 中的 disabled 设置为 true
  -> CPA 重新加载凭证并停止使用它
```

额度恢复后的处理：

```text
恢复检测到期
  -> 确认该凭证是插件此前因额度耗尽而禁用的
  -> 将 disabled 设置为 false
  -> 发送一次简单测试请求
  -> 成功后保持启用
```

如果测试仍然表明额度未恢复，则重新设置 `disabled=true`，并按照退避时间等待下一次检测。

### 3.3 不误启用用户手动禁用的凭证

CPA 的 `disabled` 字段本身没有“禁用原因”字段。因此插件需要保存最小的归属信息，例如：

- `AuthIndex`/稳定凭证身份
- 凭证文件名
- 插件设置禁用的时间
- 禁用前是否处于启用状态
- 预计下一次检查时间
- 最近一次禁用原因

这不是另一套调度禁用机制，而是为了区分：

```text
插件因为额度耗尽设置 disabled=true  -> 插件可以在恢复后自动启用
用户原本就手动设置 disabled=true    -> 插件不得自动启用
```

如果凭证在等待恢复期间被用户再次手动修改，后续实现应尽量通过文件修改时间/版本或明确的手动覆盖操作避免误启用。

## 4. 第一版功能范围

### 4.1 额度耗尽检测

使用 CPA 的 `UsagePlugin.HandleUsage` 观察请求结果。可使用的信息包括：

- 被选中的 `AuthID` / `AuthIndex`
- Provider
- HTTP 状态码
- 上游响应头
- 请求模型
- 请求是否失败
- 额度/重置时间相关信号

第一版重点支持：

- HTTP 429
- 明确表示 quota exhausted / rate limit / quota depleted 的响应
- 可从响应头或结构化错误中确定的额度耗尽状态

不要把所有 429 都无条件永久禁用；应根据 provider、响应信号和可配置规则判断是否属于额度耗尽，并记录预计恢复时间。

不记录或打印完整的 Token、Authorization、Cookie、响应敏感内容。

### 4.2 CPA 原生停用与恢复

自动操作优先使用 CPA Host API：

1. 使用 `host.auth.get` 或 `host.auth.get_runtime` 根据 `AuthIndex` 定位凭证。
2. 取得凭证文件名和完整 JSON。
3. 保留 JSON 中的所有原有字段，只修改 `disabled`。
4. 使用 `host.auth.save` 写回原凭证文件。

停用时只改变：

```json
{"disabled": true}
```

启用时只改变：

```json
{"disabled": false}
```

如果是在已有 Management Key 的管理操作中执行，也可以使用 CPA Management API：

```http
PATCH /v0/management/auth-files/status
Content-Type: application/json

{"name":"credential.json","disabled":true}
```

但自动额度回调不应依赖 Management Key；自动路径以 Host API 为主。

### 4.3 恢复检测和测试请求

恢复检测器需要支持：

- 周期扫描
- 按凭证记录的预计恢复时间减少无意义请求
- 失败退避
- 防止同一凭证重复并发探测
- CPA 重启后从持久化状态恢复任务

恢复时的基本流程：

```text
确认插件拥有该凭证的禁用记录
  -> 设置 disabled=false
  -> 发送配置的简单测试请求
  -> 成功：保留启用状态，清除/完成本次禁用记录
  -> 仍未恢复：重新 disabled=true，增加退避时间
```

测试请求应使用可配置的 provider/model 和最小请求内容，避免消耗不必要额度。探测结果只记录状态、时间和安全的错误摘要。

### 4.4 批量设置代理

提供批量选择凭证并设置代理的能力：

- 支持给多个凭证设置同一个代理
- 支持清除代理
- 支持按凭证逐项设置不同代理（可作为后续增强）
- 批量操作前提供预览
- 单个凭证失败不能吞掉其他凭证结果
- 展示成功、失败和失败原因
- 只修改 `proxy_url` 或 CPA 对应的代理字段
- 不修改 `disabled`、priority、routing 或 Token 字段

批量代理设置可以复用 CPA Management API 的字段更新能力，或使用安全的 Host 保存路径；实现时必须保留认证 JSON 的其他字段。

代理地址在日志和页面列表中应脱敏，特别是代理 URL 中的用户名和密码。

### 4.5 502 重试

第一版明确不实现自定义 502 重试，不修改 CPA 核心，也不新增同凭证重试语义。

继续使用 CPA 当前的原生重试行为：

```text
凭证 A -> 502 -> 由 CPA 当前机制决定重试或切换凭证
```

未来如果要实现“同一凭证先重试 N 次，再切换下一凭证”，需要 CPA 核心或请求执行包装层提供支持，不属于第一版插件范围。

## 5. 建议模块结构

```text
cpa-credential-guard/
├── plugin registration       # 插件注册和 SDK 入口
├── config                    # 配置加载、校验和持久化
├── usage observer             # 观察请求结果和额度信号
├── quota classifier           # 判断是否为额度耗尽及恢复时间
├── auth state                 # 通过 CPA Host API 修改 disabled
├── ownership store            # 记录哪些 disabled 是插件设置的
├── recovery scheduler         # 周期恢复检查、退避和并发控制
├── probe executor             # 恢复后的简单测试请求
├── proxy batch manager        # 批量代理设置
├── management/dashboard       # 状态查看和管理操作
└── tests                      # 单元测试、Host API 测试和集成测试
```

## 6. 建议配置项

配置名称在实现时可以调整，但第一版需要覆盖以下内容：

```yaml
credential_guard:
  enabled: true

  recovery:
    enabled: true
    scan_interval: 5m
    initial_backoff: 5m
    max_backoff: 6h

  probe:
    enabled: true
    provider: ""
    model: ""
    timeout: 30s

  quota_detection:
    enabled: true
    detect_http_429: true
    # provider-specific rules 后续扩展

  proxy_management:
    enabled: true
```

默认值要保守，不能因配置缺失而修改 CPA 现有调度策略。

## 7. 重要技术事实

### CPA 插件接口

- `UsagePlugin.HandleUsage` 能收到请求完成后的凭证和失败信息，适合做额度检测。
- Usage 回调发生在请求结束后，不能同步要求 CPA 用同一凭证重新执行请求。
- `SchedulerPickResponse` 只能返回一个 AuthID、DelegateBuiltin 或 unhandled，不能返回“过滤后的候选列表”。
- 由于第一版直接使用 CPA 原生 `disabled`，不需要插件接管 scheduler，也不需要复刻 fill-first/round-robin。

### CPA Host API

- `host.auth.list`：列出凭证信息。
- `host.auth.get`：按 `AuthIndex` 获取完整凭证 JSON。
- `host.auth.get_runtime`：获取运行时凭证信息。
- `host.auth.save`：保存修改后的凭证 JSON。
- 修改 `disabled` 后应保留 JSON 的所有其他字段。

### Management API

CPA 也提供：

```text
PATCH /v0/management/auth-files/status
```

用于更新凭证的 `disabled` 状态；

```text
PATCH /v0/management/auth-files/fields
```

可用于字段批量更新，例如代理字段。自动回调路径不应依赖 Management Key。

## 8. 实现顺序

1. 初始化 Go 插件工程和 CPA SDK 依赖。
2. 完成插件注册、配置结构和安全日志。
3. 实现 Host API 凭证读取、只改 `disabled` 的保存工具。
4. 为原生停用/启用工具编写单元测试，确认不会丢失 JSON 字段。
5. 实现 UsagePlugin 额度信号分类。
6. 实现插件禁用归属记录和持久化。
7. 实现恢复扫描、退避、并发锁和恢复测试请求。
8. 实现批量代理更新、预览、错误汇总和脱敏展示。
9. 增加 CPA Host API 模拟测试和端到端测试。
10. 使用真实 CPA 测试环境验证：额度耗尽、重启恢复、手动禁用、额度恢复、代理批量更新。

## 9. 验收标准

### 调度配置保护

- 插件运行前后 `routing.strategy` 不变。
- 插件不修改凭证 priority/weight。
- 插件不注册会替代 CPA 原生 selector 的常驻调度逻辑。

### 自动停用

- 额度耗尽凭证的 CPA 原生 `disabled` 最终为 `true`。
- CPA 后续不再正常选择该凭证。
- 原凭证 JSON 的其他字段保持不变。
- 非额度错误不会误禁用凭证。

### 自动恢复

- 只自动恢复插件自己因额度耗尽而禁用的凭证。
- 用户原本手动禁用的凭证不会被自动启用。
- 恢复后会发送一次简单测试请求。
- 探测失败会重新禁用并退避，不产生高频请求循环。

### 批量代理

- 可批量设置、替换和清除代理。
- 代理更新不修改 Token、priority、disabled 等无关字段。
- 代理凭证信息不会出现在日志中。
- 部分失败时能准确展示每个凭证的结果。

### 重试范围

- 第一版不宣称提供同凭证 502 重试。
- 不修改 CPA 核心请求重试逻辑。

## 10. 后续会话需要先确认的问题

开始编码前需要进一步确定：

1. 第一版要支持哪些 provider（仅 Codex，还是 CPA 的多个 provider）。
2. 各 provider 的额度耗尽判断规则和恢复时间来源。
3. 默认测试模型和测试请求格式。
4. 插件配置使用 CPA 配置文件、独立配置文件，还是两者结合。
5. 是否第一版就提供 Web 管理页面，还是先完成后台能力。
6. 批量代理使用 Management API 还是 Host API 保存路径。
7. 插件状态持久化文件的位置和格式。

---

## 最终决策摘要

```text
插件名称：CPA Credential Guard

额度耗尽：直接写 CPA 原生 disabled=true
额度恢复：只恢复插件自己禁用的凭证，写 disabled=false 后发送测试请求
调度策略：不修改 CPA 原有配置，不接管 scheduler
批量代理：支持
502 重试：第一版不实现，保持 CPA 原生行为
插件私有禁用池：不使用
插件内部状态：仅保存禁用归属、恢复时间、探测结果等必要元数据
```
