# 研判契约

英文 [analysis-contract.md](analysis-contract.md) 是场景选择、参数、证据强度、计数、WAF 覆盖与脱敏的规范源；本文件是其中文镜像。

## 目录

1. 场景决策表
2. 参数契约
3. 成功证据阶梯
4. 统一计数与去重口径
5. `waf_coverage`
6. 脱敏契约
7. 报告必选行为

## 1. 场景决策表

根据用户问题选主场景，不要仅根据声明资产选择。用户显式指定的 anchor 优先；证据跨越多个阶段时增加次要场景。

| 用户问题 / 最强意图 | 主场景 | pattern | 说明 |
|---|---|---|---|
| WAF 是否拦截、告警是否真实、是否有漏过 | S4 | `S4_alert_confirmation` | 必须对照 WAF、网关和主机侧证据 |
| WebShell、上传或 RCE 是否成功 | S2 | `S2_web_breach` | 已有执行或文件证据时优先 |
| 某外网 IP 攻击了哪些对象 | S1 | `S1_external_ip_trace` | 外部源范围；不得将公网 IP 当作主机 |
| 单主机命令/syslog 是否有风险 | S5 | `S5_host_risk` | 以单机行为为主 |
| 是否在主机间横向移动 | S3 | `S3_lateral_movement` | 使用 SSH、账号和目标机执行证据 |
| 账号是否失陷 | S6 | `S6_account_compromise` | 账号为调查锚点 |
| 是否存在数据归集或外传 | S7 | `S7_data_exfiltration` | 需要 connect/DNS/流量/数据库证据 |
| 主机是否正在与 C2 基础设施通信 | S8 | `S8_c2_detection` | 从主机外连出发，关联进程、DNS 和网络会话 |

冲突时优先级：显式 anchor > 用户问题 > 已确认的证据阶段 > 声明资产列表。对于“WAF 资产 + 外网 IP + 漏过”，选 **S4 为主**，证据支持时增加 S1/S2。

## 2. 参数契约

时间使用带明确时区偏移的 ISO 8601。用户给出本地日期时，按其时区解释为 `00:00:00` 至 `23:59:59`，并在报告声明时区。

| 参数 | 含义 | 规则 |
|---|---|---|
| `attacker_ip` | 外部或发起方源 IP | S1/S4 主要源锚点 |
| `src_ip` | connector/template 的源 IP 别名 | 仅在选定 template 需要时镜像 `attacker_ip` |
| `host` | 单个受害主机名或 IP | 用于 S5/S7/S8；不得放入外部公网 IP |
| `hosts` | 多个受害主机 | 仅在用户明确调查多机时使用 |
| `host_ip` | 受害或横向目标 IP | 资产区分主机 IP/名称时优先 |
| `target_ip` | 从 WAF/网关发现的目标 | 必须从证据富化，不得臆造 |
| `alert_time` | 单条告警锚点 | 仅在选中具体告警时使用相对时间窗 |
| `time_start`, `time_end` | 包含边界的调查时间 | live 取数必填；必须带时区偏移 |
| `limit` | connector 结果上限 | 必须报告截断；不得把受限结果称为全量 |

若某 IP 不在资产主机覆盖范围且是可路由公网 IP，除非用户明确说明它是受管主机，否则按 `attacker_ip` 处理。报告保留用户原始参数，并单独声明归一化/富化参数。

## 3. 成功证据阶梯

使用证据支持的最高层级作为 `attack_status`；HTTP 状态码单独不能证明命令执行。

| 层级 | `attack_status` | 最低证据 | 允许结论 |
|---|---|---|---|
| L0 | `insufficient_evidence` | 数据源缺失/失败/截断导致无法定论 | 仅声明缺口 |
| L1 | `blocked` | WAF `block` 且未到达后端/upstream | 攻击尝试已拦截 |
| L2 | `attempted` | 可疑 WAF/WEB/认证事件，无成功证据 | 观测到尝试 |
| L3 | `suspected_success` | 到达后端、上传跳转或可疑响应，无 D2 确认 | 可能漏过/成功 |
| L4 | `confirmed_success` | 匹配的 `host_exec`、`host_file_op`、`host_connect`、目标认证成功或等价 D2 证据 | 确认执行/落地/横向阶段 |

例子：

- 仅 WEB `200`/`302`，无主机证据：最高 `suspected_success`。
- WEB 请求 + 同目标/时间/listener 的 `host_exec`：`confirmed_success`。
- 只有 SSH 客户端命令：尝试或疑似；目标机 `ssh_auth` 成功 + 目标执行才确认横向成功。
- 演练/靶场假设不改变 `attack_status`；它属于上下文和响应优先级。

## 4. 统一计数与去重口径

进程与内核上下文必须按快照理解。`process_start` 增量表示相对上次扫描首次观测，
不是精确 exec 时间；内核模块/容器基线不能证明发生了新的加载/创建操作。
保留 `host_process`、`host_kernel_context` 类型，不能改标为 `host_exec`。
当前确定性 exec/connect 检测器不扫描这些类型；只有这些快照时应说明行为证据不足。
Agent 0.3.29 起，Linux 容器 `process_count` 统计观测到的唯一 PID，`pids` 排序后
最多保留 100 个；计数大于列表长度表示列表截断。旧记录可能重复计入 cgroup 控制器
条目，对已经截断的历史列表去重不能恢复真实总数。

在叙事前报告以下计数：

| 名称 | 来源 | 用途 |
|---|---|---|
| `raw_count` | `fetch_summary.total_fetched_events` | 去重前 connector 返回事件 |
| `retained_count` | `fetch_summary.total_events` | inventory、finding 和 coverage 统一使用的计数 |
| `deduplicated_count` | `fetch_summary.total_deduplicated_events` | 已删除重复事件 |
| `sampled_count` | 分析者声明的子集 | 仅在 retained 数量过大需抽样时使用 |

规则：

1. 报告总数统一使用 retained，除非字段显式标记 `raw`。
2. 同时展示 raw、retained、deduplicated，不得混用分母。
3. 每个 retained `evidence_id` 只计一次。若缺失 `evidence_id`，以 fetch 保留 bundle 为准并声明限制。
4. Prompt 不得再按时间或 message 文本自行去重。
5. 若元数据与 bundle 长度冲突，报告 `count_inconsistency`，分析使用 bundle 数量并降低置信度。

## 5. `waf_coverage`

S4 或用户询问 WAF 漏过时必须输出 `waf_coverage`。按以下顺序匹配：

1. 精确 `trace_id`/请求 ID。
2. 归一化源 IP + 虚拟主机 + method + 归一化 path，且位于 `alert_context`。
3. 源 IP + 目标 + 短时间邻近，标记较低置信度。

路径仅为匹配做归一化：安全解码 URL、移除 fragment、分离 query；证据引用仅保留脱敏展示形式。

| 字段 | 计数规则 |
|---|---|
| `waf_alert_count` | 范围内 retained WAF 告警 |
| `web_access_raw_count` | 同范围去重前网关事件 |
| `web_access_retained_count` | 同范围 retained 网关事件 |
| `blocked_count` | WAF block 且未到达后端 |
| `backend_reached_count` | 已解析 upstream/target 且到达的 retained WEB 事件 |
| `suspicious_without_waf_count` | 无匹配 WAF 告警的可疑 retained WEB 事件 |
| `confirmed_bypass_count` | 由 L4 主机侧证据确认的可疑漏过子集 |
| `unmatched_waf_count` | 无匹配网关请求的 WAF 告警 |
| `deduplicated_count` | coverage 分析前删除的 WEB 重复事件 |

`confirmed_bypass_count` 是子集，不是可累加类别。不得把所有无 WAF 告警的 WEB 流量称为漏过。健康检查和未成功的通用探测可以是 `not_alerted`，但只有可疑请求进入 `suspicious_without_waf_count`。

## 6. 脱敏契约

报告和黄金输出不得包含可复用的敏感值。

- 密码、token、API key、Cookie、Authorization header、私钥和 URI/命令中的凭据参数替换为 `[REDACTED]`。
- 脱敏 `sshpass -p`、`password=`、`token=`、Bearer 值、query/body 凭据和敏感配置内容。
- 仅保留“凭据材料出现”这一事实、字段类别和安全的命令/路径片段。
- 每个结构化 `evidence_ref` 必须包含 `evidence_id` 和 `redacted: true`。
- 使用 `excerpt`，不得使用 `raw_snippet`。未脱敏原始证据链接必须附带敏感性警告。
- 报告级设置 `redaction.applied=true` 和 `redaction.contains_reusable_secrets=false`。

## 7. 报告必选行为

1. 先输出 `fetch_summary` 和计数范围。
2. 单独输出 `verdict`，包含严重级别、`attack_status`、置信度和 disposition。
3. S4/WAF 漏过调查输出 `waf_coverage`。
4. 每条 finding 引用稳定 `evidence_id`。
5. 区分事实、解读、假设和数据缺口。
6. 提供 `chain_coverage`、`join_refs` 和可执行 `fetch_next` 提示。
