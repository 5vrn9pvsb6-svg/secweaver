风险识别 **环境白名单**（第三层）：在 **behavior-policy 策略裁决之后**，按 scope 对 `risk_items[]` 做 suppress/downgrade。**assess 默认读取** `whitelist.json`；不会删除检测证据。

## 一、与 behavior-policy 分工

| 层 | 文件 | 写什么 |
|----|------|--------|
| 策略 | behavior-policy | 硬护栏、必须告警、全平台 OPS 降噪 |
| **白名单** | **whitelist.json** | 环境 scope 例外（CIDR、exe 前缀、listener 组合等） |

禁用白名单：`assess.py --no-whitelist` 或 payload `"whitelist": {"enabled": false}`。

## 二、白名单适用场景

- 已确认是业务、运维、采集 Agent、云平台初始化产生的固定行为。
- 命令、目标地址、监听入口、主机范围都比较稳定。
- 风险规则会命中，但经人工确认不需要触发告警。

不建议加入白名单的事件：

- 只因为“这次看起来没问题”但无法稳定复现的行为。
- 反弹 shell、WebShell、任意公网下载执行等攻击特征明显的行为。
- 条件过宽的规则，例如只按 `curl`、`bash`、`sshd` 这类单字段放行。

## 三、唯一配置文件

**只维护一个文件**：

`src/skills/risk-identification/whitelist.json`

该文件同时服务于：

- `risk-identification` 编排层
- `external-listener-cmd-risk` exec 子模块
- `external-listener-connect-risk` connect 子模块

`whitelist.example.json` 仅作模板参考，运行时优先读取 `whitelist.json`。

首次使用：

```bash
cp src/skills/risk-identification/whitelist.example.json \
  src/skills/risk-identification/whitelist.json
```

**已废弃**：payload 中的 `user_rules.whitelist_ports`、`user_rules.whitelist_exe_prefixes`、`user_rules.dst_cidrs`。这些字段若仍传入，会收到警告，但不会生效。

```text
原始 evidence → 检测 rules → behavior-policy → whitelist.json → 输出
```

白名单是 **post_policy** 模式（默认开启）：

- 先正常跑风险规则，保证 `matched_rules[]`、`summary`、证据引用完整。
- 再判断风险项是否命中白名单。
- 命中后不删除风险项，而是降级或抑制告警。

策略层 `hard_guardrail`/`force_alert` 或 `policy_forced_alert` 决策不能被白名单
覆盖，也不计白名单命中。降到 P2/P3 时同步设置 `alert_required=false`；未指定
`target_action` 时采用 `observe`/`log_only`。降级不会重新激活此前已抑制的告警。

## 四、白名单命中后的输出字段

命中白名单后，单条 `risk_item` 会增加这些字段：

| 字段 | 说明 |
|---|---|
| `whitelisted` | 是否命中白名单 |
| `whitelist_rule_id` | 命中的白名单规则 ID |
| `whitelist_action` | 白名单动作，如 `suppress` / `downgrade` |
| `whitelist_reason` | 白名单原因 |
| `original_risk` | 保留策略层记录的原始检测决策；缺省时记录白名单前的值 |
| `pre_whitelist_risk` | 紧邻白名单处理前的等级、结论、动作、置信度 |
| `alert_required` | 是否仍需要产生告警 |
| `alert_suppressed` | 是否已抑制告警 |

输出 `summary` 中也会包含：

| 字段 | 说明 |
|---|---|
| `alert_required` | 仍需告警的风险数量 |
| `alert_suppressed` | 被白名单抑制的风险数量 |

## 五、规则结构

一个白名单文件的基本结构：

```json
{
  "version": "1.0",
  "defaults": {
    "enabled": true,
    "mode": "post_detection",
    "keep_evidence": true
  },
  "rules": [
    {
      "id": "wl-example-rule",
      "enabled": true,
      "description": "规则说明",
      "scope": {
        "risk_modules": ["exec"],
        "matched_rules_any": ["download_and_execute"],
        "listener_process": ["sshd"],
        "listener_ports": [22],
        "command_regex": "fixed-safe-command-pattern"
      },
      "action": "suppress",
      "target_severity": "P3",
      "target_verdict": "benign",
      "target_action": "log_only",
      "reason": "人工确认的白名单原因"
    }
  ]
}
```

## 六、scope 支持字段

`scope` 是匹配条件，多个条件之间是 **AND** 关系，全部满足才命中。

| 字段 | 类型 | 说明 |
|---|---|---|
| `risk_modules` | 数组 | 风险模块，如 `exec`、`connect`、`file` |
| `hosts` | 数组 | 主机名白名单范围 |
| `listener_process` | 数组 | 入口监听进程，如 `sshd`、`nginx`、`java` |
| `listener_ports` | 数组 | 入口监听端口，如 `[22]`、`[80, 443]` |
| `dst_cidrs` | 数组 | 外连目标网段，如 `10.0.0.0/8` |
| `dst_ports` | 数组 | 外连目标端口 |
| `matched_rules_any` | 数组 | 命中任意一个风险规则即可 |
| `matched_rules_all` | 数组 | 必须同时命中所有风险规则 |
| `severity_at_or_above` | 字符串 | 只处理不低于指定等级的风险，如 `P1` 表示 P0/P1 |
| `command_regex` | 字符串 | 命令行正则匹配 |
| `exe_regex` | 字符串 | 可执行文件路径正则匹配 |
| `exe_prefixes` | 数组 | 可执行文件路径前缀，如 `["/opt/ops/"]` |
| `summary_regex` | 字符串 | 风险摘要正则匹配 |

建议至少组合 3 个以上条件，例如：

- `risk_modules + matched_rules_any + command_regex`
- `listener_process + listener_ports + exe_regex + command_regex`
- `hosts + dst_cidrs + dst_ports + matched_rules_any`

## 七、action 支持方式

### suppress：抑制告警

适合确定无风险、但仍需要保留证据的事件。

效果：

```json
{
  "severity": "P3",
  "verdict": "benign",
  "recommended_action": "log_only",
  "alert_required": false,
  "alert_suppressed": true
}
```

### downgrade：降级风险

适合不是完全无风险，但不希望按 P0/P1 告警的事件。

示例：

```json
{
  "action": "downgrade",
  "target_severity": "P2",
  "target_verdict": "suspicious",
  "target_action": "observe",
  "target_confidence": 0.4
}
```

## 八、内置默认规则

`whitelist.json` 已内置以下默认规则，可按环境调整 `enabled` 或删除：

| 规则 ID | 模块 | 说明 |
|---|---|---|
| `wl-aliyun-metadata-region-curl` | exec | 阿里云 metadata region-id 查询 |
| `wl-ilogtail-loongcollector-grep` | exec | LoongCollector 路径 grep 巡检 |
| `wl-nginx-config-test` | exec | `nginx -t` 配置检测 |
| `wl-ops-exe-prefix` | exec | `/opt/ops/` 运维脚本目录 |
| `wl-sshd-interactive-noise` | exec | SSH 22 登录会话默认降噪 |
| `wl-listener-port-shell-exec` | exec | 22 端口 shell 执行默认降级 |
| `wl-connect-trusted-public-api` | connect | 业务公网 API 外连（默认 disabled） |

## 九、示例 1：阿里云 metadata 查询

历史示例：旧版或自定义检测器将仅查询 metadata 的 curl 标为 `download_and_execute`。
Exec 1.3 已不再给普通下载赋予该标签；下例用于解释局部旧规则兼容，不允许覆盖强制策略。

```json
{
  "id": "wl-aliyun-metadata-region-curl",
  "enabled": true,
  "description": "阿里云 metadata region-id 查询，常见于云助手/采集 agent 初始化，不作为攻击告警。",
  "scope": {
    "risk_modules": ["exec"],
    "matched_rules_any": ["download_and_execute"],
    "listener_process": ["sshd"],
    "listener_ports": [22],
    "command_regex": "100\\.100\\.100\\.200/latest/meta-data/region-id"
  },
  "action": "suppress",
  "target_severity": "P3",
  "target_verdict": "benign",
  "target_action": "log_only",
  "reason": "阿里云 metadata region-id 查询白名单"
}
```

## 十、示例 2：LoongCollector 巡检 grep

场景：运维或采集组件检查 `/usr/local/ilogtail/loongcollector` 路径，被命令风险规则识别为可疑 grep。

```json
{
  "id": "wl-ilogtail-loongcollector-grep",
  "enabled": true,
  "description": "LoongCollector/ilogtail 安装或巡检命令，grep 固定路径属于低风险噪声。",
  "scope": {
    "risk_modules": ["exec"],
    "listener_process": ["sshd"],
    "listener_ports": [22],
    "exe_regex": "/usr/bin/grep$",
    "command_regex": "/usr/local/ilogtail/loongcollector"
  },
  "action": "suppress",
  "target_severity": "P3",
  "target_verdict": "benign",
  "target_action": "log_only",
  "reason": "LoongCollector 路径巡检白名单"
}
```

## 十一、临时传入白名单

除默认读取 `whitelist.json` 外，也可以在输入 payload 中临时传入：

```json
{
  "scenario": "S5-EXEC",
  "risk_modules": ["exec"],
  "risk_whitelist": {
    "version": "1.0",
    "defaults": {"enabled": true},
    "rules": []
  },
  "evidence_bundles": {
    "host_exec": []
  }
}
```

支持两个字段名：

- `risk_whitelist`
- `whitelist`

如果 payload 中传入白名单，会优先使用 payload 中的配置。

## 十二、如何验证白名单是否生效

运行风险识别后看三个位置：

1. `summary.alert_suppressed` 是否大于 0。
2. `whitelist_hits[]` 是否包含目标规则 ID。
3. 对应 `risk_items[]` 是否出现：

```json
{
  "whitelisted": true,
  "whitelist_rule_id": "wl-aliyun-metadata-region-curl",
  "alert_required": false,
  "alert_suppressed": true,
  "original_risk": {
    "severity": "P0"
  }
}
```

## 十三、维护规范

白名单规则应遵循：

- `id` 必须稳定、可读，建议使用 `wl-业务-对象-行为` 命名。
- `reason` 必须写清楚人工确认原因，便于审计。
- 优先使用精确匹配条件，不要只按单一命令名放行。
- 新增白名单后，至少用最近一次真实样本跑一遍风险识别验证。
- 白名单只负责“是否告警”，不负责修正规则本身；如果规则长期误报，应优化风险规则。

## 十四、常见问题

### 白名单会不会把证据删掉？

不会。风险项仍然保留在 `risk_items[]`，只是标记 `alert_required=false`。

### 白名单命中后还会进入本地关联吗？

会保留风险项，但白名单会先降级或抑制。跨源攻击链 → 溯源分析 Skill。

### 为什么不要只写 command_regex？

单独命令匹配容易误放行攻击。例如只写 `curl` 会把真实远程下载也放掉。建议同时限定 `matched_rules_any`、`listener_process`、`listener_ports`、目标 URL 或路径。

### 示例文件能直接用于生产吗？

不建议直接用。建议复制成 `whitelist.json` 后，根据实际主机、业务路径、采集组件行为调整规则。
