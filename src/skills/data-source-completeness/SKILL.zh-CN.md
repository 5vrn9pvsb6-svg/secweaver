---
name: data-source-completeness
description: >-
  Assesses whether registered security data sources are sufficient for incident
  traceability and alert confirmation. Maps investigation scenarios to required
  data domains, evaluates coverage/keys/time/granularity, and outputs missing
  source recommendations with collection hints. Use when investigating whether
  data is complete for溯源, traceability, lateral movement, WEB breach analysis,
  数据源完整性, missing logs, C2 通信, beacon, DGA, 你缺少什么数据,
  or before starting SecWeaver
  traceability or alert confirmation skills.
---

# 数据源完整性分析

SecWeaver Skill：在**溯源调查 / 告警深度确认**前，评估已注册数据资产是否完整，并给出接入建议。

**定位**：调查前的「数据体检」—— 先告诉安全同学「能查到什么程度、缺什么、先接什么」，再决定是否启动溯源或告警确认。

机器可读输出契约见 [`output-schema.json`](output-schema.json)。输出同时携带共享的
`contract_version` 和规范 `skill` 字段。

## 适用时机

- 用户发起溯源前问「数据够不够」「缺什么」「你缺少什么数据告诉我」
- 已知攻击 IP/时间，要查打穿点与横向范围
- WEB 告警确认前，判断能否证明「攻击成功 / 打穿」
- 对话框**已选择数据资产**后，运行溯源/告警确认 Skill **之前**的预检

## 适用输入

```json
{
  "investigation_intent": "外网攻击IP溯源，查第一个攻破点和横向范围",
  "scenarios": ["S1", "S3"],
  "params": {
    "attacker_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "hosts": ["web-01"],
    "alert_id": "optional"
  },
  "registered_assets": [
    {
      "asset_id": "web_waf",
      "name": "WEB WAF 告警",
      "type": "waf_alert",
      "domain": "D1",
      "fields": ["src_ip", "timestamp", "url", "payload", "action"],
      "coverage": ["web_zone"],
      "retention_days": 30
    }
  ]
}
```

- `registered_assets`：用户在对话框**已选择的数据资产**；未注册或 `status=not_registered` 视为 `missing`
- `scenarios` 可省略，从 `investigation_intent` 推断（见下表）
- `fields` 表示源侧字段；`field_aliases`、`canonical_fields`、`effective_fields` 可由 `registry.asset_to_registered()` 自动补充
- 平台可调用 `src/skills/data-source-completeness/scripts/check.py` 做确定性评估，Claw 在此基础上补充自然语言解释

## 场景识别

| ID | 场景 | 典型关键词 |
|---|---|---|
| S1 | 外网攻击 IP 溯源 | 外网、攻击IP、黑客IP、溯源、打穿、攻破点 |
| S2 | WEB 入侵溯源 | WebShell、WEB入侵、网站被黑、漏洞利用 |
| S3 | 横向移动调查 | 横向、内网扩散、跳板、暴力破解横向 |
| S4 | WEB 告警确认 | 告警确认、误报、WAF告警、真实攻击、有没有打穿 |
| S5 | 主机异常行为 | 监听进程、命令执行、exec、connect、对外端口 |
| S6 | 账号失陷 | 账号、登录异常、VPN、暴力破解 |
| S7 | 数据外传 | 数据外传、泄露、大量下载 |
| S8 | C2 通信检测 | C2、C&C、回连、反弹 Shell、beacon、DGA |

可多选。例：「WAF 告警 + 怀疑横向」→ `["S2","S3","S4"]`，合并 P0 需求后取最严格结论。

完整矩阵见 [scenarios.json](scenarios.json) 与 [rules.md](rules.md)。

## 研判流程

按顺序执行，不要跳步：

```text
1. 识别场景 S1-S8（显式 scenarios 或从 investigation_intent 推断）
2. 读取 registered_assets 与 params（IP、时间、主机、alert_id）
3. 合并多场景 P0/P1/P2 需求（去重，见 scenarios.json）
4. 逐项评估每个需求：
   - ready：已注册 + 必需 fields 齐全 + coverage 全量 + retention 覆盖时间窗
   - partial：已注册但 coverage/fields/retention 不足
   - missing：未注册或无覆盖
   - 字段完整性必须调用共享 `field_inventory.check_required_fields()`，按 `effective_fields = raw fields + canonical fields` 判定；不得只看 `asset.fields`
5. 评估关联键：src_ip、host、timestamp、user、pid 跨源可用数 ≥3
6. 评估时间窗：默认 [告警时间-24h, +6h]；retention 不足 → partial
7. 计算 overall_verdict、confidence、can_trace、can_confirm_breach
8. 生成 missing_critical + recommendations（rank 排序，含 collection_hint）
9. 决定 next_skill 与 next_skill_blocked（任一 P0 missing → blocked）
10. 输出 JSON + 用户可读 Markdown 摘要
```

## 数据域 D1-D7

| 域 | 含义 |
|---|---|
| D1 | 边界与 WEB（WAF、CDN、WEB 日志） |
| D2 | 主机行为（exec、connect、file、EDR） |
| D3 | 认证访问（SSH、VPN、AD、堡垒机） |
| D4 | 网络（防火墙、NetFlow、DNS、代理） |
| D5 | 安全告警（IDS、SOC） |
| D6 | 资产配置（CMDB、漏洞） |
| D7 | 应用业务日志 |

## 整体结论

| overall_verdict | 含义 | next_skill |
|---|---|---|
| `full_traceable` | P0 齐全，P1≥80% ready | 可启动溯源 |
| `partial_traceable` | P0 齐全，P1 部分缺 | 可溯源，标注置信度上限 |
| `not_traceable` | P0 缺失 | **blocked**，先补数据 |
| `alert_triage_only` | 仅 D1/D5，无 D2 | 只能告警分类，不能证明打穿 |

### confidence 计算

```text
confidence = 0.40×P0_ready率 + 0.35×P1_ready率 + 0.15×关联键得分 + 0.10×时间窗得分
关联键 < 3 项 → confidence 上限 0.75
```

## 输出格式

### 1. 结构化 JSON（必出）

```json
{
  "alert_type": "data_source_completeness",
  "scenario": ["S1", "S3"],
  "scenario_summary": "外网攻击 IP 溯源 + 横向移动调查",
  "overall_verdict": "not_traceable",
  "confidence": 0.38,
  "can_trace": false,
  "can_confirm_breach": false,
  "summary": "中文一句话：能查什么、不能查什么",
  "requirements_evaluated": [],
  "registered_sources": [],
  "missing_critical": [],
  "recommendations": [],
  "next_skill": "traceability_analysis",
  "next_skill_blocked": true,
  "block_reason": "缺少 P0 数据源: WEB 服务器进程命令执行"
}
```

### 字段约束

| 字段 | 要求 |
|---|---|
| `can_confirm_breach` | 仅适用于 S1/S2/S4，且至少需 D1 + D2（exec 或 connect）才可 true |
| `missing_critical` | 所有 P0/P1 且 status=missing 的项 |
| `recommendations` | 每条含 rank、priority、reason、impact_if_missing、collection_hint、expected_gain |
| `next_skill_blocked` | 任一 P0 missing 必须为 true |
| `block_reason` | blocked 时必填，说明缺哪些 P0 |

### recommendations 接入话术（SecWeaver 工具）

| asset_type | collection_hint |
|---|---|
| `host_exec` | Linux 部署 audit-port-execmon，whitelist_ports 监控对外端口进程 exec |
| `host_connect` | audit-port-execmon 开启 monitor_connect |
| `host_file_op` | audit-port-execmon 开启 monitor_file_ops |
| `ssh_auth` | rsyslog 采集 auth.log，保留 src_ip、user、result |
| `waf_alert` | WAF API/syslog，**必须含 payload** |

### 2. 用户可读 Markdown（必出）

对话框中除 JSON 外，用以下结构回复用户：

```markdown
## 数据源完整性评估

**场景**：{scenario_summary}
**结论**：{overall_verdict 中文}（置信度 {confidence}）
**能否溯源**：{是/否，部分} | **能否确认打穿**：{是/否}

### 已就绪
- {asset_name}：{一句话说明能支撑什么}

### 关键缺口
1. **{source_name}**（{priority}）
   - 缺了会导致：{impact_if_missing}
   - 建议接入：{collection_hint}

### 下一步
{若 blocked：请先接入上述 P0 数据源后再启动溯源}
{若未 blocked：可启动 **{next_skill}** Skill}
```

## 关键规则（SecWeaver 场景要求对齐）

### S1 外网 IP 溯源 P0

- WAF/WEB 日志 + **WEB 主机 exec** + SSH auth

**缺 exec 时必须明确说**：

> 无法确认 WebShell、curl/wget 下载 SSH 工具，**无法证明打穿**

### S4 WEB 告警确认

- P0：WAF 含 payload + WEB 访问日志
- 无 D2 → `can_confirm_breach=false`，不得输出「已打穿」

### 禁止结论

| 数据状态 | 禁止 |
|---|---|
| 无 host_exec/connect | 「已确认打穿」「已成功注入」 |
| 无 ssh_auth 全集 | 「已确认横向到 X 台」（应说「可能遗漏」） |
| 仅 WAF 无 payload | 「真实 SQL 注入成功」 |

## 与下游 Skill 衔接

| 场景 | next_skill | 放行条件 |
|---|---|---|
| S1/S2/S3 | `traceability_analysis` | P0 齐全 |
| S4 | `alert_confirmation` | P0 齐全 |
| S5 | `risk-identification` | host_exec ready |
| S8 | `risk-identification` | host_connect ready |
| P0 缺失 | 无 | blocked=true |

## 禁止事项

- 数据不足时不得给出「已确认打穿 / 已确认横向到 X」类结论
- 不得省略 `impact_if_missing` 和 `collection_hint`
- 不得把未注册资产当作 ready
- P0 缺失时 `next_skill_blocked` 必须为 true
- 不得跳过「关键缺口」直接启动溯源

## 与 dataasset / SOPS Vault

本 Skill **不接触明文密钥**。资产来自 [`dataasset/`](../../../dataasset/)，凭证仅 `credentials_ref`（本地 SOPS Vault 解密）。

**推荐流程**：

```bash
# 内置 --from-bundle：自动读 dataasset + 可选 Vault 拉证据
python3 src/skills/data-source-completeness/scripts/check.py \
  --from-bundle \
  --params '{"attacker_ip":"203.0.113.10"}'

# 或 prepare 仅生成输入 JSON
python3 src/skills/_shared/data-access/prepare.py \
  --bundle bundle-incident-trace-default \
  --params '{"attacker_ip":"203.0.113.10"}' --run-skill completeness --pretty
```

- 资产包：`dataasset/bundles/bundle-incident-trace-default.json`、`bundle-alert-confirm-min.json`
- Vault 配置：`dataasset/credentials/README.md`
- 数据访问层：[`_shared/data-access/README.md`](../_shared/data-access/README.md)

Claw 在对话中**只引用** `asset_id` / `credentials_ref`；解密与查库由 `fetch.py` 在平台侧完成。

## 附加资源

- 平台文档：[docs_user/15-data-source-completeness.md](../../../docs_user/15-data-source-completeness.md)
- 设计说明：[docs_dev/13-data-source-completeness-skill-design.md](../../../docs_dev/13-data-source-completeness-skill-design.md)
- 需求矩阵：[rules.md](rules.md)
- 场景 JSON：[scenarios.json](scenarios.json)
- 评估脚本：[scripts/check.py](scripts/check.py)
- 数据访问层：[../_shared/data-access/prepare.py](../_shared/data-access/prepare.py)
- 样例：[examples.md](examples.md) | 测试数据：[examples/data-source-completeness/](../../../examples/data-source-completeness/)
