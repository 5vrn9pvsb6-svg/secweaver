---
name: evidence-fetch
description: >-
  SecWeaver 多源证据取数专用 Skill：经 dataasset + SOPS Vault 拉归一化
  evidence_bundles（SLS/SSH/ES/DB/HTTP/本地文件），不做风险分级、告警确认或溯源拼链。
  适用于 取数、拉日志、拉证据、fetch evidence、为大模型研判准备 payload、取数与判断分离。
---

# 证据取数

SecWeaver Skill：**只取数、不研判** — 输出 `evidence_bundles`，供下游 Skill 或大模型分析。

**不做**：P0-P3 风险分级、告警误报/成功确认、跨主机攻击链叙事、behavior-policy 最终裁决。

机器可读输出契约见 [`output-schema.json`](output-schema.json)。取数结果必须同时
保留 `evidence_bundles`、`fetch_summary` 和 `data_access`。

## 在流水线中的位置

```text
证据取数（本 Skill）  →  evidence_bundles + fetch_summary
        ↓
   开源：prompt-risk-analysis（PROMPT + policy-lite）
   企业：risk-identification（assess.py + JSON 规则）
        ↓
可选：告警确认 | 溯源分析
```

| Skill | 回答的问题 |
|-------|------------|
| **证据取数** | **这次调查能拉到哪些原始日志？** |
| **提示词研判（开源）** | **这些日志如何用提示词研判？** |
| 数据源完整性 | 能不能查？ |
| 风险识别 | 单条日志有没有异常？ |
| 告警确认 | WAF 告警真不真、有没有打成功？ |
| 溯源分析 | 异常如何跨源串成攻击链？ |

## 适用时机

- 运营：「把 192.0.2.91 最近 24 小时的 exec + ssh 日志拉出来」
- Agent 工作流：**先取数，再让大模型按 behavior-policy 裁决**
- 排查 connector / 模板是否正常（再跑研判 Skill）
- 为样例、CI 构造 `-i` 离线 payload

## 前置条件

- 资产已在 `dataasset/` 注册，connector 为 `active`（或明确接受 draft 风险）
- 凭证在 `dataasset/credentials/`，经 SOPS Vault 解析（`local_file` 除外）
- 调查参数至少含 **时间窗**；按场景还需 `host` / `hosts` / `attacker_ip` 等

连通性巡检（不是本 Skill）：[dataasset-connectivity-check](../dataasset-connectivity-check/SKILL.zh-CN.md)

## CLI

```bash
# 指定资产 ID（可多次 --asset-id；无需 --from-bundle / --bundle）
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --asset-id asset-secweaver-host-exec \
  --asset-id asset-secweaver-sys-risk-alert \
  --params '{"hosts":["192.0.2.91"],"time_start":"2026-07-01T17:00:00+08:00","time_end":"2026-07-01T18:00:00+08:00"}' \
  --pretty

# 按资产包 + 场景关联计划取数（整包拉取时用 --from-bundle）
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle bundle-host-risk-default \
  --params '{"hosts":["192.0.2.91","192.0.2.92"],"time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00"}' \
  --pretty

# 只看 fetch 计划，不连 Vault
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --plan-only \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}' \
  --pretty

# dry-run：渲染查询，不解密凭证
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --dry-run \
  --params '{"host":"web-01","time_start":"...","time_end":"..."}'

# 运营可读 Markdown 摘要
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --format markdown \
  --params '{"hosts":["192.0.2.91"],"time_start":"...","time_end":"..."}'

# 附带完整性预检（不阻断取数）
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --include-completeness \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}'

# 回放已有离线证据，不连接数据源
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  -i examples/prompt-risk-analysis/fetch-exec-syslog-mini.json \
  -o /tmp/fetch-offline-replay.json
```

使用 `-i` 输入已完成的 `data_access.fetch_mode=offline` 结果时，保留其证据和原始
取数统计。仅在明确指定 `--fetch` 后才重新查询已配置的 active Connector；
`--plan-only` 和 `--dry-run` 会以新预览替换已有证据。没有资产或资产包范围的
旧预览不可执行。

## 输出 JSON

| 字段 | 含义 |
|------|------|
| `skill` | 固定 `evidence-fetch` |
| `evidence_bundles` | 按 `asset_type` 分组的事件（host_exec、ssh_auth、waf_alert…） |
| `fetch_summary` | 事件总数、分类型统计、fetch 策略 |
| `data_access` | bundle_id、fetch_strategy、fetch_mode |
| `correlation_fetch_plan` | 关联矩阵驱动的任务队列（如有） |
| `completeness_precheck` | 仅 `--include-completeness` 时附带 |

每条事件经 `normalizer` 处理，可含 `evidence_id`、`timestamp`、别名字段。**不得虚构**不在 bundles 中的事件。

## Agent 推荐工作流

**开源（提示词研判）：**

```text
Step 1  fetch_evidence.py --from-bundle --params …
Step 2  读 prompt-risk-analysis/PROMPT.zh-CN.md + policy-lite.zh-CN.md
Step 3  分析 evidence_bundles → 研判报告
Step 4  （可选）assess.py 对照确定性规则输出（Community 已包含）
```

**确定性规则研判（Community 已包含）：**

```text
Step 1  fetch_evidence.py
Step 2  risk-identification/assess.py
Step 3  多主机链 → traceability-analysis
```

## 取数策略

| 策略 | 何时 |
|------|------|
| `host_risk_bundle` | 仅 S5/S5-HOST 且 pattern 为 `S5_host_risk`，直接查询包内全部声明资产，不依赖 D1/WAF 反查 |
| `correlation_fetch_plan` | 资产包有 investigation_scenarios，关联矩阵可生成 plan |
| `bundle_full_fallback` | 无 plan 时按 bundle 内全部资产 + 模板选择 |
| `asset_list` | 指定 `--asset-id` 时 |
| `plan_only` | `--plan-only`，只输出计划 |

支持的 connector：`sls`、`ssh_file`、`local_file`、`database_ro`、`http_api`、`es` 及 extended connectors（见 data-access/fetch.py）。

## 安全要求

溯源和混合场景继续使用关联计划；没有可用计划时，D1 bootstrap 返回空结果不能
阻止完整资产包回退查询。S5 的主机筛查不应因没有 WEB/WAF 数据而跳过主机资产。

- **禁止**向用户输出解密后的 secret、私钥、token
- 可输出 `credentials_ref`、`asset_id`、`connector_id`
- 默认小时间窗；扩大窗口前确认数据量

## 与其他 Skill 的衔接

| 下游 | 传入字段 |
|------|----------|
| **prompt-risk-analysis**（开源） | `evidence_bundles` + `params` + `fetch_summary` |
| risk-identification | `evidence_bundles` + `params` + 可选 `completeness_precheck` |
| alert-confirmation | `primary_alerts` + `correlated_evidence`（由 bundles 映射） |
| traceability-analysis | `evidence_bundles` + `params` + `completeness_precheck` |

映射示例：`correlated_evidence.host_exec` ← `evidence_bundles.host_exec`

## 附加资源

- 数据访问层：[../_shared/data-access/README.zh-CN.md](../_shared/data-access/README.zh-CN.md)
- 样例：[examples.zh-CN.md](examples.zh-CN.md)
- 英文：[SKILL.md](SKILL.md)
