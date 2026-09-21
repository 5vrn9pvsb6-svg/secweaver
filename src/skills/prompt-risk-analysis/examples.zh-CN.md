# 提示词研判 — 样例

**语言：** [English](examples.md) | 简体中文（本文）

与 [evidence-fetch/examples.zh-CN.md](../evidence-fetch/examples.zh-CN.md) 衔接：**只取数，再由资深专家 AI 研判**（本 Skill 无 Python）。

## 0. 离线黄金路径（无需 Vault）

```text
examples/prompt-risk-analysis/fetch-exec-syslog-mini.json
examples/prompt-risk-analysis/report-exec-syslog-mini.zh-CN.md  ← 期望叙事对照

examples/prompt-risk-analysis/fetch-waf-bypass-mini.json
examples/prompt-risk-analysis/report-waf-bypass-mini.json       ← 严格 Schema 对照
examples/prompt-risk-analysis/report-waf-bypass-mini.zh-CN.md   ← WAF 漏过叙事对照
```

Agent：

1. 读 `PROMPT.zh-CN.md` + `analysis-contract.zh-CN.md` + `correlation-cheatsheet.zh-CN.md`
2. 分析 mini fetch 中的 `evidence_bundles`
3. 输出报告，检查是否含 **attack_status**、**chain_coverage**、**evidence_id**、**join_refs**、**fetch_next**；S4 还须含 **waf_coverage**

详见 [examples/prompt-risk-analysis/README.zh-CN.md](../../../examples/prompt-risk-analysis/README.zh-CN.md)。

## 1. 主机 exec + syslog（live 取数）

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle \
  --asset-id asset-secweaver-host-exec \
  --asset-id asset-secweaver-sys-risk-alert \
  --params '{
    "hosts": ["192.0.2.91", "192.0.2.92"],
    "time_start": "2026-06-20T00:00:00+08:00",
    "time_end": "2026-07-03T23:59:59+08:00"
  }' \
  -o /tmp/fetch-exec-syslog.json
```

Agent 随后：

1. 读 `PROMPT.zh-CN.md` + **`analysis-contract.zh-CN.md`** + `correlation-cheatsheet.zh-CN.md`
2. 分析 `/tmp/fetch-exec-syslog.json` 中的 `evidence_bundles`；`policy-lite` 可选
3. 事件过多时抽样，报告含 **chain_coverage**、**join_refs**、**fetch_next**
4. 输出 Markdown 报告 + 可选 JSON（`output-schema.json`）

## 2. 离线样例（任意 fetch JSON）

使用任意含 `evidence_bundles` 的 fetch JSON；证据引用必填。

## 3. Agent 伪代码

```text
1. evidence-fetch（或读取 fetch JSON / mini 离线包）
2. PROMPT.zh-CN.md + analysis-contract.zh-CN.md + correlation-cheatsheet.zh-CN.md
3. 分析 evidence_bundles（policy-lite 仅参考）
4. 报告：attack_status + chain_coverage + evidence_id + join_refs + fetch_next + 攻击叙事
```

## 4. 大流量抽样

当 `fetch_summary.total_events` 很大时：

- 按 `params.hosts`、时间窗划定范围；
- 优先深读 Web 进程 shell、shadow、sshpass、account_created；
- 写明：`共 N 条，深入分析 M 条及依据`。

## 5. 报告片段示例

- **P0**：nginx:80 子进程读 shadow（T1505.003 / T1003.008）；join_refs 可空或标注同主机 exec。
- **P0**：nginx → 92 sshpass 远程读 shadow；join_refs: `lateral_from_exec`, window `lateral_movement`。
- **fetch_next**：补拉 `host_connect`（join `d2_exec_connect_same_listener`），bundle `bundle-host-risk-default`。
