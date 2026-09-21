# 证据取数 — 样例

**语言：** [English](examples.md) | 简体中文（本文）

## 1. 主机风险调查取数

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle bundle-host-risk-default \
  --params '{
    "hosts": ["192.0.2.91", "192.0.2.92"],
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00"
  }' \
  --pretty
```

输出 `evidence_bundles.host_exec`、`host_connect`、`ssh_auth` 等，交给大模型或 `assess.py`。

## 2. 外网 IP 溯源取数

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle bundle-incident-trace-default \
  --params '{
    "attacker_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "host": "web-01"
  }' \
  --format markdown
```

## 3. 只拉指定资产

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle \
  --asset-id asset-waf-prod-01 \
  --params '{
    "attacker_ip": "203.0.113.10",
    "time_start": "2026-06-21T14:00:00+08:00",
    "time_end": "2026-06-21T15:00:00+08:00"
  }'
```

## 4. 先看计划再决定是否 live fetch

```bash
# 第一步：计划
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --plan-only \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}' \
  --pretty

# 第二步：确认后 live
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}' \
  --pretty
```

## 5. 开源提示词研判（推荐）

```text
1. evidence-fetch → evidence_bundles
2. 读 prompt-risk-analysis/PROMPT.zh-CN.md + policy-lite.zh-CN.md
3. 分析 evidence_bundles → 研判报告
```

详见 [prompt-risk-analysis/examples.zh-CN.md](../prompt-risk-analysis/examples.zh-CN.md)。

## 6. 确定性规则引擎（Community 已包含，可选对照）

```text
1. evidence-fetch → evidence_bundles
2. risk-identification/assess.py → risk_items + policy_rule_id
```

## 7. 离线 JSON 管道

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --params '{"hosts":["192.0.2.91"],"time_start":"...","time_end":"..."}' \
  -o /tmp/fetch-out.json

python3 src/skills/risk-identification/scripts/assess.py -i /tmp/fetch-out.json
```

`assess.py` 若输入已含 `evidence_bundles` 且带 `--from-bundle` 未重复 fetch，可直接消费（需 payload 含 scenario/params）。
