---
name: log-format-discovery
description: >-
  LLM-powered log format discovery for dataasset assets with status=discovery.
  Run discover.py with --asset-id on the discovery queue, then use Agent/LLM
  to map fields and update that asset before promoting to draft/active.
  Use for 新日志格式, 字段映射, format discovery, discovery 状态数据源,
  or when a dataasset asset is in discovery status.
---

# 格式发现（Log Format Discovery）

**大模型驱动**的接入工作流：只处理 dataasset 中 **`status: discovery`** 的数据源；由 `discover.py` 加载该资产 + 样本分析，再由 **AI Agent（大模型）** 完成字段映射，最后更新该资产并 `discovery → draft → active`。

**定位**：格式发现队列的专用 Skill。**draft / active / disabled 资产不由本 Skill 处理**。

> 架构与设计见 [docs_dev/20-log-format-discovery-design.md](../../../docs_dev/20-log-format-discovery-design.md)；使用说明见 [docs_user/20-log-format-discovery.md](../../../docs_user/20-log-format-discovery.md)。

## dataasset `discovery` 状态（必读）

| status | 本 Skill | 对话框可选 | 说明 |
|---|---|---|---|
| `discovery` | **处理** | 否 | 格式发现队列，待映射 |
| `draft` | 不处理 | 否 | 映射完成、编辑中 |
| `active` | 不处理 | 是 | 已发布 |
| `disabled` | 不处理 | 否 | 停用 |

接入新 log 类型时：**先在 `dataasset/assets/` 注册资产并设 `status: discovery`**，再跑本 Skill。

## 工作流

```text
1. dataasset 注册 asset + connector，status=discovery
2. discover.py --asset-id <id> + 样本 → 报告 + llm_prompt
3. 【必需·大模型】Agent 产出映射 JSON，更新该 discovery 资产
4. 用户确认 → status 改为 draft → validate → active
```

### Step 0 — 查看发现队列

```bash
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery
```

### Step 1 — 对 discovery 资产跑预处理

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i samples.jsonl \
  --pretty -o /tmp/discovery.json \
  --prompt /tmp/discovery-prompt.md \
  --preview-normalize
```

`asset_type`、`connector_type` 从 dataasset 自动读取，**无需** `--asset-type`。

### Step 2 — 【必需·大模型】审阅报告

报告关键字段：

| 字段 | 用途 |
|---|---|
| `dataasset_context.discovery_asset` | 当前 discovery 资产注册信息 |
| `discovery_asset_hints` | 已有 fields / template_ids |
| `detected_format` / `gap_analysis` | 格式与缺口 |
| `llm_prompt` | 大模型任务说明 |

### Step 3 — 落地（仅改 dataasset 配置，不改 Python）

1. 默认写 `asset.field_aliases`；只有审阅确认是通用映射时才写全局别名
2. **`text_parser`** — 内置 id（`syslog_auth` / `nginx_combined` / `json_lines`）或 `dataasset/parsers/*.json`
3. **`dataasset/assets/{asset_id}.json`** — 更新 schema、template_ids、masking
4. `status`: `discovery` → `draft` → `active`
5. `validate.py` + `test_connector.py`

详见[字段发现与归一化模型](../../../docs_user/20-log-format-discovery.zh-CN.md#字段发现与归一化模型)。

## 不适用

不符合发现条件的资产（例如已 active）会收到明确的 CLI 参数错误，退出码为 2，
不再显示 Python 调用栈。此行为不绕过 discovery 状态门禁，也不自动改变资产状态。

- `status` 为 draft / active / disabled 的资产（直接改 normalizer 或模板）
- 未在 dataasset 注册、无 discovery 状态的裸样本（须先建 discovery 资产）
- 期望通过改 `ssh_fetch.py` 接入 text 日志（应改 `text_parser` 配置）

## 参考

- [docs_user/03-configure-data-sources.zh-CN.md](../../../docs_user/03-configure-data-sources.zh-CN.md) — 完整接入生命周期
- [docs_user/20-log-format-discovery.zh-CN.md](../../../docs_user/20-log-format-discovery.zh-CN.md) — 字段发现与归一化
- [docs_user/16-data-source-onboarding-faq.zh-CN.md](../../../docs_user/16-data-source-onboarding-faq.zh-CN.md) — 短问答
- [docs_dev/20-log-format-discovery-design.md](../../../docs_dev/20-log-format-discovery-design.md)
- [reference.md](reference.md) | [examples.md](examples.md) | 样本：[examples/log-format-discovery/](../../../examples/log-format-discovery/)
- `dataasset/README.md` — status 字段说明
