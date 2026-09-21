# Trace Profile 设计说明

**语言：** [English](21-trace-profile-design.md) | 简体中文（本文）

> 版本 v1.0 | 2026-07-02  
> 目标：把 `syslog_risk_normalize.py` 与 `tigersec.py` 中最稳定的语义规则迁入 **声明式 JSON**，运营复制模板即可接入同类日志，无需新增 Python adapter。

## 1. 背景

溯源链路里有两类「特化语义」长期绑在 Python：

| 模块 | 语义 | 稳定性 |
|------|------|--------|
| `syslog_risk_normalize.py` | JSON 嵌套拆包、`__source__`→受害主机、syslog→ssh_auth | 高（TigerSec SLS 固定形态） |
| `tigersec.py` | has_tty 会话信号、Web 入口推断、sshpass 横向解析 | 高（audit-port-execmon 固定字段） |

「完全零 Python」的 L0 层要求：**新厂商同类日志只改 asset + trace_profile 配置**，通用引擎解释执行。

## 2. 文件布局

```
dataasset/
  schema/trace-profile.schema.json      # JSON Schema
  trace-profiles/
    secweaver-syslog-risk-alert.json     # syslog_risk_alert 首模板
    secweaver-host-exec.json             # host_exec 首模板
src/skills/_shared/data-access/
  trace_profile.py                      # 通用解释引擎（一次性平台代码）
  syslog_risk_normalize.py            # 薄封装，委托 trace_profile
src/skills/traceability-analysis/scripts/source_adapters/
  tigersec.py                           # 薄封装，委托 trace_profile
```

资产引用方式（二选一或组合）：

```json
{
  "trace_profile_id": "secweaver-host-exec",
  "trace_profile": { "host_identity": { "ip_fields": ["agent_ip"] } }
}
```

- `trace_profile_id` → 加载 `dataasset/trace-profiles/{id}.json`
- 内联 `trace_profile` → 与模板 **深合并** 覆盖

未声明时，按 `asset_type` 回退默认模板（`syslog_risk_alert` / `host_exec`）。

## 3. Schema 能力块

| 块 | 用途 | TigerSec 模板 |
|----|------|---------------|
| `event_repairs` | fetch 后事件修复 | syslog：拆 JSON、补 timestamp、map `__source__` |
| `host_identity` | 受害/来源主机 IP 字段优先级 | 两模板均有 |
| `session_signals` | has_tty / tty → 是否非交互 | host-exec |
| `web_entry_inference` | listener + 命令 → Web 入口推断 | host-exec；listener 列表 **ref** 到 exec-rules / heuristic |
| `lateral_parse` | 命令正则 → 横向目标 IP | host-exec |
| `ssh_auth_derivation` | syslog event_type → ssh_auth bundle | syslog-risk-alert |

### 3.1 外部引用（ref）

避免在 trace_profile 里重复维护 listener 列表：

```json
"web_listeners_ref": "exec-rules.web_listeners",
"ssh_listeners_ref": "heuristic-rules.policy.listener.ssh_listeners",
"web_ports_ref": "heuristic-rules.policy.listener.web_ports"
```

引擎从 `src/skills/risk-identification/rules/exec-rules.json` 与 `heuristic-rules.json` 解析；解析失败时用模板内 `fallback_*`。

### 3.2 event_repairs 步骤类型

| type | 行为 |
|------|------|
| `unwrap_json_in_fields` | 从 content/__line__ 等字段解析 JSON 填平 null 列 |
| `fallback_timestamp` | timestamp 为空时从 `__time__` 等回填 |
| `map_source_to_host` | `__source__` → host_ip/host/_victim_host |

## 4. 运行时接入点

```
SLS fetch → fetch._postprocess_sls_events(asset)
         → repair_syslog_risk_event(row, asset)
         → trace_profile.repair_event

normalize_events → repair_syslog_risk_event(out, asset)  # syslog_risk_alert

correlate / tigersec adapter
         → exec_session_signals / is_web_listener_exec / extract_ssh_lateral_targets
         → trace_profile（profile 来自 asset 或默认模板）

inject_ssh_auth_from_syslog_risk
         → syslog_to_ssh_auth_event → ssh_auth_derivation 块
```

## 5. 运营工作流（新日志形态）

1. **log-format-discovery** 产出 asset（field_aliases、text_parser、schema.fields）
2. 复制最接近的 `dataasset/trace-profiles/*.json`，改 `profile_id`、字段名、必要时改 regex
3. asset 上设置 `"trace_profile_id": "your-vendor-host-exec"`
4. 调 `exec-rules` / `heuristic-rules.policy` / `correlation-matrix`（L1，已有）
5. **无需**新增 `tigersec_*.py`

仍需要 Python 的情况：

- 全新 bundle 类型（平台一次性）
- 关联引擎新 join 语义（matrix 扩展）
- trace_profile schema 尚未覆盖的修复步骤（扩展 schema + 引擎，一次性）

## 6. 最小实现范围（本版）

**已实现：**

- Schema + 两个 TigerSec 模板
- `trace_profile.py` 引擎（repairs / session / web entry / lateral / ssh_auth）
- `syslog_risk_normalize` / `tigersec.py` 委托引擎
- `asset-secweaver-host-exec` / `asset-secweaver-sys-risk-alert` 挂载 `trace_profile_id`
- 单元测试 `tests/test_trace_profile.py`

**刻意未迁（后续）：**

- `infer_initial_access_from_exec_event` 叙事文本（仍在 heuristic `initial_access_exec_inferred`）
- `tigersec_syslog.py` / `tigersec_target_impact.py` 时间窗与阶段映射（已在 heuristic + matrix）
- 自定义 event_repair 类型（如新嵌套格式）需扩 schema

## 7. 验证

```bash
python3 -m unittest discover -s src/skills/_shared/data-access/tests -p 'test_trace_profile.py'
python3 -m unittest discover -s src/skills/traceability-analysis/scripts/tests -p 'test_tigersec*.py'
```

## 8. 与 ops 文档关系

- 配置清单、维护流程和验证边界：[溯源分析运营配置指南](../docs_user/25-traceability-analysis-ops-config-guide.zh-CN.md)
