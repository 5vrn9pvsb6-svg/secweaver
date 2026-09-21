# 数据源完整性 — 测试数据

离线 `registered_assets` 列表，模拟已注册数据资产，评估调查场景（S1/S4 等）是否满足溯源或告警确认前置条件。

## 场景列表

| 文件 | 场景 | 预期 overall_verdict | 说明 |
|---|---|---|---|
| [s1-full-traceable.json](s1-full-traceable.json) | S1 外网 IP 溯源 | `full_traceable` | 9 类资产齐全 |
| [s1-not-traceable-missing-exec.json](s1-not-traceable-missing-exec.json) | S1 缺 host_exec | `not_traceable` | `next_skill_blocked: true` |
| [s4-alert-triage-only.json](s4-alert-triage-only.json) | S4 仅 WAF/WEB | `alert_triage_only` | 无法确认打穿 |
| [s4-partial-missing-connect.json](s4-partial-missing-connect.json) | S4 缺 connect | `partial_traceable` | P0 齐、P1 缺口 |
| [s6-full-traceable.json](s6-full-traceable.json) | S6 账号失陷数据源齐备 | `full_traceable` | 只表示可调查，不证明失陷 |
| [s6-not-traceable-missing-auth.json](s6-not-traceable-missing-auth.json) | S6 缺认证日志 | `not_traceable` | P0 缺口阻断下游分析 |
| [s7-full-traceable.json](s7-full-traceable.json) | S7 外传数据源齐备 | `full_traceable` | 仍须读取实际事件 |
| [s7-partial-missing-traffic-volume.json](s7-partial-missing-traffic-volume.json) | S7 缺流量体量 | `partial_traceable` | 无法确认传输体量 |

## 运行

```bash
python3 src/skills/data-source-completeness/scripts/check.py \
  -i examples/data-source-completeness/s1-full-traceable.json
```

## 技能链

```text
data-source-completeness（本目录）
    ├── full/partial → alert-confirmation / traceability / risk-identification
    └── not_traceable → 补齐资产后再跑下游 Skill
```

## 相关

- Skill：`src/skills/data-source-completeness/SKILL.md`
- 场景定义：`src/skills/data-source-completeness/scenarios.json`
