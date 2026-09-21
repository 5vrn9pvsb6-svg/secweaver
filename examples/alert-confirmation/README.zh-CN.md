# 告警确认 — 测试数据

离线 `primary_alerts` + `correlated_evidence`，用于验证两层研判：真实性（`alert_verdict`）与是否成功（`attack_outcome`）。

## 场景列表

| 文件 | 场景 | 预期 alert_verdict | 预期 attack_success |
|---|---|---|---|
| [s4-sqli-blocked-no-breach.json](s4-sqli-blocked-no-breach.json) | SQLi 被 WAF 拦截 | `confirmed_attack` | `false` |
| [s4-webshell-attack-success.json](s4-webshell-attack-success.json) | WebShell + D2 exec/connect | `confirmed_attack` | `true` |
| [s4-false-positive-uuid-param.json](s4-false-positive-uuid-param.json) | UUID 业务参数误报 | `false_positive` | `false` |
| [s4-scanner-generic-no-payload.json](s4-scanner-generic-no-payload.json) | 扫描器/generic 无 payload | `scanning_or_probe` | `false` |
| [s4-batch-mixed-with-query-gap.json](s4-batch-mixed-with-query-gap.json) | 混合批次且主机查询失败 | 误报、扫描、确认攻击各 1 条 | 均为 `false`；查询保持不完整 |

## 运行

```bash
python3 src/skills/alert-confirmation/scripts/confirm.py \
  -i examples/alert-confirmation/s4-webshell-attack-success.json
```

## 技能链

- 成功确认（`attack_success: true`）→ 可衔接 [examples/traceability/](../traceability/)
- 前置完整性参考 [examples/data-source-completeness/](../data-source-completeness/)

## 相关

- Skill：`src/skills/alert-confirmation/SKILL.md`
- 误报模式：`fp-patterns.json` | 攻击类型：`attack-types.json`
