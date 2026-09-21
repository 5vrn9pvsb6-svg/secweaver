---
name: external-listener-connect-risk
description: >-
  Sub-module of risk-identification: triages active_connect events from
  external listener processes. Detects C2 egress, suspicious ports, and
  exec-correlated outbound connections. Use via risk-identification Skill
  or when analyzing host_connect evidence alone.
---

# 对外监听进程主动外连高危识别

**风险识别** 的子模块，分析 `host_connect` / `active_connect` 事件。

规则见 [rules.md](rules.md)。编排与 CLI 请使用上级 Skill：

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-external-connect-p0.json \
  -o /tmp/secweaver-connect-risk.json
```

上述命令使用离线合成样例。自定义 payload 时在顶层设置 `"risk_modules": ["connect"]` 限制模块，不要放在查询 params 中。真实数据取数见上级[运营手册](../risk-identification/OPS-HANDBOOK.zh-CN.md)。

**白名单**：公网业务外连、已知可信目标等，统一维护 [../risk-identification/whitelist.json](../risk-identification/whitelist.json)，说明见 [../risk-identification/whitelist.md](../risk-identification/whitelist.md)。
