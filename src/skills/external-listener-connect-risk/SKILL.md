---
name: external-listener-connect-risk
description: >-
  Sub-module of risk-identification: triages active_connect events from
  external listener processes. Detects C2 egress, suspicious ports, and
  exec-correlated outbound connections. Use via risk-identification Skill
  or when analyzing host_connect evidence alone.
---

# External Listener Active Outbound Risk Identification

**Sub-module of risk identification** — analyzes `host_connect` / `active_connect` events.

Rules: [rules.md](rules.md). Orchestration and CLI use parent Skill:

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-external-connect-p0.json \
  -o /tmp/secweaver-connect-risk.json
```

The command uses an offline synthetic sample. To restrict a custom payload, set top-level `"risk_modules": ["connect"]`; it is not a query parameter. For live scoped retrieval, follow the parent [operations handbook](../risk-identification/OPS-HANDBOOK.md).

**Whitelist:** public business egress, known trusted targets, etc. — unified in [../risk-identification/whitelist.json](../risk-identification/whitelist.json); see [../risk-identification/whitelist.md](../risk-identification/whitelist.md).
