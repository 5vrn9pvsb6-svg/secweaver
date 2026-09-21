# 风险识别样例

## 离线样例

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i src/skills/risk-identification/scripts/input.example.json
```

预期：`overall_verdict=high_risk_detected`，输出 P0/P1 **risk_items**（单事件异常）。

## 输出片段

```json
{
  "overall_verdict": "high_risk_detected",
  "summary": {
    "p0": 2,
    "alert_required": 2,
    "top_incidents": 2
  },
  "recommended_next_skills": []
}
```

跨源攻击链请使用 **traceability-analysis** Skill，不在本 Skill 输出。

## 仅 exec + ssh（不跑 connect）

```json
{
  "risk_modules": ["exec", "ssh"],
  "params": {
    "hosts": ["192.0.2.91", "192.0.2.92"],
    "time_start": "2026-06-01T00:00:00+08:00",
    "time_end": "2026-07-02T23:59:59+08:00",
    "severity_floor": "P2"
  }
}
```

## 对话表述

> 用 **风险识别** 列出 web-01 上的异常 exec/ssh 事件（WebShell、sshpass、暴力破解 burst）。  
> 用 **溯源分析** 关联源主机到目标主机的横向移动与多轮演练叙事。
