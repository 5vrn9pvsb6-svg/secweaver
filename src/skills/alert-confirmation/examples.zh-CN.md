# 告警确认 — 样例

## 样例 1：S4 公开告警确认场景 — SQLi blocked，无 D2

### 用户输入

```text
选择 WEB 安全告警资产
分析今天 IP 203.0.113.10 的安全报警
确认尝试攻击/真实攻击/误报，真实则看是否成功
```

### 运行

```bash
python3 src/skills/alert-confirmation/scripts/confirm.py \
  -i src/skills/alert-confirmation/scripts/input.example.json
```

### 预期

```json
{
  "alert_verdict": "confirmed_attack",
  "attack_type": "sqli",
  "attack_outcome": "blocked",
  "attack_success": false,
  "next_skill": null,
  "data_gaps_impact": ["无 host_exec/connect/file_op，无法确认是否打穿"]
}
```

Claw 必说：**无法确认是否攻击成功**，建议接入 audit-port-execmon。

---

## 样例 2：真实攻击 + 成功（移交溯源）

### 输入

`scripts/input.example.success.json`

### 预期

```json
{
  "alert_verdict": "confirmed_attack",
  "attack_outcome": "success_confirmed",
  "attack_success": true,
  "recommended_action": "escalate_investigate",
  "next_skill": "traceability_analysis",
  "evidence": {
    "success_proof": ["exec-101", "connect-101"]
  }
}
```

---

## 样例 3：误报 — 业务 UUID

### primary_alert

```json
{
  "alert_id": "WAF-FP-001",
  "rule_name": "Generic Attack",
  "payload": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "url": "/order/detail",
  "action": "logged"
}
```

### 预期

- alert_verdict: `false_positive`
- attack_outcome: `not_applicable`
- recommended_action: `close_as_fp`

---

## 样例 4：无 payload — suspicious

### primary_alert

```json
{
  "alert_id": "WAF-NP-001",
  "rule_id": "990001",
  "rule_name": "Generic Anomaly",
  "url": "/admin",
  "payload": "",
  "action": "logged"
}
```

### 预期

- alert_verdict: `suspicious` 或 `scanning_or_probe`
- attack_outcome: `success_unknown`
- 不得 confirmed_attack

---

## 样例 5：批量降噪

### 输入

```json
{
  "batch_mode": true,
  "primary_alerts": [ "...50条..." ],
  "correlated_evidence": {}
}
```

### 输出结构

```json
{
  "results": [ "...逐条 alert_confirmation..." ],
  "batch_summary": {
    "alert_type": "alert_confirmation_batch_summary",
    "total": 50,
    "false_positive": 20,
    "confirmed_attack": 10,
    "success_confirmed": 2
  }
}
```

---

## 样例 6：alert_triage_only 预检

### completeness_precheck

```json
{
  "overall_verdict": "alert_triage_only",
  "confidence": 0.55
}
```

### 约束

- confirmation_mode: `triage_only`
- 即使有 exec 也不得在 triage_only 模式输出 success_confirmed（脚本强制）
- 第二层最高 success_unknown

---

## 样例 7：与风险识别协作

告警后存在 exec 事件时，Claw 可：

1. 本 Skill 判 success_confirmed
2. 调用 **external-listener-cmd-risk** 对 exec-101 做 P0-P3 分级
3. 将 risk 结果写入 `evidence.supporting`

---

## 禁止输出示例

| 场景 | 错误 | 正确 |
|---|---|---|
| 无 D2 | 「已打穿服务器」 | success_unknown |
| 无 payload | 「确认 SQL 注入成功」 | suspicious + 规则命中 |
| false_positive | success_confirmed | not_applicable |
