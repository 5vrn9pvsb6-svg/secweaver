# 溯源分析 — 样例

**跨源测试数据目录**：[examples/traceability/](../../../examples/traceability/)（项目根目录，含 S1 完整链 / 扫描负例 / 打穿无横向）

## 样例 1：S1/S3 公开溯源场景 — WebShell → curl → SSH 横向（完整链）

### 用户输入

```text
选择全部资产
报警时间 2026-06-21 10:00，黑客 IP 203.0.113.10
可能已被打穿，分析第一个攻破点和横向攻击事件
```

### 前置：完整性预检已通过

```json
{
  "overall_verdict": "full_traceable",
  "confidence": 0.88,
  "next_skill_blocked": false
}
```

### 输入

见 [examples/traceability/s1-web-shell-to-ssh-lateral.json](../../../examples/traceability/s1-web-shell-to-ssh-lateral.json)（跨源完整测试数据）或 [scripts/input.example.json](scripts/input.example.json)（精简版）

### 运行关联脚本

```bash
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json
```

### 预期 JSON 摘要

```json
{
  "overall_verdict": "confirmed_intrusion_chain",
  "confidence": 0.88,
  "initial_access": {
    "host": "web-01",
    "vector": "webshell",
    "url": "/upload/shell.php",
    "attacker_ip": "203.0.113.10",
    "evidence_refs": ["waf-001"]
  },
  "attack_chain": [
    {"stage": "initial_access", "host": "web-01", "evidence_refs": ["waf-001"]},
    {"stage": "execution", "host": "web-01", "evidence_refs": ["exec-001", "connect-001"]},
    {"stage": "lateral_movement", "host": "db-01", "evidence_refs": ["ssh-001", "fw-001"]},
    {"stage": "lateral_movement", "host": "app-02", "evidence_refs": ["ssh-002"]}
  ],
  "impacted_assets": [
    {"host": "web-01", "role": "initial_compromise", "priority": "P0"},
    {"host": "db-01", "role": "lateral_target", "priority": "P0"},
    {"host": "app-02", "role": "lateral_target", "priority": "P0"}
  ]
}
```

### 预期 Markdown 片段

```markdown
## 溯源分析报告

**结论**：已确认完整攻击链（置信度 0.88）

### 执行摘要
攻击者 203.0.113.10 于 09:10 通过 WebShell 命中 web-01；09:15 通过 nginx 子进程 curl 下载 sshscan 工具；09:22 起从 web-01(10.0.1.5) SSH 横向至 db-01、app-02。

### 初始入口（第一个攻破点）
- **主机**：web-01
- **时间**：2026-06-21 09:10:05
- **URL**：/upload/shell.php
- **向量**：webshell
- **证据**：waf-001

### 横向移动
- confirmed：web-01 → db-01（root, ssh-001, fw-001）
- confirmed：web-01 → app-02（deploy, ssh-002）
```

---

## 样例 2：预检 blocked — 不得 confirmed

### completeness_precheck

```json
{
  "overall_verdict": "not_traceable",
  "next_skill_blocked": true,
  "block_reason": "缺少 P0 数据源: host_exec"
}
```

### 预期

```json
{
  "overall_verdict": "insufficient_evidence",
  "blocked": true,
  "attack_chain": [],
  "summary": "数据源预检未通过，无法开展可靠溯源"
}
```

Claw 不得输出「已确认打穿」或横向结论。

---

## 样例 3：仅 WAF — scanning_or_attempt_only

测试数据：[examples/traceability/s1-scan-only-no-host-exec.json](../../../examples/traceability/s1-scan-only-no-host-exec.json)

### evidence_bundles

仅含 `waf_alert`，无 `host_exec`。

### 预期

```json
{
  "overall_verdict": "scanning_or_attempt_only",
  "initial_access": {"host": "web-01", "vector": "webshell"},
  "attack_chain": [{"stage": "initial_access"}],
  "hypotheses": [
    {"text": "存在 WEB 入口迹象，但未发现主机命令执行证据，无法确认打穿"}
  ]
}
```

---

## 样例 4：打穿但无横向 — initial_access_only

测试数据：[examples/traceability/s2-initial-access-no-lateral.json](../../../examples/traceability/s2-initial-access-no-lateral.json)

### evidence

- waf + exec + connect，无 ssh Accepted

### 预期

```json
{
  "overall_verdict": "initial_access_only",
  "hypotheses": [
    {"text": "已发现主机执行/下载行为，但未发现 SSH Accepted 横向成功记录"}
  ],
  "recommended_actions": [
    "立即隔离初始受害主机: web-01",
    "保全 WEB 与 SSH 相关日志"
  ]
}
```

---

## 样例 5：SSH 覆盖不全 — partial

### completeness_precheck

```json
{
  "overall_verdict": "partial_traceable",
  "confidence": 0.72,
  "data_gaps": ["ssh_auth coverage partial"]
}
```

### 输出要求

- `summary` 使用「**至少**横向至 db-01」
- `impacted_assets[].note`: 「SSH 日志覆盖不全，可能遗漏」
- `confidence` ≤ 0.72

---

## 样例 6：从告警确认进入溯源

### 上游告警确认结论

```json
{
  "verdict": "confirmed_attack",
  "attack_success": true,
  "alert_id": "WAF-001"
}
```

### 用户

「这条告警已确认真实攻击成功，帮我查完整攻击链和横向范围」

### Claw 行为

1. 将 WAF 告警与关联 exec/connect 填入 `evidence_bundles`
2. 运行溯源六步流程
3. 不在此重复误报研判
