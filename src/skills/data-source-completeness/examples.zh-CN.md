# 数据源完整性分析 — 样例

## 样例 1：SecWeaver 场景要求 — 外网 IP 溯源（数据不足）

### 用户输入

```text
选择全部资产
报警时间 2026-06-21 10:00，黑客 IP 203.0.113.10
可能已被打穿，查第一个攻破点和横向范围
你缺少什么数据告诉我
```

### 已注册资产

```json
{
  "registered_assets": [
    {"asset_id": "waf_01", "type": "waf_alert", "domain": "D1", "fields": ["src_ip", "timestamp", "url", "payload"], "coverage": ["web_zone"]},
    {"asset_id": "ssh_logs", "type": "ssh_auth", "domain": "D3", "fields": ["host", "src_ip", "user", "result", "timestamp"], "coverage": ["partial_internal"]},
    {"asset_id": "cmdb", "type": "asset_inventory", "domain": "D6", "coverage": ["full"]}
  ]
}
```

### 预期输出（摘要）

```json
{
  "alert_type": "data_source_completeness",
  "scenario": ["S1", "S3"],
  "overall_verdict": "not_traceable",
  "confidence": 0.38,
  "can_trace": false,
  "can_confirm_breach": false,
  "summary": "已有 WAF 告警与部分 SSH 日志，但缺少 WEB 服务器主机行为数据（exec/connect），无法确认是否打穿及是否下载横向工具；SSH 覆盖不全，横向结论可能遗漏。",
  "missing_critical": [
    {
      "source_name": "WEB 服务器进程命令执行",
      "domain": "D2",
      "priority": "P0",
      "impact_if_missing": "无法确认 WebShell、curl/wget 下载 SSH 暴力破解工具，不能证明攻击成功"
    },
    {
      "source_name": "WEB 服务器主动外连",
      "domain": "D2",
      "priority": "P1",
      "impact_if_missing": "无法关联下载域名与 C2，攻击链缺少外连证据"
    }
  ],
  "recommendations": [
    {
      "rank": 1,
      "source_name": "WEB 服务器进程命令执行",
      "priority": "P0",
      "collection_hint": "在 WEB 服务器部署 audit-port-execmon，监控 80/443 对应进程 exec",
      "expected_gain": "可确认打穿、命令执行链、下载行为"
    },
    {
      "rank": 2,
      "source_name": "WEB 服务器主动外连",
      "priority": "P1",
      "collection_hint": "audit-port-execmon 开启 monitor_connect",
      "expected_gain": "可看到下载工具的外连目标 IP/端口"
    },
    {
      "rank": 3,
      "source_name": "内网 SSH 认证日志全集",
      "priority": "P0",
      "collection_hint": "补全 ssh_auth 覆盖至全部内网 Linux 服务器",
      "expected_gain": "横向移动范围完整，避免漏报"
    },
    {
      "rank": 4,
      "source_name": "内网防火墙流量",
      "priority": "P1",
      "collection_hint": "接入 WEB 网段到内网 SSH 网段的防火墙 syslog",
      "expected_gain": "可视化 WEB→内网 SSH 连接路径与时间"
    }
  ],
  "next_skill": "traceability_analysis",
  "next_skill_blocked": true,
  "block_reason": "缺少 P0 数据源: host_exec（WEB 服务器）"
}
```

### Claw 应对用户说

> 当前 WAF 能看到 203.0.113.10 的攻击请求，但**没有 WEB 服务器上的命令执行日志**，因此无法确认是否已打穿、是否执行了 curl 下载 SSH 工具。  
> SSH 日志只覆盖了部分内网主机，横向范围可能不完整。  
> **建议优先接入**：WEB 服务器 exec（audit-port-execmon）→ WEB 服务器 connect → 补全 SSH 日志覆盖。

---

## 样例 2：外网 IP 溯源（数据基本完整）

### 已注册资产

```json
{
  "registered_assets": [
    {"asset_id": "waf_01", "type": "waf_alert", "coverage": ["web_zone"], "fields": ["src_ip", "timestamp", "url", "payload"]},
    {"asset_id": "web_exec", "type": "host_exec", "coverage": ["web-01"], "fields": ["host", "command", "timestamp", "pid"]},
    {"asset_id": "web_connect", "type": "host_connect", "coverage": ["web-01"], "fields": ["dst_ip", "dst_port", "timestamp"]},
    {"asset_id": "ssh_all", "type": "ssh_auth", "coverage": ["full"], "fields": ["host", "src_ip", "user", "result", "timestamp"]},
    {"asset_id": "fw_01", "type": "firewall_log", "coverage": ["dmz_to_internal"]}
  ]
}
```

### 预期输出（摘要）

```json
{
  "overall_verdict": "full_traceable",
  "confidence": 0.88,
  "can_trace": true,
  "can_confirm_breach": true,
  "summary": "WAF、WEB 主机 exec/connect、全网 SSH 与 DMZ 防火墙均已接入，可支撑外网 IP 溯源与横向移动分析。",
  "missing_critical": [],
  "recommendations": [
    {
      "rank": 1,
      "source_name": "WEB 服务器文件操作",
      "priority": "P2",
      "collection_hint": "audit-port-execmon monitor_file_ops",
      "expected_gain": "补充 WebShell 落地路径，提高持久化分析置信度"
    }
  ],
  "next_skill_blocked": false
}
```

---

## 样例 3：WEB 告警确认 — 仅有 WAF

### 用户输入

```text
这条 WAF SQL 注入告警是误报还是真实攻击？有没有打穿？
告警 ID WAF-20260621-001
```

### 已注册资产

```json
{
  "registered_assets": [
    {"asset_id": "waf_01", "type": "waf_alert", "fields": ["src_ip", "timestamp", "url", "rule_id"], "gaps": ["no_payload"]}
  ]
}
```

### 预期输出（摘要）

```json
{
  "scenario": ["S4"],
  "overall_verdict": "alert_triage_only",
  "confidence": 0.35,
  "can_trace": false,
  "can_confirm_breach": false,
  "summary": "仅有 WAF 告警且缺少 payload 与主机行为数据，只能做告警分类，无法确认攻击是否成功或是否打穿。",
  "registered_sources": [
    {
      "asset_id": "waf_01",
      "status": "partial",
      "gaps": ["payload", "request_body"]
    }
  ],
  "recommendations": [
    {
      "rank": 1,
      "source_name": "WAF 完整请求体",
      "priority": "P0",
      "collection_hint": "WAF 接入时开启 request body 记录或联动 WEB 访问日志",
      "expected_gain": "可判断 SQLi payload 是否为真实注入尝试"
    },
    {
      "rank": 2,
      "source_name": "WEB 服务器进程命令执行",
      "priority": "P1",
      "collection_hint": "audit-port-execmon on WEB servers",
      "expected_gain": "可确认 SQLi 是否导致 RCE 或后续命令执行"
    }
  ],
  "next_skill": "alert_confirmation",
  "next_skill_blocked": true,
  "block_reason": "WAF 缺少 payload，且无任何 D2 主机行为数据"
}
```

### 允许 vs 禁止结论

| 结论 | 是否允许 |
|---|---|
| 「规则命中，疑似 SQL 注入尝试」 | ✅ |
| 「真实 SQL 注入攻击」 | ⚠️ 低置信度，需标注 |
| 「已成功注入数据库」 | ❌ |
| 「已打穿服务器」 | ❌ |

---

## 样例 4：主机异常行为 — 对接 audit-port-execmon

### 用户输入

```text
对外 443 端口的 nginx 进程刚才执行了 bash -c，数据够不够做风险分析？
```

### 已注册资产

```json
{
  "registered_assets": [
    {"asset_id": "web_exec", "type": "host_exec", "coverage": ["web-01"]},
    {"asset_id": "web_connect", "type": "host_connect", "coverage": ["web-01"]}
  ]
}
```

### 预期输出（摘要）

```json
{
  "scenario": ["S5"],
  "overall_verdict": "full_traceable",
  "confidence": 0.85,
  "can_trace": true,
  "summary": "exec 与 connect 均已接入，可启动风险识别 Skill。",
  "next_skill": "risk-identification",
  "next_skill_blocked": false,
  "recommendations": [
    {
      "rank": 1,
      "source_name": "文件操作日志",
      "priority": "P2",
      "collection_hint": "audit-port-execmon monitor_file_ops on 443 listener",
      "expected_gain": "判断是否落地 WebShell 或异常文件"
    }
  ]
}
```

---

## 样例 5：多场景叠加

### 用户输入

```text
WAF 告警 + 怀疑横向到内网，帮我查完整攻击链
```

### 场景识别

`["S2", "S3", "S4"]` — WEB 入侵 + 横向 + 告警确认

### 合并 P0 需求（去重）

- waf_alert（含 payload）
- web_access_log
- host_exec（WEB + 跳板机）
- host_file_op（WEB）
- ssh_auth（内网全集）
- firewall_log（WEB→内网）

### 输出要点

- 列出合并后 P0 清单及每项 status
- overall_verdict 取最严格场景的结果
- recommendations 按 rank 合并，避免重复

---

## 样例 6：关联键不足

### 问题

WAF 有 src_ip + time，SSH 有 host + user + time，但 **SSH 日志无 src_ip**（仅记录本地登录）

### 判定

- ssh_auth status = partial
- key_completeness = partial（无法 WAF IP → SSH 横向直接关联）
- confidence 上限 0.75
- recommendation：SSH 日志需记录来源 IP 或通过 firewall_log 桥接

```json
{
  "recommendations": [
    {
      "rank": 1,
      "source_name": "SSH 认证日志来源 IP",
      "priority": "P0",
      "collection_hint": "确保 auth.log 记录 remote IP；或通过防火墙 WEB→SSH 流量关联",
      "expected_gain": "可将 WAF 攻击 IP 与内网 SSH 登录串联"
    }
  ]
}
```
