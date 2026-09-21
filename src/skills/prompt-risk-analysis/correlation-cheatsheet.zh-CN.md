# 关联速查表（prompt-risk-analysis）

> **先读本表做拼链与补数；细节以权威 JSON 为准：**  
> [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json) · [anchor-patterns.json](../../../dataasset/scenarios/anchor-patterns.json)

场景重叠时按 [analysis-contract.zh-CN.md](analysis-contract.zh-CN.md) 决策，并应用其参数、计数、成功证据、WAF 覆盖和脱敏规则。

## 1. 时间窗（写报告时引用 window id）

| window id | 范围 | 典型用途 |
|-----------|------|----------|
| `host_behavior_chain` | 前 5min / 后 5min | 同主机 exec ↔ connect ↔ file_op |
| `attack_success` | 前 5min / 后 30min | WAF/WEB 告警后 host_exec 是否打穿 |
| `alert_context` | 前 10min / 后 10min | WAF 告警前后 WEB 访问 |
| `alert_confirmation_fetch` | 前 10min / 后 30min | S4 告警确认默认取数窗 |
| `lateral_movement` | 前 30min / 后 120min | SSH 横向、syslog 账号 + 目标主机 exec |
| `trace_default` | 前 24h / 后 6h | S1/S2/S3 溯源默认调查窗 |

## 2. 场景速选（根据已拉 evidence）

| 已有 asset_type / 用户问题 | 场景 | pattern id | 推荐 bundle |
|---------------------------|------|------------|-------------|
| `waf_alert` + 是否真实攻击 | S4 | `S4_alert_confirmation` | `bundle-alert-confirm-min` |
| `waf_alert` / WebShell / uploads 脚本 | S2 | `S2_web_breach` | `bundle-incident-trace-default` |
| 外网 IP 打哪台主机 | S1 | `S1_external_ip_trace` | `bundle-incident-trace-default` |
| `host_exec` + `syslog_risk_alert` / 单机高危命令 | S5 | `S5_host_risk` | `bundle-host-risk-default` |
| 多主机 SSH / devops 横向 | S3 | `S3_lateral_movement` | `bundle-incident-trace-default` |
| 账号异常 / 暴力破解成功 | S6 | `S6_account_compromise` | `bundle-incident-trace-default` |
| 异常外连 / DNS / 大流量外传 | S7 | `S7_data_exfiltration` | `bundle-data-exfiltration-default` |

**exec + syslog 双源（无 WAF）**：优先对齐 **S5**；若出现 Web 进程 shell + 跨主机 sshpass，叙事上叠加 **S2 + S3** 环节。

## 3. 常用 Join id（叙事拼链）

| join id | 左 → 右 | 杀链阶段 | 说明 |
|---------|---------|----------|------|
| `web_access_to_host_exec` | web_access → host_exec | execution | WEB 访问后同主机命令执行 |
| `waf_to_host_exec_via_web_access` | waf → web → exec | execution | S4 二层确认 |
| `d2_exec_connect_same_listener` | host_exec → host_connect | execution | 同监听进程下 exec 后外连 |
| `d2_exec_file_same_host` | host_exec → host_file_op | execution | 同主机文件操作链 |
| `ssh_auth_to_host_exec_same_host` | ssh_auth → host_exec | execution | SSH 登录后会话内命令 |
| `attacker_ip_to_ssh_auth` | src_ip → ssh_auth | lateral_movement | 攻击源 IP 登录尝试 |
| `host_ip_to_ssh_auth_lateral` | host → ssh_auth | lateral_movement | 受害主机上的 SSH 活动 |
| `lateral_from_exec` | host_exec(A) → host_exec(B) | lateral_movement | 跨主机 exec 弱关联（账号/工具链/时间） |
| `lateral_from_syslog` | syslog(A) → exec(B) | lateral_movement | syslog 账号/SSH 与目标 exec |
| `host_connect_to_dns` | host_connect → dns_log | network_activity | 外连与 DNS 解析 |

`host_connect_to_dns` 仅建立外连与 DNS 解析的网络上下文，不能单独证明数据外传。外传结论需要传输方向、数据内容/体量、目的地及其他关联证据支持；缺少这些证据时保留未知或待验证假设。

**无 matrix join 时**：跨主机弱关联须在报告中标注 `confidence: low`，并写清假设。

## 4. 推荐链覆盖检查（写入 `chain_coverage`）

### S5_host_risk（host exec + syslog）

```text
recommended_chain: d2_exec_connect_same_listener, d2_exec_file_same_host
```

| 环节 | 需要 asset_type | 常见缺口 |
|------|-----------------|----------|
| exec ↔ connect | host_exec + host_connect | 未拉 connect → 无法确认 C2 |
| exec ↔ file | host_exec + host_file_op | 未拉 file_op → 无法确认写 shell |

### S2_web_breach

```text
waf_to_web_access_by_ip → web_access_to_host_exec → d2_exec_file_same_host → d2_exec_connect_same_listener
```

### S3_lateral_movement

```text
attacker_ip_to_ssh_auth → host_ip_to_ssh_auth_lateral → ssh_auth_to_host_exec_same_host
```

报告 `data_gaps` 应列出：**缺哪一环、对应 join id、建议补拉 asset_id**。

## 5. 补数命令模板

先确认授权 Bundle 与本地参数文件，参数包含明确主机或攻击源 IP，以及带时区的 `time_start` / `time_end`，不包含凭证。该命令会真实只读取数，执行前核实范围。S5 标准包为 `bundle-host-risk-default`，S2 为 `bundle-incident-trace-default`，还需确认本地 active 资产覆盖。

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle "${EVIDENCE_BUNDLE_ID:?Set an authorized bundle ID}" \
  --params-file "${EVIDENCE_PARAMS_FILE:?Set a scoped params JSON file}" \
  -o /tmp/secweaver-followup-evidence.json
```

## 6. 字段解读提示

归一字段见 [evidence-minimum-fields.json](../../../dataasset/configure/evidence-minimum-fields.json)：

| 常见源字段 | canonical | 说明 |
|-----------|-----------|------|
| `host_ip`, `host_name` | `host` | 主机标识 |
| `command_line` + `command` | 命令文本 | exec 研判优先看两者 |
| `listener_process` + `listener_port` | 对外入口 | Web 滥用关键 |
| `rule_name`, `event_type` | syslog 类型 | 与 exec 时间互证 |
