# 研判报告 — 192.0.2.91 / 192.0.2.92（2026-07-01 14:00 ~ 18:30）

> **黄金样例**：对应 [fetch-exec-syslog-mini.json](fetch-exec-syslog-mini.json)。Agent 输出应与此同级叙事质量；事实必须来自 `evidence_bundles`，不得复制本样例中不存在的事件。

## 1. 证据概要

| 项 | 值 |
|----|-----|
| 场景对齐 | **S5** 主机风险（主）；叙事含 **S2** Web 入侵 + **S3** 横向 |
| 事件量 | host_exec 6，syslog_risk_alert 2 |
| 第一眼判断 | **P0 主机风险**：91 上 Web 进程读取 shadow 并尝试 SSH 到 92；目标机是否被打穿尚不能确认 |

## 2. 场景与链覆盖（chain_coverage）

| join id | 状态 | 说明 |
|---------|------|------|
| `d2_exec_connect_same_listener` | **missing** | 未拉 host_connect，无法确认 C2 |
| `d2_exec_file_same_host` | **missing** | 未拉 host_file_op |
| `lateral_from_exec` | **partial** | 91 nginx 发起到 92 的 sshpass 命令；缺少登录结果与目标机后续事件 |
| `lateral_from_syslog` | **context_only** | 92 的账号创建和本机执行发生在 91 的 Web 行为之前，不能归因于本次横向 |

## 3. 时间线

| 时间 | 主机 | 阶段 | 摘要 |
|------|------|------|------|
| 14:34 | 192.0.2.92 | context | root 创建 devops + wheel（syslog + exec，早于 91 的异常行为） |
| 15:01 | 192.0.2.92 | context | 92 本机读取 shadow（早于 91 的异常行为） |
| 16:46 | 192.0.2.91 | investigation | sshd 关联进程通过 curl 访问本机 uploads/s.phtml；没有 HTTP 响应证据 |
| 17:22 | 192.0.2.91 | lateral_attempt | nginx:80 发出到 92 的 sshpass 命令，结果未知 |
| 17:59 | 192.0.2.91 | impact | nginx:80 cat /etc/shadow |
| 18:01 | 192.0.2.91 | lateral_attempt | nginx:80 发出到 92 读取 shadow 的 SSH 命令，结果未知 |

## 4. 风险发现

| 级别 | 主机 | 时间 | 类型 | 摘要 | 策略 | join / window | 分析理由 |
|------|------|------|------|------|------|---------------|----------|
| P0 | 192.0.2.91 | 17:59:58 | host_exec | nginx 子进程读 shadow | alert_required | — | T1505.003 + T1003.008 |
| P1 | 192.0.2.91 | 18:01:43 | host_exec | nginx 发出到 92 的远程读 shadow 命令 | investigate | lateral_from_exec / lateral_movement | 尝试跨主机操作，缺少成功结果 |
| P1 | 192.0.2.91 | 16:46:36 | host_exec | 本机访问疑似 WebShell 路径 | investigate | 入口待核查 | 未提供 WAF、Web 访问或 HTTP 响应证据 |
| P3 | 192.0.2.92 | 14:34:31 | syslog+exec | devops 账号创建 | verify_authorization | context_only | 发生在 91 的异常行为前，不能归因于本次攻击 |
| P3 | 192.0.2.92 | 15:01:40 | exec | 本机读取 shadow | verify_authorization | context_only | 发生在 91 的异常行为前 |

## 5. 攻击叙事

**192.0.2.91** 的 nginx:80 关联进程执行了本机 `cat /etc/shadow`，随后发出到 **192.0.2.92** 的 `sshpass` 远程命令；这足以优先调查 91 的主机行为。对 `uploads/s.phtml` 的访问来自 91 上的命令事件，缺少外部 Web 请求和 HTTP 响应，不能仅凭该记录确定攻击入口。92 上的账号创建和本机 shadow 读取发生在这些事件之前；输入中没有 SSH 登录成功记录或 92 在远程命令之后的主机行为，因此**不能确认横向成功或 92 已失陷**。

## 6. 影响与置信度

- **可确认行为**：192.0.2.91（nginx 关联命令执行、读取敏感文件、尝试 SSH）
- **待核实范围**：192.0.2.92 的账号变更和本机命令发生较早；尚不能关联至 91 的后续 SSH 尝试
- **置信度**：91 的主机行为较高；Web 入口、SSH 成功与 92 失陷均未证实
- **演练可能**：92 有预置账号特征；需核对变更授权，不据此忽略 91 的高风险行为

## 7. 数据缺口与后续（fetch_next）

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle bundle-host-risk-default \
  --params '{"hosts":["192.0.2.91","192.0.2.92"],"time_start":"2026-07-01T14:00:00+08:00","time_end":"2026-07-01T19:00:00+08:00"}' \
  -o /tmp/fetch-s5-full.json
```

- 补拉 **host_connect**（join: `d2_exec_connect_same_listener`）
- 补拉 **host_file_op**（join: `d2_exec_file_same_host`）
- 补拉 **92 的 SSH 认证与 18:01 之后的 host_exec**，确认远程命令是否落地；同时获取 WAF/WEB 日志核对入口
- 证据链补齐后可选 **traceability-analysis**
