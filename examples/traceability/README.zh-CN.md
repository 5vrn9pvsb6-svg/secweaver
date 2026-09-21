# 溯源分析 — 跨源测试数据

本目录提供 **离线 evidence_bundles**，用于模拟 [`correlation-matrix.json`](../../dataasset/assets/correlation-matrix.json) 定义的跨源 Join 拼链，无需 live fetch。

说明文档：[跨源字段关联说明](../../docs_user/21-cross-source-field-correlation.md)

## 场景列表

| 文件 | 场景 | 预期 verdict | 说明 |
|---|---|---|---|
| [s1-web-shell-to-ssh-lateral.json](s1-web-shell-to-ssh-lateral.json) | S1 + S2 + S3 | `confirmed_intrusion_chain` | 主机行为与 SSH 横向；WEB 到主机 Join 未匹配 |
| [s1-scan-only-no-host-exec.json](s1-scan-only-no-host-exec.json) | S1 负例 | `scanning_or_attempt_only` | 仅 WAF/WEB，无 host_exec |
| [s2-initial-access-no-lateral.json](s2-initial-access-no-lateral.json) | S2 | `initial_access_only` | 已打穿 WEB，无 SSH Accepted |

离线回归同时检查实际匹配的 Join ID 和结论。当前样例中的 `web_access_to_host_exec`
及 `host_to_cmdb` 均未匹配，不应把已确认的其他证据链解释成所有推荐 Join 均已匹配。
SSH 失败记录也可能产生 Join 边，但不能单独证明横向成功；需结合结论与边的分类。
回归测试还会把成功登录改为失败或改成不相关来源：两种情况下均不得保留已确认的横向结论。
首次观察到的 WebShell 控制点不等于原始攻破点，后者在本例中仍是 `unresolved`。

## 跨源 Join 路径（样例 1）

```text
203.0.113.55 (attacker_ip)
    │
    ├─ waf_alert (waf-001)          join: src_ip
    │       └─ web_access_log (web-001)     waf_to_web_access_by_ip ±10min
    ├─ host_exec (exec-001…)        web_access_to_host_exec: no_match
    │       ├─ host_connect (connect-001)   d2_exec_connect_same_listener
    │       └─ host_file_op (file-001)      d2_exec_file_same_host
    │
    └─ host_exec.host_ip 10.0.1.5
            ├─ firewall_log (fw-001)        DMZ→内网 :22
            └─ ssh_auth (ssh-002, ssh-003)  host_ip_to_ssh_auth_lateral
                    → db-01, app-02
```

## 运行

```bash
# 主机行为与 SSH 横向（首次攻破点未证实）
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json \
  --no-ip-intel --no-notify \
  -o /tmp/trace-s1-out.json

# 仅扫描负例
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s1-scan-only-no-host-exec.json

# 打穿无横向
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s2-initial-access-no-lateral.json
```

## 字段约定

- 所有事件使用 **canonical** 字段名（`src_ip`、`host`、`timestamp`），与 fetch 归一化后一致
- `host_exec` 含 `host_ip`、`listener_pid`、`listener_port`，供 D2 内关联与横向 Join
- `evidence_id` 与 `correlate.py` 输出中的 `evidence_refs` 一一对应

## 维护

新增场景时：

1. 按 `correlation-matrix.json` → `anchor_patterns` 设计时间线与 Join 键
2. 运行 `correlate.py` 验证 `overall_verdict` 与 `attack_chain`
3. 在本 README 与上级 [examples/README.md](../README.md) 补充场景行
