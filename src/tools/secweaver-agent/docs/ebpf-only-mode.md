# Linux eBPF-only Collection Mode

Starting with Agent 0.3.100, a Linux host whose current boot kernel cannot provide
Audit can use product-level eBPF-only collection when the embedded programs work,
without rebooting to enable Audit. SLS SaaS and ES share this selection logic.
Windows and the Docker workload profile do not use it.

## Configuration and Selection

The module configuration `/opt/secweaver-agent/etc/audit-port-execmon.json` adds:

```json
{
  "audit": { "mode": "auto" },
  "exec": { "monitor": true, "process_tree_backend": "auto" }
}
```

| audit.mode | Behavior |
| --- | --- |
| `auto` (default, including an absent field) | Keep the complete path when Audit is available; otherwise verify eBPF-only; fail if neither transport works |
| `audit` | Require Audit and fail instead of switching |
| `ebpf_only` | Require eBPF; never read audit.log or create/delete Audit rules; fail if eBPF is unavailable |

`audit.mode` defines the capability boundary of the Linux collection run.
`exec.process_tree_backend` still controls process tracking within the complete
Audit mode. Explicit `audit`/`audit_pid` backends conflict with eBPF-only and
produce an error without rewriting the administrator's choice. Use `auto` to
allow automatic selection. Standalone module commands can override the JSON mode
with `-collection-mode=auto|audit|ebpf_only`.

After dependencies are prepared and before enrollment or binary replacement, the
installer verifies the environment. Available Audit retains queue prechecks.
Unavailable Audit skips auditd configuration and lifecycle operations, checks
architecture/BTF/tracepoints, then actually loads and attaches the embedded eBPF
programs. Success persists only `audit.mode=ebpf_only`. Errors distinguish kernel
capabilities, program load/verifier, attach and explicit policy conflicts. A
second installation attempt is not a workaround for a capability failure.

## Prerequisites and Coverage

eBPF-only supports Linux amd64/arm64 systemd hosts with root, readable
`/sys/kernel/btf/vmlinux`, execve entry/exit and successful-exec tracepoints, and
attachable embedded fork/exit programs. A kernel version alone does not prove
support: vendor backports, BPF helpers, privileges and verifier behavior are
verified by actual loading. A missing execveat tracepoint pair produces a warning;
execve collection remains available. No Clang, kernel headers or libbpf are
required on the target. Linux loong64 currently needs usable Audit because it has
no supported embedded eBPF backend.

| Capability | eBPF-only behavior |
| --- | --- |
| Listener-root and descendant exec | Preserved with existing ownership and JSONL contracts |
| fork/exit, PID reuse protection, listener reconciliation | Preserved; reconciliation defaults to 300 seconds |
| Custom collection rules and exec learning | Preserved; existing policy and learning baselines are not reset |
| Audit connect/file_op and sensitive-file read watches | Unavailable; current eBPF programs provide process evidence only |
| host-persistence | File polling/diffs remain; Audit watches and actor enrichment are disabled |
| syslog, host-process, host-state, health logs and upload | Existing capabilities remain; delivery still requires configured shipper/Logtail |

Agent 0.3.101 additionally captures exec-time parent PID, name, executable path
and boot-time start token in the kernel. Parent exit or PID reuse cannot replace
that snapshot with today's `/proc` name; missing/bounded-out fields are explicit.
See [process attribution](process-attribution.md) for additive JSON fields,
path limits and real-kernel verification.

Existing argument-count/length limits still apply, with `command_truncated=true`
when truncated. An event is not collected twice from both Audit and eBPF inputs.
The Agent freezes one host transport at startup; child restarts cannot change it
independently from parent subscriptions and sibling modules. A failed eBPF event stream uses the
existing module restart mechanism and reports failures rather than switching to
unavailable Audit.

## Operation and Verification

Verify current configuration and actual program loading before changing a host:

```bash
sudo secweaver-agent config check-linux-collection \
  -config /opt/secweaver-agent/etc/audit-port-execmon.json
```

This temporarily loads eBPF without enrollment, listener roots, event output or
learning changes, then releases loaded resources. An auto configuration with
available Audit verifies its Audit environment directly.

Explicitly enable the mode and restart:

```bash
sudo secweaver-agent config set-audit-mode \
  -config /opt/secweaver-agent/etc/audit-port-execmon.json -mode ebpf_only
sudo systemctl restart secweaver-agent
sudo secweaver-agent preflight
sudo secweaver-agent doctor
```

Expect `Linux collection mode: ebpf_only`, successful eBPF loading and an
`audit-mode` coverage warning, without fatal auditd-unavailable errors.
`preflight/doctor` perform read-only capability checks; they cannot replace
`check-linux-collection` or actual runtime loading. Execute a command in a new
SSH session and inspect `audit-port-execmon.log` for `exec` with an `ebpf:` ID.

Binary-only upgrades also choose the runtime mode before startup for old
absent/auto configurations. The host-persistence Audit override applies only in
memory for that run. Its configuration and learning state are retained. To
restore complete Audit capabilities, first prepare Audit, set `audit.mode=auto`
and restart. An explicitly configured `exec.process_tree_backend=ebpf` must also
be reset to `auto` to restore fallback. If neither transport is usable, the
installer or Agent exits nonzero with the cause.
Runtime capability verification failures use exit code `78`, which the packaged
systemd unit excludes from automatic restart to prevent a loop. Start the service
manually after repairing the environment or configuration.

## Verified Scope

On 2026-10-14, actual loading and complete Agent execution were verified on a
Kylin V10 x86_64 host with kernel `4.19.90-89.27.v2401.ky10.x86_64` and the current
boot parameter `audit=0`. Preflight reported `error=0`. Two isolated runs produced
191 `ebpf:` exec events, including a marked command attributed to `sshd`, and two
host-persistence changes. Audit rule count was zero, no shared audit.log reader
started, and auditd remained inactive. The test did not use SLS/ES upload and does
not prove cloud delivery. Build checks passed for Linux amd64/arm64/loong64 and
Windows amd64/arm64. Actual eBPF support on other kernels still requires target
loading verification.
