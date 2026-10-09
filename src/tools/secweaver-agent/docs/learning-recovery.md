# Learning Recovery and Empty Baselines (0.3.86)

[中文](learning-recovery.zh-CN.md)

## Fresh Installs and Upgrades

Fresh templates enable learning with shadow=false. The first startup learns from
an empty baseline, correctly reporting filtering_active=false. Five distinct
events with the same four fields in a rolling hour admit/filter the fifth event;
there is no need to wait for the learning day to end. Originals remain until then.

Initial legacy migration archives the old baseline and starts a new baseline_id;
old logs do not replay to supply counts. Ordinary restarts and later compatible
upgrades preserve progress. The 0.3.85 Linux command-completeness change does not
restart completed learning. See [behavior learning](behavior-learning.md).

Empty baselines/lack of repetitions are not faults. Relearning cannot manufacture
events or guarantee immediate filtering. Fix missing input or continuing audit
loss first; otherwise the new generation may degrade too, including on fresh installs.

## Linux Helper

Copy recovery/restart-behavior-learning.py alone. It supports Linux systemd, root,
Python 3.6+ and Agent 0.3.81+, with either SLS SaaS or ES and no network access.
It requires the standard layout and audit module arguments
`-config <install-root>/etc/audit-port-execmon.json`. Use --root/--service for an
alternate root/service. Custom state_dir, extra module arguments, Windows,
containers and non-systemd installations need their manual procedure.

```bash
# Inspect only: JSON result; no service stop or config/state mutation
sudo python3 ./restart-behavior-learning.py

# Recover disabled/shadow/degraded or completed-empty learning
sudo python3 ./restart-behavior-learning.py --apply

# Explicitly restart healthy learning with an empty baseline (usually unnecessary)
sudo python3 ./restart-behavior-learning.py --apply --relearn
```

Healthy exec baselines and active file baselines are always preserved. Healthy
empty learning is skipped without --relearn. Repeating ordinary --apply preserves
the new cycle; repeating --relearn explicitly requests another cycle. The default
healthy day limits new admissions; completed-empty baselines never create filtering.

The helper only enables learning, disables shadow and raises generation above
config/checkpoint values, preserving duration and event scope. It briefly stops
the entire Agent; Linux exec and enabled file_op streams sharing that generation
both relearn. It preserves audit policy, other module configuration, device
identity/keys, authorization, update policy and Logtail/Filebeat.

## Backup, Acceptance and Failure

Version, service paths and update transactions are checked before mutation. After
stopping, the complete learning tree (file baseline, journals, key) and collector
config are saved under `<install-root>/data/recovery/learning-*`. An atomic config
write requests native state creation; HMAC state is not edited, locks are not
deleted and entries are not invented. Unknown/invalid learning states are refused;
finish pending updates first. A local lock serializes helpers. Backups reject links
and special files, limit traversal to 10000 entries/512 MiB and require disk
headroom. Inspection may create a private mutex file.

Startup waits up to 180 seconds (--health-timeout, 30–600) for a new generation,
fresh native doctor learning observation, accrued healthy time and an active
service, returning status=relearning. This does not claim filtering is active:
five-hit admission is still required; the next heartbeat updates the Workspace.
Inspection returns checked; preserved states return skipped with a reason. Use
`secweaver-agent doctor --verbose` to inspect progress and source problems.

Normal failures restore config and the complete learning tree, then restart the
original service; failed new state is retained in the backup. Concurrent changes
or updates prevent overwriting their state and require manual recovery with the
reported backup. Forced termination/power loss also requires that backup. Do not
restore device identity or copy another host's baseline.
Failed command output stays in a local mode-0600 secweaver-learning-error-*.log;
results expose only its path, avoiding credential/config disclosure in terminals.

Validation: make recovery-test performs real temporary-filesystem transactions
for backup, rollback, repeated execution, delayed startup and baseline preservation;
service/doctor boundaries are isolated. go test . ./pkg/behaviorlearning verifies
native policy/generation behavior. Real Linux recovery needs its own host
acceptance; source verification does not mean deployment.
