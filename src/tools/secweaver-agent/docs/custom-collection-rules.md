# Enterprise Custom Collection Rules

Requires Agent0.3.97, Agent Server rc.84 and Server rc.135/schema41. Workspace uses approved option A under Custom collection rules. Owner/Admin can publish; members read; local subadministrators do not gain rule-write permission.

Choose platform, module and actual event types. ALL/ANY/NOT support typed values, field combinations, RE2, CIDR, numeric ranges and arrays. Missing/incomplete/wrongly typed inputs remain unknown, even under NOT. Actions precede learning: alert and retain; count only without learning; retain and bypass learning; pass to learning. Ordering is alert > keep > pass > suppress, then numeric priority within an action. New rules are disabled/observe. Both policy and rule must enforce. Observe counts the first predicted winner before existing learning. High/critical and persistence changes resist suppression; exceptions require policy/rule permission, reason and expiry within seven days.

Test semantic JSON, save draft, then publish with reason and all-enterprise or explicit owned-device scope. Drafts are not delivered. Conflicts require refresh; history restores as a new draft. Applied receipts require fresh current-module PID/revision/digest. Device pages contain20 rows/load more; counters aggregate loaded devices/current revision, reset on restart and never reset learning.

Linux audit exec/file/connect, syslog and persistence; Windows process/risk/evidence file/connect are supported. Use registered fields, not cloud fields or PCRE. Windows listener_process is explicitly empty; unavailable correlated command lines remain unknown. Snapshots, control/health/diagnostics/update/custom alerts and backfill are excluded. Remote delivery requires SaaS v2 signed device identity; ES/offline installations do not automatically receive cloud rules.

Linux TCP listener scope uses keep_listener/exclude_listener, existing root ownership and loopback boundaries. Legacy ports import binds exact device/digest with device-specific predicates. Local settings remain for rollback and reactivate when enforcement expires/stops. Multiple imports never become a fleet-wide union.

Policies live at data/collection-rules/current.json. collection_rules supports enabled/policy_file/public_key/alert_output overrides. A dedicated public key is bundled; Gateway collection_signing_key_file points to a protected external0600 private key, independent of release signing. Back it up and coordinate Agent trust when rotating. Device/tenant-bound envelopes last24h and renew with six hours remaining. Optional outages do not deny heartbeats. Invalid updates retain unexpired last-good; expiry retains originals/restores listener scope.

```bash
secweaver-agent whitelist validate -policy policy.json
secweaver-agent whitelist test -policy policy.json -event semantic-event.json
secweaver-agent whitelist status -config /opt/secweaver-agent/etc/config.json
secweaver-agent whitelist disable -config /opt/secweaver-agent/etc/config.json
secweaver-agent whitelist enable -config /opt/secweaver-agent/etc/config.json
secweaver-agent doctor -verbose
```

Status shows download metadata only. Disable creates a cloud-resistant local sentinel; enable removes only that sentinel, still respecting tenant policy.

Alerts use logs/custom-risk-alert.log,0600,100MiB/five backups, one parent writer. Module queues have64 records/1MiB bounds. Failures increment counters and retain originals. Copies redact sshpass passwords, URL-encoded credentials and token/secret fields before enqueue; matching uses originals. Severity cannot fall below source severity.

Bind Logtail custom-risk-alert.log* to host-custom-risk-alert, excluding compressed files. Windows uses ProgramData logs. Operators configure cloud collection; Agents receive no AK/SK. Local receipts/queues do not prove cloud delivery: verify machine heartbeat and fresh tenant/host/evidence-scoped SLS records. Community Filebeat includes the dataset; existing ES Operator shippers need another route. See [example](../logtail/custom-risk-alert.example.json).

Acceptance covers race tests, real PostgreSQL ownership/publication/audit, Windows cross-build and frontend interaction/type checks. Roll back using a new disabled revision/local emergency disable, retaining schema41 and learning. Legacy Agents remain operational but cannot execute rules.

DataAsset includes asset-secweaver-custom-risk-alert, using the existing syslog_risk_alert bundle and time/host queries. Detection maps custom critical/high/medium alerts to P0/P1/P2; investigate source_evidence_id and the retained original. A tenant rule hit is a finding to review, not proof of compromise. Replace the draft connector placeholders and explicitly grant its Logstore before querying.
