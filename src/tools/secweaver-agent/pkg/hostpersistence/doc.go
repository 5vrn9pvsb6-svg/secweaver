// Package hostpersistence detects file-backed persistence changes on Linux and
// Windows and emits stable host_persistence evidence.
//
// Polling owns change detection and durable baselines. On Linux, optional auditd
// enrichment runs independently and contributes bounded actor/process context;
// failure of that reader is surfaced to the supervisor instead of silently
// changing the event contract. Package files are split by lifecycle so scanner,
// state-store, audit-rule, and audit-follower changes can be reviewed separately.
package hostpersistence
