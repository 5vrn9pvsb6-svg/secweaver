// Package auditportexecmon monitors commands and selected activity originating
// from externally listening Linux processes.
//
// The package combines three sources of truth:
//   - socket and /proc snapshots identify listener roots and current descendants;
//   - audit rules provide real-time exec/clone/connect/file evidence;
//   - periodic reconciliation repairs races, exited processes, PID reuse, and
//     listener changes that cannot be represented by one permanent audit rule.
//
// Rule installation is budgeted and transactional. A PID is considered covered
// only after its complete rule group succeeds; partial failures are rolled back,
// and rollback residuals remain tracked until a later cleanup succeeds. Audit
// pressure can reduce dynamic coverage in stages while preserving critical web
// and SSH roots.
package auditportexecmon
