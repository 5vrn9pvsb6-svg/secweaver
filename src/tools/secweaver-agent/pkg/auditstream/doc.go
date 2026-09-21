// Package auditstream owns the lowest-level Linux audit-log transport used by
// secweaver-agent. It deliberately knows nothing about event semantics or audit
// keys: its job is to preserve file order across normal appends and log rotation,
// then expose either a file follower or an inherited reader to higher layers.
//
// In supervised mode the parent process follows audit.log once and gives child
// modules a pipe FD. Standalone modules call FollowFile directly. Keeping these
// transports behind one package ensures both modes use the same rotation and
// cancellation behavior.
package auditstream
