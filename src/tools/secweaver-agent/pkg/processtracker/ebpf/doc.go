// Package ebpf implements recursive Linux process-tree ownership with a fixed
// set of eBPF programs. It does not create audit rules: tracked ownership is
// inherited in a kernel hash map on fork and deleted on process exit.
package ebpf
