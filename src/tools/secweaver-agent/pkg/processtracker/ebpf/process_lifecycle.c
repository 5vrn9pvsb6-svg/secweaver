//go:build ignore

// This CO-RE program deliberately carries only the definitions it uses. The
// release binary embeds the compiled object, so target hosts need neither a C
// compiler nor kernel headers.
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) __typeof__(value) *name
#define __always_inline inline __attribute__((always_inline))
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_ANY 0
#define BPF_F_CURRENT_CPU 0xffffffffULL

#define EVENT_FORK 1
#define EVENT_EXEC 2
#define EVENT_EXIT 3
#define OWNER_TRACK_DESCENDANTS 1
#define MAX_ARGS 16
#define ARG_SIZE 96
#define FILENAME_SIZE 256
#define COMM_SIZE 16

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(const void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(const void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)25;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)114;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)115;

// Minimal CO-RE flavor of task_struct. preserve_access_index lets the loader
// relocate tgid even when a distribution kernel lays task_struct out differently.
struct kuid_t {
	__u32 val;
} __attribute__((preserve_access_index));
struct kgid_t {
	__u32 val;
} __attribute__((preserve_access_index));
struct cred {
	struct kuid_t uid, euid;
	struct kgid_t gid, egid;
} __attribute__((preserve_access_index));
struct super_block {
	__u32 s_dev;
} __attribute__((preserve_access_index));
struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));
struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));
struct task_struct {
	int tgid;
	const struct cred *cred;
	struct kuid_t loginuid;
	__u64 start_boottime;
} __attribute__((preserve_access_index));

struct linux_binprm {
	const char *filename;
	struct file *file;
} __attribute__((preserve_access_index));

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

// sys_enter tracepoints begin with an eight-byte trace header followed by the
// syscall number and six native-word arguments on supported 64-bit targets.
struct syscall_enter_ctx {
	__u64 trace_header;
	long syscall_nr;
	unsigned long args[6];
};

// sys_exit tracepoints expose the syscall return value after the common trace
// header and syscall number. Failed exec attempts must discard their staged
// arguments so a later successful exec cannot inherit stale command data.
struct syscall_exit_ctx {
	__u64 trace_header;
	long syscall_nr;
	long ret;
};

struct process_owner {
	__u32 root_pid;
	__u32 parent_pid;
	__u32 flags;
};

struct process_event {
	__u32 type;
	__u32 root_pid;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 argc;
	__u32 flags;
	__u64 timestamp_ns;
	// Successful exec identity is captured in-kernel, not guessed from a later
	// /proc snapshot. identity_valid marks all required reads as successful.
	__u64 start_boottime_ns;
	__u64 executable_inode;
	__u32 executable_dev;
	__u32 euid;
	__u32 egid;
	__u32 identity_valid;
	__u32 auid;
	__u32 identity_padding;
	char comm[COMM_SIZE];
	char filename[FILENAME_SIZE];
	char args[MAX_ARGS][ARG_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 131072);
	__type(key, __u32);
	__type(value, struct process_owner);
} tracked_processes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_event);
} scratch_events SEC(".maps");

// Exec arguments are captured before the syscall and emitted only after
// sched_process_exec confirms success. A failed exec is overwritten by the
// next attempt or removed on process exit, so it is never mislabeled success.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct process_event);
} pending_execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} process_events SEC(".maps");

static __always_inline int read_tgid(struct task_struct *task, __u32 *tgid)
{
	const void *field = __builtin_preserve_access_index(&task->tgid);
	return bpf_probe_read_kernel(tgid, sizeof(*tgid), field);
}

static __always_inline struct process_event *new_event(__u32 type, const struct process_owner *owner,
		__u32 pid, __u32 ppid)
{
	__u32 zero = 0;
	struct process_event *event = bpf_map_lookup_elem(&scratch_events, &zero);
	if (!event)
		return 0;
	event->type = type;
	event->root_pid = owner->root_pid;
	event->pid = pid;
	event->ppid = ppid;
	event->argc = 0;
	event->flags = 0;
 event->identity_valid = 0;
 event->timestamp_ns = bpf_ktime_get_ns();
 event->filename[0] = 0;
 return event;
}

SEC("raw_tracepoint/sched_process_fork")
int handle_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *parent = (void *)ctx->args[0];
	struct task_struct *child = (void *)ctx->args[1];
	struct process_owner child_owner;
	struct process_owner *owner;
	struct process_event *event;
	__u32 parent_tgid = 0;
	__u32 child_tgid = 0;

	if (read_tgid(parent, &parent_tgid) || read_tgid(child, &child_tgid))
		return 0;
	// sched_process_fork also fires for threads. They share a TGID and must not
	// create extra process ownership entries or userspace events.
	if (parent_tgid <= 1 || child_tgid <= 1 || parent_tgid == child_tgid)
		return 0;
	owner = bpf_map_lookup_elem(&tracked_processes, &parent_tgid);
	if (!owner || !(owner->flags & OWNER_TRACK_DESCENDANTS))
		return 0;
	child_owner.root_pid = owner->root_pid;
	child_owner.parent_pid = parent_tgid;
	child_owner.flags = owner->flags;
	if (bpf_map_update_elem(&tracked_processes, &child_tgid, &child_owner, BPF_ANY))
		return 0;
	event = new_event(EVENT_FORK, &child_owner, child_tgid, parent_tgid);
	if (event)
		bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	return 0;
}

static __always_inline int handle_exec(struct syscall_enter_ctx *ctx, int execveat)
{
	const char *filename;
	const char *const *argv;
	struct process_owner *owner;
	struct process_event *event;
	__u64 uid_gid;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	int i;

	owner = bpf_map_lookup_elem(&tracked_processes, &pid);
	if (!owner)
		return 0;
	filename = (const char *)(execveat ? ctx->args[1] : ctx->args[0]);
	argv = (const char *const *)(execveat ? ctx->args[2] : ctx->args[1]);
	event = new_event(EVENT_EXEC, owner, pid, owner->parent_pid);
	if (!event)
		return 0;
	uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;
	event->gid = (__u32)(uid_gid >> 32);
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	if (filename)
		bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);

#pragma unroll
	for (i = 0; i < MAX_ARGS; i++) {
		const char *arg = 0;
		if (!argv || bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) || !arg)
			break;
		if (bpf_probe_read_user_str(event->args[i], ARG_SIZE, arg) <= 0)
			break;
		event->argc = i + 1;
	}
	if (event->argc == MAX_ARGS)
		event->flags = 1;
	bpf_map_update_elem(&pending_execs, &pid, event, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct syscall_enter_ctx *ctx)
{
	return handle_exec(ctx, 0);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct syscall_enter_ctx *ctx)
{
	return handle_exec(ctx, 1);
}

static __always_inline int handle_exec_failure(struct syscall_exit_ctx *ctx)
{
	__u32 pid;

	if (ctx->ret >= 0)
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&pending_execs, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_execve_exit(struct syscall_exit_ctx *ctx)
{
	return handle_exec_failure(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int handle_execveat_exit(struct syscall_exit_ctx *ctx)
{
	return handle_exec_failure(ctx);
}

// capture_exec_identity is best-effort. Field existence guards retain support
// for vendor kernels without start_boottime; such events remain full-output.
static __always_inline void capture_exec_identity(struct process_event *event, struct task_struct *task,
						  struct linux_binprm *bprm)
{
	const struct cred *cred = 0;
	struct file *file = 0;
	struct inode *inode = 0;
	struct super_block *sb = 0;
	event->identity_valid = 0;
	if (!bprm || !__builtin_preserve_field_info(task->start_boottime, 2) ||
	    !__builtin_preserve_field_info(task->loginuid, 2))
		return;
	if (bpf_probe_read_kernel(&cred, sizeof(cred), __builtin_preserve_access_index(&task->cred)) || !cred)
		return;
	if (bpf_probe_read_kernel(&event->auid, sizeof(event->auid),
				  __builtin_preserve_access_index(&task->loginuid.val)) ||
	    bpf_probe_read_kernel(&event->uid, sizeof(event->uid),
				  __builtin_preserve_access_index(&cred->uid.val)) ||
	    bpf_probe_read_kernel(&event->euid, sizeof(event->euid),
				  __builtin_preserve_access_index(&cred->euid.val)) ||
	    bpf_probe_read_kernel(&event->gid, sizeof(event->gid),
				  __builtin_preserve_access_index(&cred->gid.val)) ||
	    bpf_probe_read_kernel(&event->egid, sizeof(event->egid),
				  __builtin_preserve_access_index(&cred->egid.val)) ||
	    bpf_probe_read_kernel(&event->start_boottime_ns, sizeof(event->start_boottime_ns),
				  __builtin_preserve_access_index(&task->start_boottime)))
		return;
	if (bpf_probe_read_kernel(&file, sizeof(file), __builtin_preserve_access_index(&bprm->file)) ||
	    !file ||
	    bpf_probe_read_kernel(&inode, sizeof(inode), __builtin_preserve_access_index(&file->f_inode)) ||
	    !inode || bpf_probe_read_kernel(&sb, sizeof(sb), __builtin_preserve_access_index(&inode->i_sb)) ||
	    !sb)
		return;
	if (bpf_probe_read_kernel(&event->executable_inode, sizeof(event->executable_inode),
				  __builtin_preserve_access_index(&inode->i_ino)) ||
	    bpf_probe_read_kernel(&event->executable_dev, sizeof(event->executable_dev),
				  __builtin_preserve_access_index(&sb->s_dev)))
		return;
	event->identity_valid = 1;
}

SEC("raw_tracepoint/sched_process_exec")
int handle_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task = (void *)ctx->args[0];
	struct linux_binprm *bprm = (void *)ctx->args[2];
	struct process_owner *owner;
	struct process_event *event;
	const char *filename = 0;
	__u64 uid_gid;
	__u32 tgid = 0;

	if (read_tgid(task, &tgid) || tgid <= 1)
		return 0;
	owner = bpf_map_lookup_elem(&tracked_processes, &tgid);
	if (!owner)
		return 0;
	event = bpf_map_lookup_elem(&pending_execs, &tgid);
	if (!event) {
		event = new_event(EVENT_EXEC, owner, tgid, owner->parent_pid);
		if (!event)
			return 0;
		uid_gid = bpf_get_current_uid_gid();
		event->uid = (__u32)uid_gid;
		event->gid = (__u32)(uid_gid >> 32);
		if (bprm) {
			const void *field = __builtin_preserve_access_index(&bprm->filename);
			if (!bpf_probe_read_kernel(&filename, sizeof(filename), field) && filename)
				bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), filename);
		}
	}
	event->timestamp_ns = bpf_ktime_get_ns();
	capture_exec_identity(event, task, bprm);
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	bpf_map_delete_elem(&pending_execs, &tgid);
	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int handle_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task = (void *)ctx->args[0];
	struct process_owner *owner;
	struct process_event *event;
	__u32 tgid = 0;
	__u64 current = bpf_get_current_pid_tgid();
	__u32 current_tgid = current >> 32;
	__u32 current_pid = (__u32)current;

	if (read_tgid(task, &tgid) || tgid <= 1 || tgid != current_tgid || current_pid != tgid)
		return 0;
	bpf_map_delete_elem(&pending_execs, &tgid);
	owner = bpf_map_lookup_elem(&tracked_processes, &tgid);
	if (!owner)
		return 0;
	event = new_event(EVENT_EXIT, owner, tgid, owner->parent_pid);
	if (event)
		bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	bpf_map_delete_elem(&tracked_processes, &tgid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
