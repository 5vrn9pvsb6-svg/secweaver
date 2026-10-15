// This bounded CO-RE walker deliberately avoids bpf_d_path, which is absent
// from older supported vendor kernels. Paths are relative to the parent's own
// filesystem root, including mount transitions; incomplete suffixes are never
// published as complete executable paths. All writes stay in the map scratch
// record rather than using a large BPF stack allocation.
static __always_inline void capture_parent_exe(struct process_event *event,
					      struct task_struct *parent)
{
	struct mm_struct *mm = 0;
	struct fs_struct *fs = 0;
	struct file *file = 0;
	struct path path = {}, root = {};
	__u64 offset = FILENAME_SIZE - 1;
	int step;

	if (!__builtin_preserve_field_info(parent->mm, 2) ||
	    !__builtin_preserve_field_info(parent->fs, 2) ||
	    !__builtin_preserve_field_info(((struct mount *)0)->mnt, 2))
		return;
	if (bpf_probe_read_kernel(&mm, sizeof(mm), __builtin_preserve_access_index(&parent->mm)) || !mm ||
	    bpf_probe_read_kernel(&fs, sizeof(fs), __builtin_preserve_access_index(&parent->fs)) || !fs ||
	    bpf_probe_read_kernel(&file, sizeof(file), __builtin_preserve_access_index(&mm->exe_file)) || !file ||
	    bpf_probe_read_kernel(&path, sizeof(path), __builtin_preserve_access_index(&file->f_path)) ||
	    bpf_probe_read_kernel(&root, sizeof(root), __builtin_preserve_access_index(&fs->root)))
		return;
	event->parent_exe[FILENAME_SIZE - 1] = 0;

#pragma unroll
	for (step = 0; step < PARENT_PATH_STEPS; step++) {
		struct dentry *mount_root = 0, *next = 0;
		const unsigned char *name = 0;
		__u32 length = 0;
		if (!path.dentry || !path.mnt)
			return;
		if (path.dentry == root.dentry && path.mnt == root.mnt) {
			struct mm_struct *after = 0;
			// Concurrent parent exec must not turn an old mm path into a
			// claimed snapshot of the replacement executable.
			if (bpf_probe_read_kernel(&after, sizeof(after),
						 __builtin_preserve_access_index(&parent->mm)) || after != mm)
				return;
			if (offset == FILENAME_SIZE - 1)
				event->parent_exe[--offset] = '/';
			event->parent_exe_offset = offset;
			event->parent_flags |= PARENT_EXE_VALID;
			return;
		}
		if (bpf_probe_read_kernel(&mount_root, sizeof(mount_root),
					 __builtin_preserve_access_index(&path.mnt->mnt_root)))
			return;
		if (path.dentry == mount_root) {
			struct mount *mount = (void *)path.mnt -
				__builtin_preserve_field_info(((struct mount *)0)->mnt, 0);
			struct mount *up = 0;
			if (bpf_probe_read_kernel(&up, sizeof(up),
						 __builtin_preserve_access_index(&mount->mnt_parent)) || !up || up == mount ||
			    bpf_probe_read_kernel(&path.dentry, sizeof(path.dentry),
						 __builtin_preserve_access_index(&mount->mnt_mountpoint)))
				return;
			path.mnt = (void *)up +
				__builtin_preserve_field_info(((struct mount *)0)->mnt, 0);
			continue;
		}
		if (bpf_probe_read_kernel(&next, sizeof(next),
					 __builtin_preserve_access_index(&path.dentry->d_parent)) || !next || next == path.dentry ||
		    bpf_probe_read_kernel(&length, sizeof(length),
					 __builtin_preserve_access_index(&path.dentry->d_name.len)) ||
		    bpf_probe_read_kernel(&name, sizeof(name),
					 __builtin_preserve_access_index(&path.dentry->d_name.name)) || !name || !length)
			return;
		if (length >= offset) {
			event->parent_flags |= PARENT_EXE_TRUNCATED;
			return;
		}
		// The explicit masks keep variable helper offsets/sizes verifier-bounded
		// even on pre-bounded-loop kernels. The length check reserves a slash.
		offset -= length;
		__u64 read_size = length;
		// Compiler barriers retain explicit 64-bit bounds instructions: newer
		// LLVM otherwise removes masks proven by C control flow that an older
		// kernel verifier cannot reproduce. The scratch guard covers the two
		// independently bounded values without relational range inference.
		asm volatile("" : "+r"(offset));
		asm volatile("" : "+r"(read_size));
		offset &= FILENAME_SIZE - 1;
		read_size &= FILENAME_SIZE - 1;
		if (bpf_probe_read_kernel(&event->parent_exe[offset], read_size, name))
			return;
		offset--;
		asm volatile("" : "+r"(offset));
		offset &= FILENAME_SIZE - 1;
		event->parent_exe[offset] = '/';
		path.dentry = next;
	}
	event->parent_flags |= PARENT_EXE_TRUNCATED;
}

// Read the current real_parent, not the fork-time owner. Reparenting changes
// this relationship but must not change the independently captured service root.
// A second relationship check rejects a concurrent reparent; absent optional
// fields remain unknown, never repaired from a later /proc view of the same PID.
static __always_inline void capture_parent_identity(struct process_event *event,
						   struct task_struct *task)
{
	struct task_struct *parent = 0, *leader = 0, *after = 0;
	__u32 pid = 0;

	event->ppid = 0;
	event->parent_flags = 0;
	event->parent_start_boottime_ns = 0;
	event->parent_exe_offset = 0;
	if (!__builtin_preserve_field_info(task->real_parent, 2) ||
	    !__builtin_preserve_field_info(task->group_leader, 2))
		return;
	if (bpf_probe_read_kernel(&parent, sizeof(parent),
				 __builtin_preserve_access_index(&task->real_parent)) || !parent ||
	    bpf_probe_read_kernel(&leader, sizeof(leader),
				 __builtin_preserve_access_index(&parent->group_leader)) || !leader ||
	    read_tgid(leader, &pid) || !pid)
		return;
	event->ppid = pid;
	event->parent_flags = PARENT_PID_VALID;
	if (__builtin_preserve_field_info(leader->comm, 2) &&
	    bpf_probe_read_kernel_str(event->parent_comm, sizeof(event->parent_comm),
				     __builtin_preserve_access_index(&leader->comm)) > 0)
		event->parent_flags |= PARENT_COMM_VALID;
	if (__builtin_preserve_field_info(leader->start_boottime, 2) &&
	    !bpf_probe_read_kernel(&event->parent_start_boottime_ns, sizeof(event->parent_start_boottime_ns),
				  __builtin_preserve_access_index(&leader->start_boottime)))
		event->parent_flags |= PARENT_START_VALID;
	else if (__builtin_preserve_field_info(leader->real_start_time, 2) &&
		 !bpf_probe_read_kernel(&event->parent_start_boottime_ns, sizeof(event->parent_start_boottime_ns),
				       __builtin_preserve_access_index(&leader->real_start_time)))
		// Older kernels call the same boot-time nanosecond token real_start_time.
		// start_time is deliberately not substituted: it uses a different clock.
		event->parent_flags |= PARENT_START_VALID;
	capture_parent_exe(event, leader);
	if (bpf_probe_read_kernel(&after, sizeof(after),
				 __builtin_preserve_access_index(&task->real_parent)) || after != parent) {
		event->ppid = 0;
		event->parent_flags = 0;
	}
}
