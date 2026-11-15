// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cpugraph.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} perf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} counts_last SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct pd_key);
	__type(value, struct pd_value);
} counts_pid SEC(".maps");

/* Use LRU so exited processes are still likely to keep their entries */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct pd_key);
	__type(value, struct pd_extra);
} task_extra SEC(".maps");

static void __always_inline init_extra(struct task_struct *task, struct pd_key *key) {
	struct pd_extra extra;
	extra.parent.tgid = task->real_parent->tgid;
	bpf_probe_read_kernel_str(extra.comm, sizeof(extra.comm), task->comm);
	extra.uid = task->real_cred->uid.val;
	extra.gid = task->real_cred->gid.val;
	bpf_map_update_elem(&task_extra, key, &extra, BPF_ANY);
}

SEC("iter/task")
int iter_for_parents(struct bpf_iter__task *ctx) {
	int err;
	struct task_struct *task = ctx->task;
	struct pd_key key;

	if (task == NULL) {
		/* setup task 0 after everything else to avoid map lookup errors */
		key.tgid = 0;
		struct pd_extra extra = {
			.parent = key,
			.comm = "swapper",
			.uid = 0, .gid = 0,
		};
		bpf_map_update_elem(&task_extra, &key, &extra, BPF_ANY);
		return 0;
	}

	/* only process thread leaders, ie once per userspace PID (tgid) */
	if (task->tgid != task->pid) {
		return 0;
	}

	key.tgid = task->tgid;
	init_extra(task, &key);

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_switch, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state) {
	int error;
	const __u32 zero = 0;
	struct bpf_perf_event_value buf;
	__u64 *count_last;
	__u64 delta;

	struct pd_key key;
	struct pd_value *value;

	error = bpf_perf_event_read_value(&perf, BPF_F_CURRENT_CPU, &buf, sizeof(buf));
	if (error)
		return 0;

	/* calculate counter deltas for prev process */
	/* delta is a percpu array with one item: it starts with value=0 at key=0 */
	count_last = bpf_map_lookup_elem(&counts_last, &zero);

	/* This should never happen, but is needed for the verifier */
	if (count_last == NULL) {
		return 0;
	}

	/* Skip the first run, when counts_last[0] is unset (0) */
	if (*count_last != 0) {
		delta = buf.counter - *count_last;

		/* update or set counter for prev process */
		key.tgid = prev->tgid;

		value = bpf_map_lookup_elem(&counts_pid, &key);

		if (value != NULL) {
			/* percpu map can safely be updated from the pointer */
			value->cycles += delta;

		} else {
			struct pd_value new_val = {
				.cycles = delta,
			};
			bpf_map_update_elem(&counts_pid, &key, &new_val, BPF_ANY);
			/* ignore errors; we still want to update the counts_last entry */
		}

		/* make sure parent is up-to-date */
		struct pd_extra *extra_ptr;
		extra_ptr = bpf_map_lookup_elem(&task_extra, &key.tgid);
		if (extra_ptr == NULL) {
			/* should not happen because iter/task or exec would have recorded this */
			init_extra(prev, &key);
		} else if (extra_ptr->parent.tgid != prev->real_parent->tgid) {
			extra_ptr->parent.tgid = prev->real_parent->tgid;
		}
	}
	/* always update count_last value */
	*count_last = buf.counter;

	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm) {
	struct pd_key key;
	struct pd_extra extra;

	key.tgid = p->tgid;

	/* copy info */
	init_extra(p, &key);

	return 0;
}
