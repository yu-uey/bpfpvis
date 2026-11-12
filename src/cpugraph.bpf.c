// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
	__type(key, __u32);
	__type(value, __u64);
} counts_pid SEC(".maps");


SEC("tp_btf/sched_switch")
int BPF_PROG(handle_switch, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state) {
	int error;
	struct bpf_perf_event_value buf;
	__u64 *count_last;
	__u64 *count_pid;
	__u64 delta;
	pid_t pid;
	const __u32 zero = 0;

	pid = prev->tgid;

	error = bpf_perf_event_read_value(&perf, BPF_F_CURRENT_CPU, &buf, sizeof(buf));
	if (error)
		return 0;

	/* calculate counter deltas for prev process */
	/* because delta is a percpu array, we update normally */
	count_last = bpf_map_lookup_elem(&counts_last, &zero);
	if (!count_last)
		return 0;

	if (*count_last) {
		delta = buf.counter - *count_last;

		/* update or set counter */
		count_pid = bpf_map_lookup_elem(&counts_pid, &pid);
		if (count_pid) {
			*count_pid += delta;
		} else {
			bpf_map_update_elem(&counts_pid, &pid, &delta, BPF_ANY);
		}
	}

	/* update last counter value */
	*count_last = buf.counter;
}
