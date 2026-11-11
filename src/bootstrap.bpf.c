// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 64);
} perf SEC(".maps");

/* holds the last perf event counter per cpu */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} counts_last SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, __u64);
} counts_delta SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm) {
	struct event *e;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = p->tgid;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	e->exit_event = false;
	e->pid = pid;
	e->ppid = p->real_parent->tgid;
	bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), p->comm);

	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), bprm->filename);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *p, bool group_dead) {
	struct event *e;
	pid_t pid, tid;
	u64 *start_ts, duration_ns = 0;

	/* clean up from perf */
	bpf_map_delete_elem(&counts_delta, &pid);

	/* get PID and TID of exiting thread/process */
	pid = p->tgid;
	tid = p->pid;

	/* ignore thread exits while other threads are still running */
	if (!group_dead)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = p->real_parent->tgid;
	e->exit_code = ((p->exit_code) >> 8) & 0xff;
	bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), p->comm);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_switch, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state) {
	int error;
	struct bpf_perf_event_value buf;
	__u64 *count_last;
	__u64 *count_delta;
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
		count_delta = bpf_map_lookup_elem(&counts_delta, &pid);
		if (count_delta) {
			*count_delta += delta;
		} else {
			bpf_map_update_elem(&counts_delta, &pid, &delta, BPF_ANY);
		}
	}

	/* update last counter value */
	*count_last = buf.counter;
}
