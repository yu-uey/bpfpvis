// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <unistd.h>
#include "cpugraph.h"
#include "cpugraph.skel.h"

static struct env {
	bool verbose;
} env;

const char *argp_program_version = "cpugraph 0.0";
const char *argp_program_bug_address = "<>";
const char argp_program_doc[] = "CPU graph"
				"\n"
				"It shows process CPU cycle share.\n"
				"\n"
				"USAGE: ./cpugraph [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int sample(const struct bpf_map *map) {
	int err;
	const int ncpus = libbpf_num_possible_cpus();

	struct pd_key key;
	void *prev = NULL;

	while (err = bpf_map__get_next_key(map, prev, &key, sizeof(key)), err == 0) {
		prev = &key;

		/* read counter and sum across cpus */
		/* atomically delete reading to measure within the interval only */
		struct pd_value percpu[ncpus];
		struct pd_value agg;
		err = bpf_map__lookup_and_delete_elem(map, &key, sizeof(key), &percpu, sizeof(percpu), 0);
		if (err < 0) {
			fprintf(stderr, "Lookup elem: %s\n", strerror(-err));
			continue;
		}
		for (int cpu = 0; cpu < ncpus; cpu++) {
			agg.cycles += percpu[cpu].cycles;
		}

		printf("%d (%d): %lld\n", key.tgid, key.ptgid, agg.cycles);
	}
	if (err != -ENOENT) {
		fprintf(stderr, "Failed to get next key: %s\n", strerror(-err));
		return -1;
	}

	return 0;
}

int setup_perf_events(const struct bpf_map *map) {
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(struct perf_event_attr),
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};

	int ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0) {
		return -1;
	}

	for (int cpu = 0; cpu < ncpus; cpu++) {
		/* open perf event fd */
		int fd = syscall(SYS_perf_event_open, &attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (fd < 0) {
			fprintf(stderr, "Failed to open perf event for cpu %d: %s\n", cpu, strerror(errno));
			return -1;
		}

		/* put in map */
		int rc = bpf_map__update_elem(map, &cpu, sizeof(cpu), &fd, sizeof(fd), BPF_ANY);
		if (rc < 0) {
			fprintf(stderr, "Failed to store perf fd for cpu %d: %s\n", cpu, strerror(errno));
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct cpugraph_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = cpugraph_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = cpugraph_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Set up perf events */
	err = setup_perf_events(skel->maps.perf);
	if (err) {
		fprintf(stderr, "Failed to open perf events\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = cpugraph_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Read start time for accurate intervals */
	struct timespec wait_until;
	err = clock_gettime(CLOCK_MONOTONIC, &wait_until);
	if (err) {
		fprintf(stderr, "Failed to wait: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Main loop */
	while (!exiting) {
		err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &wait_until, NULL);
		if (err == EINTR) {
			continue;
		}
		if (err) {
			fprintf(stderr, "Failed to sleep: %s\n", strerror(err));
			goto cleanup;
		}

		err = sample(skel->maps.counts_pid);
		if (err) {
			goto cleanup;
		}

		/* Wait accurately, in case we want rolling averages later */
		wait_until.tv_nsec += 2000 * 1000000L;
		while (wait_until.tv_nsec >= 1000000000L) {
			wait_until.tv_nsec -= 1000000000L;
			wait_until.tv_sec += 1;
		}
	}

cleanup:
	/* Clean up */
	cpugraph_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
