// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <unistd.h>
#include <ncurses.h>
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

/* simple tree implementation */
struct ptree_node {
	struct pd_key key;
	struct pd_value value;
	struct pd_extra extra;
	struct ptree_node *parent;
	struct ptree_node **children;
	size_t n_children;
	size_t cap_children;
};
/* allocates a new root node with the inserted data */
struct ptree_node *ptree_new(struct pd_key key, struct pd_value value, struct pd_extra extra) {
	struct ptree_node *node = malloc(sizeof(*node));
	if (node == NULL) {
		fprintf(stderr, "Failed malloc node: %s\n", strerror(errno));
		return NULL;
	}
	node->key = key;
	node->value = value;
	node->extra = extra;
	node->parent = NULL;
	node->children = NULL;
	node->n_children = 0;
	node->cap_children = 0;
	return node;
}
void ptree_free(struct ptree_node *node, bool recursive) {
	if (node == NULL) {
		return;
	}
	if (recursive) {
		for (int i = 0; i < node->n_children; i++) {
			ptree_free(node->children[i], true);
		}
	}
	free(node->children);
	free(node);
}
int ptree_parent(struct ptree_node *parent, struct ptree_node *child) {
	/* no reparent if already parent */
	/* ignore NULL parent because this tree only implements insert */
	if (!parent || !child || parent == child->parent) {
		return 0;
	}
	/* reallocate array (0 => 1, n => 2n)*/
	if (!parent->children || parent->n_children >= parent->cap_children) {
		parent->cap_children = (parent->cap_children) ? parent->cap_children << 1 : 1;
		parent->children = reallocarray(parent->children, parent->cap_children, sizeof(*parent->children));
		if (parent->children == NULL) {
			fprintf(stderr, "Failed realloc: %s\n", strerror(errno));
			return -1;
		}
	}
	/* insert child */
	parent->children[parent->n_children] = child;
	child->parent = parent;
	parent->n_children++;
	return 0;
}

/* Simple hash map implementation
 * - Insert-only, no delete (empty instead)
 * - Assumes all inserted values > 0 */
enum {
	PMAP_POW = 13,
	PMAP_SIZE = (size_t)1 << PMAP_POW,
};
static struct {
	struct pd_key keys[PMAP_SIZE];
	struct ptree_node *values[PMAP_SIZE];
	struct ptree_node *zero_value;
} pmap;
/* return pointer to where element is or should be set, and NULL if full
 * Uses linear probing with fibonacci hash */
static struct ptree_node **pmap_get(struct pd_key *key) {
	__u32 hash;
	__u32 i;

	if (key->tgid == 0) {
		return &pmap.zero_value;
	}

	hash = (key->tgid * 0x9E3779B97F4A7C15ULL) >> (64 - PMAP_POW);

	for (int j = 0; j < PMAP_SIZE; j++) {
		i = (hash + j) & (PMAP_SIZE - 1);

		/* a 0 key entry means empty, since real key=0 is handled above */
		if (pmap.keys[i].tgid == 0) {
			pmap.keys[i].tgid = key->tgid;
		}
		if (pmap.keys[i].tgid == key->tgid) {
			return &pmap.values[i];
		}
	}
	return NULL;
}
static void pmap_clear() {
	memset(&pmap.zero_value, 0, sizeof(pmap.zero_value));
	memset(pmap.keys, 0, sizeof(pmap.keys));
	memset(pmap.values, 0, sizeof(pmap.values));
}


int sample(const struct bpf_map *counter_map, const struct bpf_map *extra_map) {
	int err = 0;
	bool done = false;

	ptree_free(pmap.zero_value, true); /* leak orphans */
	pmap_clear();

	const int ncpus = libbpf_num_possible_cpus();
	const __u32 batch_size = 2048;
	struct pd_value (*values)[ncpus];
	struct pd_key *keys;

	keys = malloc(batch_size * sizeof(*keys));
	if (keys == NULL) {
		fprintf(stderr, "Failed to allocate batch keys: %s\n", strerror(errno));
		err = -1;
		goto cleanup;
	}
	values = malloc(batch_size * ncpus * sizeof(*values));
	if (values == NULL) {
		fprintf(stderr, "Failed to allocate batch values: %s\n", strerror(errno));
		err = -1;
		goto cleanup;
	}

	int counter_map_fd = bpf_map__fd(counter_map);
	void *batch_pos = NULL;
	__u32 next_batch;
	__u32 count;
	LIBBPF_OPTS(bpf_map_batch_opts, batch_opts); /* no extra flags */

	while (!done) {
		count = batch_size;
		err = bpf_map_lookup_and_delete_batch(
			counter_map_fd,
			batch_pos, &next_batch,
			keys, values, 
			&count,
			&batch_opts
		);
		if (err == -ENOENT) {
			done = true;
		} else if (err < 0) {
			/* if err != EFAULT, count elements were copied successfully. We ignore them */
			fprintf(stderr, "Failed lookup: %s\n", strerror(errno));
			goto cleanup;
		}
		batch_pos = &next_batch;

		/* process each entry in the batch */
		for (__u32 i = 0; i < count; i++) {
			struct pd_key *key = &keys[i];
			struct pd_value *percpu = values[i];

			/* read counter and sum across cpus */
			struct pd_value agg = {0};

			for (int cpu = 0; cpu < ncpus; cpu++) {
				agg.cycles += percpu[cpu].cycles;
			}

			/* walk up ancestry and add to their counters too */
			struct pd_key next_key = *key;
			struct pd_extra extra;
			struct ptree_node *prev_node = NULL;
			struct ptree_node **next_node = NULL; /* pointer inside map for writing */
			while (true) {
				/* lookup process information, including parent */
				err = bpf_map__lookup_elem(
					extra_map,
					&next_key, sizeof(next_key),
					&extra, sizeof(extra),
					0
				);
				if (err < 0) {
					fprintf(stderr, "Lookup extra %d: %s\n", next_key.tgid, strerror(-err));
					continue;
				}

				/* fetch node from map. NULL means no space */
				next_node = pmap_get(&next_key);
				if (next_node == NULL) {
					fprintf(stderr, "Failed userspace map lookup\n");
					continue;
				}
				/* if unset in map, allocate new node */
				if (*next_node == NULL) {
					struct pd_value z = {0};
					*next_node = ptree_new(next_key, z, extra);
					if (*next_node == NULL) {
						continue;
					}
				}
				/* add prev_node as a child to this new parent */
				/* returns silently for first iteration, when prev_node=NULL*/
				ptree_parent(*next_node, prev_node);

				struct pd_value *record = &(*next_node)->value;
				record->cycles += agg.cycles;

				/* continue to parent, or terminate if we just saw PID=0 */
				if (next_key.tgid == 0) {
					break;
				}
				next_key = extra.parent;
				prev_node = *next_node;
			}
		}
	}

	err = 0;

cleanup:
	free(keys);
	free(values);

	return (err < 0) ? -1 : 0;
}

void setup_display() {
	initscr();
	noecho();
	cbreak();
	curs_set(0);
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);
	if (has_colors()) {
		start_color();
		use_default_colors();
		init_pair(1, COLOR_BLUE, -1);
		init_pair(2, COLOR_RED, -1);
	}
}
void draw_recurse(int row, int col, int width, struct ptree_node *node, bool color, struct ptree_node *highlight) {
	if (width <= 0) {
		return;
	}
	/* draw this row full width */
	attr_t attr = COLOR_PAIR(1)
	              | (color ? A_BOLD : A_DIM)
	              | (node == highlight ? A_BLINK : 0);
	attron(attr);
	move(row, col);
	for (int i = 0; i < width; i++) {
		addch(ACS_BLOCK);
	}
	attroff(attr);

	/* recurse children */
	unsigned long long offset = 0;
	bool child_color = false;
	for (int i = 0; i < node->n_children; i++) {
		struct ptree_node *child = node->children[i];
		int child_width = width * child->value.cycles / node->value.cycles;
		int child_offset = width * offset / node->value.cycles;
		if (child_width > 0) {
			draw_recurse(row+1, col+child_offset, child_width, child, child_color, highlight);
			child_color = !child_color;
		}
		offset += child->value.cycles;
	}
}
/* Displays the data living in pmap */
void visualize(struct ptree_node *root, struct ptree_node *highlight) {
	int maxx;
	int y = 0;
	maxx = getmaxx(stdscr);
	erase();
	if (root != NULL) {
		mvprintw(
			y++, 0,
			"Children of PID %d (%d:%d): %s",
			root->key.tgid,
			root->extra.uid, root->extra.gid,
			root->extra.comm
		);
		if (highlight != NULL) {
			mvprintw(
				y++, 0,
				"Select child? %d: %s",
				highlight->key.tgid,
				highlight->extra.comm
			);
		}
		draw_recurse(y, 0, maxx, root, false, highlight);
	}
	refresh();
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

void enter_pause(struct ptree_node *root) {
	if (root == NULL) return;

	int pos = 0;

	while (true) {
		switch (getch()) {
		case KEY_LEFT:
			if (pos > 0)
				pos--;
			break;
		case KEY_RIGHT:
			if (pos < root->n_children - 1)
				pos++;
			break;
		case ' ':
			/* pause on current selection */
			if (pos < root->n_children) {
				enter_pause(root->children[pos]);
			}
			break;
		case 127:
		case '\b':
		case KEY_BACKSPACE:
			/* unpause */
			return;
		}

		visualize(root, (pos < root->n_children ? root->children[pos] : NULL));
	}
}

int main(int argc, char **argv)
{
	struct cpugraph_bpf *skel;
	int iter_fd = -1;
	char iter_buf; /* iterator does not write to seq_file, so buf is ceremonial */
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

	/* Run iterator to set initial parents */
	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.iter_for_parents));
	if (iter_fd < 0) {
		fprintf(stderr, "Failed to create iterator\n");
		err = -1;
		goto cleanup;
	}
	while (true) {
		int n = read(iter_fd, &iter_buf, sizeof(iter_buf));
		if (n == 0) break;
		if (n < 0 && errno != EINTR && errno != EAGAIN) {
			fprintf(stderr, "Failed to read iterator\n");
			err = -1;
			goto cleanup;
		}
	}

	/* Read start time for accurate intervals */
	struct timespec wait_until;
	err = clock_gettime(CLOCK_MONOTONIC, &wait_until);
	if (err) {
		fprintf(stderr, "Failed to wait: %s\n", strerror(errno));
		goto cleanup;
	}

	setup_display();

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

		/* catch keys before updating */
		/* all keys emptied to prevent unexpected response */
		int ch;
		bool pause;
		while (ch = getch(), ch != ERR) {
			if (ch == ' ') {
				pause = true;
			}
		}
		if (pause) {
			pause = false;
			enter_pause(pmap.zero_value);
		}

		err = sample(skel->maps.counts_pid, skel->maps.task_extra);
		if (err) {
			goto cleanup;
		}
		visualize(pmap.zero_value, NULL);

		/* Wait accurately, in case we want rolling averages later */
		wait_until.tv_nsec += 500 * 1000000L;
		while (wait_until.tv_nsec >= 1000000000L) {
			wait_until.tv_nsec -= 1000000000L;
			wait_until.tv_sec += 1;
		}
	}

cleanup:
	/* Clean up */
	endwin();
	if (iter_fd >= 0) {
		close(iter_fd);
	}
	cpugraph_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
