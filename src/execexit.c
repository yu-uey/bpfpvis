// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "execexit.h"
#include "execexit.skel.h"
#include <ncurses.h>

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF bootstrap demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
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

enum colcolor {
	CC_DEFAULT, /* to make useful pairs start at 1 */
	CC_EXEC,
	CC_EXIT,
};
struct column {
	size_t len;
	size_t oldlen;
	char *text;
	int pos;
	int ticks;
	int speed;
	enum colcolor color;
	pid_t pid;
};

struct context {
	int ncols;
	int nrows;
	struct column *cols;
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int find_column(const struct context *c, pid_t pid) {
	/* try to find matching PID */
	for (int i = 0; i < c->ncols; i++) {
		if (c->cols[i].pid == pid) {
			return i;
		}
	}
	/* otherwise, use random column */
	int col = -1;
	const int r = rand() % c->ncols;
	for (int i = r; i < c->ncols; i++) {
		if (c->cols[i].pos < -1) {
			col = i;
			break;
		}
	}
	if (col < 0) {
		for (int i = 0; i < r; i++) {
			if (c->cols[i].pos < -1) {
				col = i;
				break;
			}
		}
	}
	/* set typical values */
	if (col >= 0) {
		c->cols[col].pid = pid;
		c->cols[col].pos = -1;
		c->cols[col].ticks = 0;
		c->cols[col].speed = 10;
	}
	return col;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct context *c = ctx;
	const struct event *e = data;
	int col;

	/* if column for pid exists, re-use that */
	col = find_column(ctx, e->pid);
	if (col < 0) return 0;

	/* these fields describe the process and are updated on exec */
	c->cols[col].text = strdup(e->comm);
	c->cols[col].len = strlen(e->comm);
	c->cols[col].color = (e->exit_event) ? CC_EXIT : CC_EXEC;
	/* oldlen = max(new len, previous len) */
	if (c->cols[col].oldlen < c->cols[col].len ) {
		c->cols[col].oldlen = c->cols[col].len;
	}

	/* exit event => adjust speed based on lifetime */
	if (e->exit_event) {
		double x = e->duration_ns ;
		x /= x + (1000 * 1000000ULL);
		x = x * 10;
		c->cols[col].speed = (int)x;
	}

	return 0;
}

void init_col(struct column *col) {
	col->text = NULL;
	col->len = 0;
	col->oldlen = 0;
	col->pos = -2;
	col->ticks = 0;
	col->color = CC_DEFAULT;
	col->pid = -1;
}
void free_col(struct column *col) {
	free(col->text);
}

void set_scrsz(struct context *ctx) {
	getmaxyx(stdscr, ctx->nrows, ctx->ncols);
	free(ctx->cols);
	ctx->cols = malloc(ctx->ncols * sizeof(struct column));
	for (int i = 0; i < ctx->ncols; i++) {
		init_col(&ctx->cols[i]);
	}
}

void setup_display(struct context *ctx) {
	initscr();
	noecho();
	cbreak();
	curs_set(0);
	set_scrsz(ctx);
	if (has_colors()) {
		start_color();
		use_default_colors();
		init_pair(CC_EXEC, COLOR_GREEN, -1); /* exec */
		init_pair(CC_EXIT, COLOR_RED, -1); /* exit */
	}
}

void update_display(struct context *ctx) {
	for (int x = 0; x < ctx->ncols; x++) {
		struct column *col = &ctx->cols[x];

		/* column not falling */
		if (col->pos < -1) continue;

		/* tick for update */
		col->ticks ++;
		if (col->ticks < col->speed) continue;
		col->ticks = 0;
		col->pos ++;
		if (col->pos >= ctx->nrows + col->len) {
			free_col(col);
			init_col(col);
			continue;
		}

		attron(COLOR_PAIR(col->color));
		/* add bottom */
		mvaddch(col->pos, x, col->text[col->pos % col->len]);
		/* decay top, decaying extra if column was previously longer */
		if (col->oldlen > col->len) {
			mvaddch(col->pos - col->oldlen, x, ' ');
			col->oldlen --;
		}
		mvaddch(col->pos - col->oldlen, x, ' ');
		attroff(COLOR_PAIR(col->color));
	}
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct execexit_bpf *skel;
	int err;

	/* state for display */
	struct context ctx = {0};

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
	skel = execexit_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = execexit_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = execexit_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &ctx, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Set up ncurses */
	setup_display(&ctx);

	/* Process events */
	while (!exiting) {
		/* consume without waiting */
		err = ring_buffer__consume(rb);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}

		update_display(&ctx);
		refresh();
		napms(25);
	}
	endwin();

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	execexit_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
