# BPF Process Visualizer

A simple program to display some live process information, with a BPF backend. Code based on [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap).

### `cpugraph.c`
Produces a flame/icicle graph of processes, arranged hierarchically by parent (PPID). It uses the `PERF_COUNT_HW_CPU_CYCLES` perf event to track CPU cycles and attributes them to processes at the `tp_btf/sched_switch` tracepoint. A `iter/task` iterator is used to initialize this hierarchy and include processes that may not go on the CPU.

The ncurses display is slightly interactive: the spacebar pauses the display, and allows the user to recursively "zoom in" on a process, selecting from its children using arrow keys. Backspace zooms out / unpauses.

Future plans may include:
- Command-line options to adjust sampling interval
- Visual continuity between frames for the same process, with easing or color/symbol hash to allow the process to make clear it is the same process in both frames.


### `bootstrap.c`
Inspired by [CMatrix](https://github.com/abishekvashok/cmatrix). Tracks `tp_btf/sched_process_exec` and `tp_btf/sched_process_exit` events using a ring buffer, and outputs them as "digital rain" in ncurses. The bpf tracepoint code is largely unchanged from libbpf-bootstrap (though modified to use BTF).


## Dependencies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## Building

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules <URL>
```

Makefile build:
```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd src
$ make
$ sudo ./cpugraph
```
