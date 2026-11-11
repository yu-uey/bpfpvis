# BPF Process "Visualizer"

Code based on [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap). The process exec and exit bpf tracepoint code is largely unchanged (though ported to BTF).

Inspired by the [CMatrix](https://github.com/abishekvashok/cmatrix) screensaver. Plenty of full-fledged tools for execsnoop already exist, so this project does not try to be a useful tool. For the most part, this is a just-for-fun piece of code to play around with BPF.

Processes `tp_btf/sched_process_exec` and `tp_btf/sched_process_exit` events using a ring buffer. CPU cycle counts are computed on the `tp_btf/sched_switch` tracepoint, reading from the `PERF_COUNT_HW_CPU_CYCLES` perf event. The userspace program takes this information from a per-CPU hash map on an interval.

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
$ sudo ./bootstrap
```
