# Veil

Veil is an eBPF-based Linux observability tool written in Go. It attaches to
kernel and userspace hooks -- tracepoints, kprobes, and uprobes -- to trace
system calls, file access, TCP connections, context switches, page faults,
and userspace function calls, with kernel-side filtering that keeps overhead
low.

## Features

- **Kernel-level filtering.** Events are matched against BPF hash maps before
  they reach userspace. Filters have allow and deny variants, and deny wins.
- **Runtime filter modification.** Add, remove, or clear filters while tracing
  runs, via an interactive prompt or a Unix control socket -- no restart.
- **Concurrent modules.** Run several modules at once and share one output
  stream.
- **Flexible output.** Text or JSON, with optional enrichment (timestamps,
  process and user names) and a count/summary mode for top-N aggregation.
- **Terminal-friendly CLI.** Colorized diagnostics with per-module tinting,
  bash/zsh completion, and "did you mean" suggestions for mistyped names.
- **Portable objects.** CO-RE with pinned BTF, built per architecture
  (x86_64, arm64). The generated objects are committed, so a plain build needs
  no BPF toolchain.

## Modules

- **syscall** -- system calls, via the `raw_syscalls/sys_enter` tracepoint.
- **files** -- file open, read, and write, via kprobes on the `vfs_*` layer.
- **network** -- TCP connection lifecycle (IPv4), via the
  `inet_sock_set_state` tracepoint and kprobes.
- **scheduler** -- context switches, via the `sched_switch` tracepoint.
- **memory** -- major and minor page faults, via a kprobe/kretprobe pair on
  `handle_mm_fault`.
- **uprobe** -- userspace function calls on a chosen `binary:symbol`, with
  optional call-latency measurement via a uretprobe.

## Quickstart

Veil runs on Linux 5.8+ (for BTF and ring buffer maps) and needs root, or
`CAP_BPF` + `CAP_PERFMON`, to load its programs.

```bash
make                 # generate BPF objects + build -> bin/veil
make help            # list all available targets
sudo ./bin/veil --module syscall --pid $(pidof nginx)
```

Building from source needs Go 1.18+, and regenerating the BPF objects needs
Clang 14+ and bpftool. The generated objects are committed, so `go build
./cmd/veil` works without the BPF toolchain when you are not changing the C.

To put `veil` on your `PATH` with bash and zsh completion:

```bash
sudo make install                  # or: make install PREFIX=$HOME/.local
```

See [Shell Completion](docs/USAGE.md#shell-completion) for details.

## Examples

```bash
# Trace syscalls from nginx, exclude ioctl noise
sudo ./bin/veil --module syscall -p $(pidof nginx) --syscall '!ioctl'

# Watch file reads across the system with timestamps
sudo ./bin/veil --module files --op read --enrich time

# Trace TCP connections to port 443, output as JSON
sudo ./bin/veil --module network --port 443 --output json

# Profile context switches on CPU 0-3
sudo ./bin/veil --module scheduler --cpu 0,1,2,3

# Trace major page faults only
sudo ./bin/veil --module memory --fault major

# Time a libc call for one process
sudo ./bin/veil --module uprobe --uprobe /lib/x86_64-linux-gnu/libc.so.6:malloc --latency -p 1234

# Run multiple modules concurrently
sudo ./bin/veil --module syscall,network,files --enrich all
```

> [!NOTE]
> Wrap `!` filters in single quotes. In an interactive shell bash treats `!`
> as [history expansion](https://www.gnu.org/software/bash/manual/html_node/History-Interaction.html)
> and will rewrite the argument before Veil sees it.

## Documentation

See [`docs/USAGE.md`](docs/USAGE.md) for the complete CLI reference with
practical examples.

## License

GPLv3
