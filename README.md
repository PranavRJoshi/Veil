# Veil

Veil is an eBPF-based Linux kernel observability toolkit written in Go. It attaches to kernel hooks--tracepoints, kprobes, kretprobes--to trace system calls, file operations, TCP connections, context switches, and page faults with near-zero overhead.

Events are filtered at the kernel level using BPF hash maps before they ever reach userspace. Filters can be modified at runtime without restarting the tracer.

## What It Does

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

# Run multiple modules concurrently
sudo ./bin/veil --module syscall,network,files --enrich all
```

## Modules

| Module | What it traces | Kernel hooks | Key filters |
|---|---|---|---|
| `syscall` | System calls | `tracepoint/raw_syscalls/sys_enter` | `--syscall`, `--pid`, `--uid` |
| `files` | File open/read/write | `kprobe/vfs_open`, `vfs_read`, `vfs_write` | `--op`, `--file`, `--pid` |
| `network` | TCP lifecycle | `tracepoint/sock/inet_sock_set_state` + kprobes | `--port`, `--pid` |
| `scheduler` | Context switches | `tracepoint/sched/sched_switch` | `--cpu`, `--pid` |
| `memory` | Page faults | `kprobe`/`kretprobe` on `handle_mm_fault` | `--fault`, `--pid` |

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │                  Kernel                     │
                    │                                             │
                    │   tracepoint ──> BPF program ──> filter     │
                    │   kprobe ──────> BPF program     maps       │
                    │                       │                     │
                    │                  ring buffer                │
                    └───────────────────────┬─────────────────────┘
                                            │
                    ┌───────────────────────┼─────────────────────┐
                    │               Userspace (Go)                │
                    │                       │                     │
                    │               ringbuf.Reader                │
                    │                       │                     │
                    │              parseEvent (binary)            │
                    │                       │                     │
                    │              userspace filters              │
                    │                       │                     │
                    │    ┌──────────────────┼──────────────────┐  │
                    │    │           EventSink pipeline        │  │
                    │    │                                     │  │
                    │    │  PausableSink > EnrichSink > Output │  │
                    │    │                                │    │  │
                    │    │                            TextSink │  │
                    │    │                            JSONSink │  │
                    │    │                            CountSink│  │
                    │    └─────────────────────────────────────┘  │
                    │                                             │
                    │    ┌──────────────────────────────────────┐ │
                    │    │        Runtime control               │ │
                    │    │  interactive prompt / Unix socket    │ │
                    │    │  > add/del/list/clear filter keys    │ │
                    │    └──────────────────────────────────────┘ │
                    └─────────────────────────────────────────────┘
```

Every module follows the same pattern: a BPF C program defines the kernel-side hook and filter maps, a Go package implements `loader.Program` and `runner.Module`, and an `init()` function self-registers with the module registry. Adding a new module requires no changes to the core; just a blank import in `main.go`.

## Key Design Decisions

**Deny-first filtering.** Every filter map has an allow and deny variant. Deny is checked before allow in the BPF program, so `--pid 100 --pid '!100'` drops PID 100. The `!` prefix in CLI flags drives this via `splitAllowDeny`.

> [!NOTE]
> During interactive mode, handle the use of `!` character with care as it is interpreted by bash as [_History Expansion_](https://www.gnu.org/software/bash/manual/html_node/History-Interaction.html). As shown in example, wrap the argument inside single quotes.

**Ring buffer over perf buffer.** All modules use `BPF_MAP_TYPE_RINGBUF` (shared, variable-size, no per-CPU waste) rather than perf event arrays.

**Composable output pipeline.** Modules emit to an `EventSink` interface. Sinks compose: `PausableSink` wraps the formatter, `EnrichSink` adds `/proc`-derived fields, `CountSink` aggregates for summary mode. Modules don't know which sinks are active.

**Runtime filter modification.** Every module implements the `MapUpdater` interface, which lets the control server (interactive prompt or Unix socket) add, delete, list, or clear BPF map entries while tracing continues.

## Requirements

| Dependency | Version | Purpose |
|---|---|---|
| Go | 1.18+ | Userspace toolchain |
| Clang | 14.0+ | BPF C compilation |
| Linux kernel | 5.4+ | BTF and CO-RE support |
| bpftool | any | Generates `vmlinux.h` from running kernel |

Veil requires root privileges (or `CAP_BPF` + `CAP_PERFMON`) to load eBPF programs.

## Building

```bash
make                # generate BPF code + build binary
make generate       # BPF code generation only
make build          # Go build only
make clean          # remove generated files and binary
```

`make generate` requires `bpftool` and `clang`. It produces `vmlinux.h` from the running kernel's BTF data and runs `bpf2go` to compile the BPF C programs into Go-embeddable objects.

## Testing

```bash
go test ./internal/... -v     # core infrastructure, no root needed
go test ./modules/... -v      # module-level, needs go generate first
```

Tests cover binary parsing round-trips, filter configuration, output field mapping, and control command dispatch. They do not require root or BPF, they test the Go-side logic using constructed byte buffers.

## Documentation

See [`docs/USAGE.md`](docs/USAGE.md) for the complete CLI reference with practical examples.

## Project Structure

```
Veil/
├── bpf/                # eBPF C programs (kernel-side)
│   └── headers         # vmlinux.h and shared BPF headers
├── cmd/                # CLI
│   ├── gen/            # parse unistd.h from host and gen syscall table
│   │   └── syscalls
│   └── veil            # main CLI application
├── internal/
│   ├── cli             # Command-line argument parser
│   ├── control         # Interactive and socket control interface
│   ├── count           # Count-only mode (suppresses default output)
│   ├── enrich          # Event enrichment middleware
│   ├── events          # Shared event types
│   ├── exterrs         # errors.Join polyfill
│   ├── loader          # BPF program lifecycle
│   ├── output          # Output sink pipeline (text, JSON)
│   ├── registry        # Module self-registration
│   └── runner          # Multi-module orchestration
└── modules/
    ├── files           # File access tracing
    ├── memory          # Memory fault tracing
    ├── network         # TCP connection tracing
    ├── scheduler       # Context switch tracing
    └── syscall         # System call tracing
```

## License

GPLv3
