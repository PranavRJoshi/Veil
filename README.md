# Veil

A kernel observability and analysis toolkit built on eBPF. Designed to teach eBPF concepts through practical, real-world problem solving.

## What It Does

Veil is a collection of eBPF modules, each targeting a specific kernel subsystem. Each module is both a learning exercise and a useful diagnostic tool:

| Module | Purpose |
|---|---|
| `syscall` | Per-process syscall frequency tracking and anomaly detection |
| `network` | Flow-level network monitoring without full packet capture |
| `files` | File access auditing with full path resolution |
| `scheduler` | CPU run queue latency profiling |
| `memory` | OOM event inspection and page fault tracing |

## Requirements

| Dependency | Minimum Version | Notes |
|---|---|---|
| Go | 1.18 | Toolchain for userspace code |
| Clang | 14.0 | BPF C compilation |
| Linux kernel | 5.4 | Required for BTF and CO-RE support |
| bpftool | any | Used to generate `vmlinux.h` from running kernel |
| cilium/ebpf bpf2go | v0.11.0 | Code generation tool, install via `go install` |

## Setup

```bash
# Install bpf2go
go install github.com/cilium/ebpf/cmd/bpf2go@v0.11.0

# Export GOPATH to PATH environment variable
# Skip this if you already have GOPATH in PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Build
make
```

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
│   ├── events          # Shared kernel event types
│   ├── exterrs         # error method
│   └── loader          # BPF program lifecycle management
└── modules/            # One package per kernel subsystem
    ├── syscall
    ├── files
    └── network
```

## Stack

- **Userspace**: Go + `cilium/ebpf`
- **Kernel-side**: C compiled to BPF bytecode via Clang
- **Portability**: CO-RE (Compile Once – Run Everywhere) via BTF — no kernel headers needed at runtime
