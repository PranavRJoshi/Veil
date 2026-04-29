# Veil

Veil is an eBPF-based kernel observability toolkit for Linux. Trace system calls, file access, and TCP connections with minimal overhead.

## Quick Start

```bash
# Install dependencies
go install github.com/cilium/ebpf/cmd/bpf2go@v0.11.0
export PATH=$PATH:$(go env GOPATH)/bin
 
# Build
make
 
# Trace syscalls from a specific process
sudo ./bin/veil --module syscall -p $(pidof nginx)
 
# Trace all file reads
sudo ./bin/veil --module files --op read
 
# Trace TCP connections to port 443, output as JSON
sudo ./bin/veil --module network --port 443 --output json
```

## Requirements

## Requirements
 
| Dependency | Version | Purpose |
|---|---|---|
| Go | 1.18+ | Userspace toolchain |
| Clang | 14.0+ | BPF C compilation |
| Linux kernel | 5.4+ | BTF and CO-RE support |
| bpftool | any | Generates `vmlinux.h` from running kernel |
 
NOTE: Veil requires root privileges (or `CAP_BPF` + `CAP_PERFMON`) to load eBPF programs.

## Modules
 
| Module | Subsystem | Hooks |
|---|---|---|
| `syscall` | System calls | `tracepoint/raw_syscalls/sys_enter` |
| `files` | File access | `kprobe/vfs_open`, `vfs_read`, `vfs_write` |
| `network` | TCP connections | `tracepoint/sock/inet_sock_set_state`, kprobes |
 
Planned: `scheduler` (CPU run queue latency), `memory` (OOM, page faults).

## Usage
 
### Selecting a Module
 
```bash
sudo ./bin/veil --module <n> [flags...]
sudo ./bin/veil --list-modules          # show available modules
```
 
### Filtering
 
Filters reduce event volume at the source. PID, UID, and port filters operate in the kernel via BPF maps; filtered events never reach userspace.
 
```bash
# By PID (comma-separated for multiple)
sudo ./bin/veil --module syscall -p 1234,5678
 
# By UID
sudo ./bin/veil --module files -u 1000
 
# By process name (substring match, applied in userspace)
sudo ./bin/veil --module network -n curl
 
# Module-specific filters
sudo ./bin/veil --module syscall -s openat,read,write
sudo ./bin/veil --module files --op read --file passwd
sudo ./bin/veil --module network --port 80,443
```

### Output Formats
 
**Text** (default), one line per event:
 
```
[syscall] pid=1234   uid=0     comm=bash syscall=openat
[file access] pid=5678   uid=1000  comm=nginx           op=read   filename=nginx.conf
[network] pid=1234   uid=0     comm=curl             CONNECT      10.0.2.15:54268 -> 93.184.216.34:80 (CLOSE->SYN_SENT)
```
 
**JSON** (`--output json`), one JSON object per line, suitable for
piping to `jq` or ingesting into monitoring systems:
 
```bash
sudo ./bin/veil --module syscall --output json | jq '.syscall'
sudo ./bin/veil --module network --output json >> /var/log/veil-network.jsonl
```

### Interactive Control
 
Press **CTRL-C** during tracing to pause output and enter a control
prompt where you can modify filters at runtime:
 
```
^C
---  Veil Tracing Paused  ---

Veil interactive control (type 'help' for commands, 'resume' to continue tracing, 'quit' to exit)
veil $ add pid 1234
OK
veil $ resume
---  resumed (554 events dropped while paused)  ---
...
```
 
For external/scripted access, use `--control` to start a Unix socket:
 
```bash
sudo ./bin/veil --module network --control /tmp/veil.sock
# In another terminal:
echo "list port" | socat - UNIX-CONNECT:/tmp/veil.sock
```

NOTE: The above example uses `socat` binary. It's mirror is published in Github [here](https://github.com/3ndG4me/socat).

## Building
 
```bash
make                # generate BPF code + build binary
make generate       # BPF code generation only
make build          # Go build only
make clean          # remove generated files and binary
```

NOTE: `make generate` requires `bpftool` and `clang`. It produces `vmlinux.h` from the running kernel's BTF data and runs `bpf2go` to compile the C programs into Go-embeddable objects.

## Testing
 
```bash
go test ./internal/... -v     # always runnable, no root needed
go test ./modules/... -v      # needs go generate to have run first
```

Module tests cover binary parsing, filter configuration, and output field mapping. They do not require root or a running kernel; they test the Go-side logic using constructed byte buffers.

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
│   ├── enrich          # Event enrichment middleware
│   ├── events          # Shared event types
│   ├── exterrs         # error.Join polyfill
│   ├── loader          # BPF program lifecycle
│   ├── output          # Output sink pipeline (text, JSON)
│   ├── registry        # Module self-registration
│   └── runner          # Multi-module orchestration
└── modules/
    ├── syscall         # System call tracing
    ├── files           # File access tracing
    └── network         # TCP connection tracing
```

## License
 
GPLv3
