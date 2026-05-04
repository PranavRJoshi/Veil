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

## Features
 
### Multi-Module Tracing

Run multiple modules concurrently with interleaved output:
 
```bash
sudo ./bin/veil --module syscall,network --pid 1234
sudo ./bin/veil --module syscall,files,network --enrich all --output json
```

### Kernel-Side Filtering
 
PID, UID, port, and syscall filters operate in BPF; filtered events never reach userspace. Supports both allow and deny (negation) filters:
 
```bash
# Allow filters
sudo ./bin/veil --module syscall -p 1234,5678
sudo ./bin/veil --module network --port 80,443
 
# Deny (negation) filters — prefix with !
sudo ./bin/veil --module syscall --pid '!1'          # exclude PID 1
sudo ./bin/veil --module network --port '!22'        # exclude SSH
sudo ./bin/veil --module syscall --syscall '!ioctl'  # exclude ioctl
 
# Combined: allow root only, but exclude PID 100
sudo ./bin/veil --module syscall --uid 0 --pid '!100'
```

> [!NOTE]
> During interactive mode, handle the use of `!` character with care as it is interpreted by bash as [_History Expansion_](https://www.gnu.org/software/bash/manual/html_node/History-Interaction.html). As shown in example, wrap the argument inside single quotes.

Deny filters are checked before allow; if an event matches a deny entry, it is dropped regardless of allow filters.

### Event Enrichment

Add derived fields to events with `--enrich`:

```bash
sudo ./bin/veil --module syscall --enrich time           # timestamps
sudo ./bin/veil --module syscall --enrich time,user      # timestamps + usernames
sudo ./bin/veil --module network --enrich all            # everything
```

Output with `--enrich all`:

```
[14:32:05.123] bash             PID=1234   TID=1234   UID=0     GID=0     syscall=openat(257) user=root proc=bash
```

### Output Formats
 
**Text** (default), one line per event:
 
```
systemd-journal  PID=432    TID=432    UID=0     GID=0     syscall=ioctl(29)
systemd-journal  PID=432    TID=432    UID=0     GID=0     syscall=ioctl(29)
systemd-journal  PID=432    TID=432    UID=0     GID=0     syscall=ioctl(29)
systemd-journal  PID=432    TID=432    UID=0     GID=0     syscall=ioctl(29)
systemd-journal  PID=432    TID=432    UID=0     GID=0     syscall=ioctl(29)
...
cat              PID=245377 UID=502   op=open  filename=hosts
cat              PID=245377 UID=502   op=read  filename=hosts
cat              PID=245377 UID=502   op=read  filename=hosts
...
...
nc               PID=245466 LISTEN       0.0.0.0:1234 -> 0.0.0.0:0 [CLOSE->LISTEN]
nc               PID=245471 CONNECT      127.0.0.1:5432 -> 127.0.0.1:1234 [CLOSE->SYN_SENT]
nc               PID=245471 ESTABLISHED  127.0.0.1:5432 -> 127.0.0.1:1234 [SYN_SENT->ESTABLISHED]
nc               PID=245466 ESTABLISHED  127.0.0.1:1234 -> 127.0.0.1:5432 [SYN_RECV->ESTABLISHED]
nc               PID=245471 CLOSE        127.0.0.1:5432 -> 127.0.0.1:1234 [ESTABLISHED->FIN_WAIT1]
nc               PID=245466 CLOSE        127.0.0.1:1234 -> 127.0.0.1:5432 [ESTABLISHED->CLOSE_WAIT]
```
 
**JSON** (`--output json`), one JSON object per line, suitable for
piping to `jq` or ingesting into monitoring systems:
 
```bash
sudo ./bin/veil --module syscall --output json | jq '.syscall'
sudo ./bin/veil --module network --output json >> /var/log/veil-network.jsonl
```

### Runtime Filter Control
 
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
│   ├── exterrs         # errors.Join polyfill
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
