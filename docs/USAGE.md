# Veil Usage Reference

Complete CLI reference for all modules, flags, and features.

## Table of Contents

- [Global Flags](#global-flags)
- [Module Reference](#module-reference)
  - [syscall](#syscall-module)
  - [files](#files-module)
  - [network](#network-module)
  - [scheduler](#scheduler-module)
  - [memory](#memory-module)
  - [uprobe](#uprobe-module)
- [Filtering](#filtering)
  - [Allow Filters](#allow-filters)
  - [Deny Filters (Negation)](#deny-filters-negation)
  - [Combined Filters](#combined-filters)
  - [Filter Evaluation Order](#filter-evaluation-order)
- [Multi-Module Mode](#multi-module-mode)
- [Event Enrichment](#event-enrichment)
- [Output Formats](#output-formats)
- [Configuration File](#configuration-file)
  - [Profiles](#profiles)
  - [Validating a Config](#validating-a-config)
- [Count Mode](#count-mode)
- [Runtime Filter Control](#runtime-filter-control)
  - [Interactive Mode](#interactive-mode)
  - [Unix Socket Control](#unix-socket-control)
  - [Control Commands](#control-commands)
  - [Multi-Module Routing](#multi-module-routing)
- [Practical Recipes](#practical-recipes)

---

## Global Flags

| Flag | Description |
|---|---|
| `--module <name[,name...]>` | Module(s) to run (required unless `--config`). Comma-separated for multi-module. |
| `--config <path>` | Load the trace spec from a YAML file (governs modules and output). See [Configuration File](#configuration-file). |
| `--profile <name>` | Select a profile from the `--config` file (default: the file's `default`). See [Profiles](#profiles). |
| `--output <format>` | Output format: `text` (default) or `json`. |
| `--enrich <opts>` | Enrichment: `time`, `proc`, `user`, `all` (comma-separated). |
| `--fields <a,b,c>` | Project output to these fields (comma-separated); text becomes `key=value`, JSON keeps only these keys. |
| `--count` | Summary mode: suppress live output, show top-N on exit. |
| `--count-by <field>` | Override aggregation key (implies `--count`). |
| `--control <path>` | Start a Unix socket control server at the given path. |
| `--yes` | Skip the confirmation prompt for high-volume tracing (e.g. uprobe without a filter). |
| `--list-modules` | List available modules and exit. |
| `-h`, `--help` | Show help message. |

## Module Reference

### syscall module

Traces system calls via `tracepoint/raw_syscalls/sys_enter`.

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--pid <pid>` | `-p` | Filter by PID (comma-separated, supports `!` negation) |
| `--uid <uid>` | `-u` | Filter by UID (comma-separated, supports `!` negation) |
| `--name <name>` | `-n` | Filter by process name (substring match, userspace) |
| `--syscall <name>` | `-s` | Filter by syscall name or number (comma-separated, supports `!` negation) |

Syscall names are resolved using a generated table from the host's `unistd.h`. Both names and raw numbers work: `--syscall openat` and `--syscall 257` are equivalent on x86\_64.

**Output fields:** `comm`, `pid`, `tid`, `uid`, `gid`, `syscall`, `syscall_nr`, `timestamp`

**Examples:**

```bash
# Trace all syscalls from PID 1234
sudo ./bin/veil --module syscall -p 1234

# Trace openat and read calls from any nginx process
sudo ./bin/veil --module syscall -n nginx -s openat,read

# Trace everything except ioctl and futex (noisy syscalls)
sudo ./bin/veil --module syscall -s '!ioctl,!futex'

# Trace root-only syscalls, excluding PID 1
sudo ./bin/veil --module syscall -u 0 -p '!1'
```

---

### files module

Traces file open, read, and write operations via kprobes on `vfs_open`, `vfs_read`, and `vfs_write`. The `filename` field contains the full absolute path resolved by walking the kernel dentry chain at event time.

**Flags:**

| Flag | Description |
|---|---|
| `--pid <pid>` | Filter by PID (comma-separated, supports `!` negation) |
| `--uid <uid>` | Filter by UID (comma-separated, supports `!` negation) |
| `--name <name>` | Filter by process name (substring match, userspace) |
| `--op <op>` | Filter by operation: `open`, `read`, `write` (comma-separated) |
| `--file <path>` | Filter by path (userspace, path-aware -- see below) |

**`--file` matching modes:**

The filter value's shape determines how it is matched against the full absolute path:

| Filter value | Mode | Matches | Does not match |
|---|---|---|---|
| `/etc/hosts` | Exact path | `/etc/hosts` | `/usr/etc/hosts`, `/etc/hosts.bak` |
| `/etc/` | Directory prefix | `/etc/hosts`, `/etc/passwd` | `/usr/etc/hosts` |
| `etc/hosts` | Path suffix | `/etc/hosts` | `/usr/share/hosts` |
| `hosts` | Substring | `/etc/hosts`, `/var/lib/hosts` | `/etc/shadow` |

A leading `/` anchors the match to the path root. A trailing `/` matches everything under that directory. A value containing `/` but not leading anchors to a path suffix. A plain name matches anywhere in the path.

**Output fields:** `comm`, `pid`, `uid`, `op`, `filename` (absolute path), `timestamp`

**Examples:**

```bash
# Watch all file opens
sudo ./bin/veil --module files --op open

# Watch reads to any file under /etc (directory prefix)
sudo ./bin/veil --module files --op read --file /etc/

# Watch access to exactly /etc/passwd
sudo ./bin/veil --module files --file /etc/passwd

# Watch access to any file named hosts anywhere on the filesystem
sudo ./bin/veil --module files --file hosts

# Watch what a specific process touches
sudo ./bin/veil --module files -p $(pidof postgres)

# Watch writes by non-root users
sudo ./bin/veil --module files --op write --uid '!0'
```

---

### network module

Traces TCP connection lifecycle events using a tracepoint on `sock/inet_sock_set_state` combined with kprobes on `tcp_v4_connect`, `inet_csk_accept`, and `inet_listen` for PID correlation.

The tracepoint fires on TCP state transitions but runs in interrupt context where `bpf_get_current_pid_tgid()` returns wrong results. The kprobes stash process context (PID, comm, UID) into a BPF hash map keyed by socket pointer, which the tracepoint handler looks up.

State transitions are classified into event types: `CONNECT`, `ESTABLISHED`, `CLOSE`, `FAILED`, `LISTEN`.

**Flags:**

| Flag | Description |
|---|---|
| `--pid <pid>` | Filter by PID (comma-separated, supports `!` negation) |
| `--uid <uid>` | Filter by UID (comma-separated, supports `!` negation) |
| `--name <name>` | Filter by process name (substring match, userspace) |
| `--port <port>` | Filter by port number (comma-separated, supports `!` negation) |

**Output fields:** `comm`, `pid`, `uid`, `evt_type`, `saddr`, `sport`, `daddr`, `dport`, `oldstate`, `newstate`, `timestamp`

**Examples:**

```bash
# Trace all TCP activity
sudo ./bin/veil --module network

# Trace connections to HTTPS
sudo ./bin/veil --module network --port 443

# Trace everything except SSH
sudo ./bin/veil --module network --port '!22'

# Trace TCP activity by a specific user
sudo ./bin/veil --module network -u 1000

# JSON log for ingestion into a monitoring pipeline
sudo ./bin/veil --module network --output json >> /var/log/veil-tcp.jsonl
```

---

### scheduler module

Traces context switches via `tracepoint/sched/sched_switch`. Each event captures the task being switched out (prev) and the task being switched in (next), along with CPU core, priority, and the descheduling reason.

**Flags:**

| Flag | Description |
|---|---|
| `--pid <pid>` | Filter by PID (matches both prev and next, supports `!` negation) |
| `--uid <uid>` | Filter by UID (comma-separated, supports `!` negation) |
| `--name <name>` | Filter by process name (matches both prev\_comm and next\_comm, userspace) |
| `--cpu <cpu>` | Filter by CPU core (comma-separated, supports `!` negation) |

PID filtering in the scheduler module matches against both the outgoing and incoming task. An event is included if either prev_pid or next_pid matches an allowed PID, and excluded if either matches a denied PID.

**Output fields:** `prev_comm`, `next_comm`, `prev_pid`, `next_pid`, `prev_tid`, `next_tid`, `uid`, `cpu`, `prev_state`, `prev_prio`, `next_prio`, `timestamp`, `comm` (alias for prev\_comm), `pid` (alias for prev\_pid)

**prev_state values:** `RUNNING`, `SLEEPING`, `DISK_SLEEP`, `STOPPED`, `TRACED`, `EXIT_DEAD`, `ZOMBIE`, `PARKED`, `DEAD`, `NEW`

**Examples:**

```bash
# Watch context switches on CPU 0
sudo ./bin/veil --module scheduler --cpu 0

# Watch when nginx gets scheduled in or out
sudo ./bin/veil --module scheduler -n nginx

# Exclude CPU 0 (often used by interrupt handlers)
sudo ./bin/veil --module scheduler --cpu '!0'

# Watch a specific PID across all CPUs with timestamps
sudo ./bin/veil --module scheduler -p 1234 --enrich time
```

---

### memory module

Traces page faults via a `kprobe`/`kretprobe` pair on `handle_mm_fault`. The kprobe fires at function entry and stashes process context (PID, TID, UID, comm, faulting address) into a hash keyed by `pid_tgid`. The kretprobe fires on return, looks the entry back up, classifies the fault from the return value, applies filters, emits to the ring buffer, and deletes the entry.

Keying the correlation by `pid_tgid` (rather than a per-CPU slot) keeps entry and return matched even when the task migrates between CPUs or another task faults in between -- both of which can happen because a major fault sleeps waiting on disk.

Fault classification uses the `VM_FAULT_MAJOR` bit (0x04) in the return value. If set, the fault required disk I/O (major). Otherwise it was resolved from page cache or anonymous memory (minor).

**Flags:**

| Flag | Description |
|---|---|
| `--pid <pid>` | Filter by PID (comma-separated, supports `!` negation) |
| `--uid <uid>` | Filter by UID (comma-separated, supports `!` negation) |
| `--name <name>` | Filter by process name (substring match, userspace) |
| `--fault <type>` | Filter by fault type: `major`, `minor` (comma-separated, supports `!` negation) |

**Output fields:** `comm`, `pid`, `tid`, `uid`, `evt_type` (major/minor), `address` (hex), `timestamp`

**Examples:**

```bash
# Watch all page faults
sudo ./bin/veil --module memory

# Watch only major faults (disk I/O indicators)
sudo ./bin/veil --module memory --fault major

# Exclude minor faults (the vast majority)
sudo ./bin/veil --module memory --fault '!minor'

# Watch faults from a database process
sudo ./bin/veil --module memory -p $(pidof postgres)

# Major faults with enrichment for investigation
sudo ./bin/veil --module memory --fault major --enrich all --output json
```

---

### uprobe module

Traces calls to a userspace function via a uprobe on a chosen `binary:symbol`, given at load time with `--uprobe`. Each call emits an event. With `--latency`, a uretprobe is attached too and the entry-to-return duration is reported.

The target is a filesystem path, not a library name: `--uprobe /usr/bin/bash:readline`. The symbol is resolved from the binary's ELF symbol table, so a stripped binary fails with a clear error. Only entry and return timing are captured -- no function arguments -- so the module is architecture-neutral.

To find a symbol, use `nm` or `objdump`. Function symbols appear with type `T` (exported) or `t` (local):

```bash
# Exported (dynamic) symbols of a shared library
nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep ' malloc$'

# All symbols of a non-stripped executable
nm /usr/bin/bash | grep ' readline$'

# objdump works too, and lists only dynamic symbols
objdump -T /lib/x86_64-linux-gnu/libc.so.6 | grep malloc
```

If `nm` reports "no symbols", the binary is stripped; only its dynamic (exported) symbols, shown by `nm -D`, remain resolvable.

A uprobe on a hot symbol fires for every process that calls it. When neither `--pid` nor `--uid` is set, Veil prompts for confirmation before starting; pass `--pid`/`--uid` to scope the trace, or `--yes` to skip the prompt. In a non-interactive shell the prompt is declined, so one of those flags is required there.

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--uprobe <path:symbol>` | | Attach target as `path:symbol` (required) |
| `--latency` | | Also measure call latency via a uretprobe |
| `--pid <pid>` | `-p` | Filter by PID (comma-separated, supports `!` negation) |
| `--uid <uid>` | `-u` | Filter by UID (comma-separated, supports `!` negation) |
| `--name <name>` | `-n` | Filter by process name (substring match, userspace) |

**Output fields:** `comm`, `pid`, `tid`, `uid`, `symbol`, `path`, `duration_ns` (0 in entry-only mode), `timestamp`

**Examples:**

```bash
# Trace calls to readline in bash
sudo ./bin/veil --module uprobe --uprobe /usr/bin/bash:readline

# Measure how long each readline call takes
sudo ./bin/veil --module uprobe --uprobe /usr/bin/bash:readline --latency

# Probe a shared-library function, scoped to one process to avoid a firehose
sudo ./bin/veil --module uprobe --uprobe /lib/x86_64-linux-gnu/libc.so.6:malloc -p 1234
```

---

## Filtering

Veil supports three filtering levels:

1. **L1 - BPF program selection:** which hooks are attached (determined by `--module`)
2. **L2 - BPF map filtering:** deny/allow maps checked inside the BPF program, before ring buffer. High-frequency events never reach userspace.
3. **L3 - Userspace filtering:** substring match on process name (`--name`), applied after ring buffer read.

All numeric filters (PID, UID, port, CPU, syscall, fault type) operate at L2 in the kernel. Process name filtering operates at L3 because BPF string comparison is limited.

### Allow Filters

When an allow filter is active, only matching events pass. Multiple values are OR'd:

```bash
# PID 100 or PID 200
sudo ./bin/veil --module syscall -p 100,200

# UID 0 (root)
sudo ./bin/veil --module syscall -u 0

# Port 80 or 443
sudo ./bin/veil --module network --port 80,443
```

### Deny Filters (Negation)

Prefix a value with `!` to exclude it. The `!` character must be quoted in bash to avoid history expansion:

```bash
# Exclude PID 1
sudo ./bin/veil --module syscall --pid '!1'

# Exclude ioctl syscalls
sudo ./bin/veil --module syscall --syscall '!ioctl'

# Exclude SSH traffic
sudo ./bin/veil --module network --port '!22'

# Exclude minor faults
sudo ./bin/veil --module memory --fault '!minor'
```

### Combined Filters

Allow and deny can coexist in the same flag value:

```bash
# Allow PID 100, deny PID 200
sudo ./bin/veil --module syscall --pid '100,!200'

# Allow CPU 0-3, deny CPU 0
sudo ./bin/veil --module scheduler --cpu '0,1,2,3,!0'
```

Separate filter types are AND'd. Within a type, allow values are OR'd:

```bash
# PID must be 100 AND uid must be 0
sudo ./bin/veil --module syscall -p 100 -u 0
```

### Filter Evaluation Order

Inside the BPF program, filtering follows a strict order:

1. **Deny filters checked first.** If the event matches any deny entry, it is dropped immediately.
2. **Allow filters checked second.** If an allow filter is active and the event does not match any entry, it is dropped.
3. **No filters active:** all events pass through.

This means deny always wins. `--pid '100,!100'` drops PID 100 because deny is evaluated first.

---

## Multi-Module Mode

Run multiple modules concurrently by comma-separating their names:

```bash
sudo ./bin/veil --module syscall,network
sudo ./bin/veil --module syscall,files,network,scheduler,memory
```

All modules share the same output sink. Events are interleaved as they arrive. Shared flags (`--pid`, `--uid`, `--name`) apply to every module that supports them. Module-specific flags are ignored by modules that don't use them:

```bash
# PID filter applies to both modules; --port only affects network
sudo ./bin/veil --module syscall,network -p 1234 --port 443
```

---

## Event Enrichment

The `--enrich` flag adds derived fields resolved from the host system at event time:

| Enricher | Field added | Source |
|---|---|---|
| `time` | `time` | `ktime_get_ns()` converted to wall-clock time |
| `proc` | `proc_name` | `/proc/<pid>/comm` |
| `user` | `username` | `/etc/passwd` lookup by UID |
| `all` | all of the above | — |

Enrichers compose as sink middleware. They run after the pausable sink, so pausing output also pauses `/proc` reads.

```bash
# Timestamps only
sudo ./bin/veil --module syscall --enrich time

# Timestamps and usernames
sudo ./bin/veil --module network --enrich time,user

# Everything
sudo ./bin/veil --module files --enrich all
```

Example output with `--enrich all`:

```
[14:32:05.123] bash             PID=1234   TID=1234   UID=0     GID=0     syscall=openat(257) user=root proc=bash
```

> **Note:** Enrichment adds per-event overhead (`/proc` reads, passwd lookups). For high-throughput tracing, use only what you need or rely on post-processing.

> **Note:** `--enrich` has no observable effect in combination with `--count`, since the count summary does not include enriched fields.

---

## Output Formats

### Text (default)

One line per event. Each module has its own formatter:

```
bash             PID=1234   TID=1234   UID=0     GID=0     syscall=openat(257)
cat              PID=5678   UID=1000  op=open  filename=/etc/hosts
nc               PID=9012   CONNECT      127.0.0.1:5432 -> 127.0.0.1:1234 [CLOSE->SYN_SENT]
CPU=2   bash     PID=1234   prio=120 -> nginx    PID=5678   prio=120  [SLEEPING]
bash             PID=1234   TID=1234   UID=0     fault=major   addr=0x7f4a2c001000
```

### JSON (`--output json`)

One JSON object per line (NDJSON). Every event includes a `module` field:

```bash
sudo ./bin/veil --module network --port 443 --output json | jq '.evt_type'
sudo ./bin/veil --module syscall --output json >> /var/log/veil.jsonl
```

JSON output is suitable for piping to `jq`, ingesting into monitoring systems, or structured log aggregation.

### Field Projection (`--fields`)

`--fields comm,pid,syscall` restricts output to the named fields, in the given order:

- **Text**: the module's fixed line is replaced by a `key=value` line of the selected fields. A field the event does not carry renders as `key=`.
- **JSON**: only the selected keys are emitted. `module` is included only if you list it.

```bash
sudo ./bin/veil --module syscall --fields comm,pid,syscall
# comm=bash pid=1234 syscall=openat

sudo ./bin/veil --module syscall --fields comm,pid,syscall --output json
# {"comm":"bash","pid":1234,"syscall":"openat"}
```

Field names are the output fields listed for each module above. Unknown fields are not an error: they render empty (text) or are omitted (JSON). Like `--enrich`, `--fields` has no effect under `--count`.

---

## Configuration File

`--config <path>` loads the whole trace from a YAML file instead of flags. The
file is a second way to write the same thing the CLI produces, with one thing
the CLI cannot express: **each module gets its own filters** (on the command
line, filter flags are shared across every module in a multi-module run).

```yaml
modules:
  - name: syscall
    flags:
      pid: [1234, 5678]
      syscall: [openat, "!ioctl"]   # '!' is a deny value, as on the CLI
  - name: network
    flags:
      port: [443]

output:
  format: json
  enrich: [time, proc]
  fields: [comm, pid, syscall]
  count_by: syscall               # implies count

run:
  control: /tmp/veil.sock
  yes: true
```

Flag values may be a single scalar, a list (joined with commas), or a boolean
for toggle flags such as `latency`. Module and flag names are validated against
the registry, and unknown keys are rejected, so a typo fails loudly.

```bash
sudo ./bin/veil --config trace.yaml
```

With `--config`, the file governs the modules and output; trace-defining flags
passed alongside it are ignored with a warning. The operational flags
`--control`, `--pprof`, and `--yes` still apply and override the file.

### Profiles

A single file can hold several named traces under `profiles:`, picked with
`--profile <name>`. This replaces the top-level `modules`/`output`/`run` -- a
file uses one form or the other, not both. Each profile is a complete,
independent trace; they do not inherit anything from each other or from a
file-level default.

```yaml
default: overview             # used when --profile is omitted (optional)

profiles:
  overview:
    modules:
      - name: syscall
        flags: { name: nginx }
    output:
      count_by: syscall

  triage:
    modules:
      - name: syscall
        flags: { pid: [1234] }
      - name: network
        flags: { pid: [1234] }
    output:
      enrich: [time, proc]
```

```bash
sudo ./bin/veil --config web.yaml --profile triage
sudo ./bin/veil --config web.yaml                 # runs 'overview' (the default)
```

Without a `default`, a multi-profile file requires `--profile`; it errors and
lists the available profiles otherwise. `--profile` needs `--config`, and does
not apply to a single-profile file.

### Validating a Config

`veil config validate <path>...` checks one or more config files without
touching the kernel: YAML structure, module and flag names, per-module flag
parsing, and syscall-name resolution against the host's table. It needs no root
and loads no BPF, so it suits a CI step or a quick pre-flight. Every profile in
a multi-profile file is checked, not just the one that would run. It exits
non-zero if any file (or any profile) fails.

```bash
$ ./bin/veil config validate examples/*.yaml
ok: examples/incident-triage.yaml (3 modules: syscall, files, network; output text)
ok: examples/network-audit.yaml (1 module: network; output json)
ok: examples/web-service.yaml [connections] (1 module: network; output json)
ok: examples/web-service.yaml [overview] (1 module: syscall; output text)
ok: examples/web-service.yaml [triage] (3 modules: syscall, files, network; output text)

$ ./bin/veil config validate broken.yaml
error: broken.yaml: syscall: unknown syscall name "epoll_wait"

Did you mean:
epoll_pwait
epoll_pwait2
```

Syscall names are architecture-specific -- `epoll_wait` exists on x86_64 but not
arm64, where the call is `epoll_pwait` -- so validation resolves them against
the table for the host it runs on, and suggests near matches on a miss.

---

## Count Mode

Suppress live event output and show a ranked summary on exit. Useful for answering questions like "which syscalls are most frequent?" or "which ports see the most connections?"

```bash
# Top syscalls
sudo ./bin/veil --module syscall --count

# Top syscalls by PID instead of syscall name
sudo ./bin/veil --module syscall --count-by pid

# Top destination ports
sudo ./bin/veil --module network --count

# Top file paths
sudo ./bin/veil --module files --count

# Top fault types
sudo ./bin/veil --module memory --count
```

`--count-by` overrides the default aggregation key. Each module has a sensible default:

| Module | Default key |
|---|---|
| `syscall` | `syscall` |
| `files` | `filename` |
| `network` | `dport` |
| `scheduler` | `next_comm` |
| `memory` | `evt_type` |

Any field name present in any module's output can be used with `--count-by`. For the complete list, use an invalid field name and the error message will list all valid fields.

Example summary output:

```
--- Veil Event Summary ---

[syscall] 84231 events (grouped by syscall)
  futex                                       32104  ( 38.1%)
  epoll_wait                                  18923  ( 22.5%)
  read                                        12045  ( 14.3%)
  write                                        8876  ( 10.5%)
  openat                                       4521  (  5.4%)
  ... and 23 more unique keys
```

---

## Runtime Filter Control

### Interactive Mode

Press **CTRL-C** during tracing to pause event output and enter an interactive prompt:

```
^C
---  Veil Tracing Paused [syscall]  ---

Veil interactive control (type 'help' for commands, 'resume' to continue tracing, 'quit' to exit)
veil $ status
syscall: loaded, filters: pid=[], uid=[], syscall=[]
veil $ add pid 1234
OK
veil $ add pid 5678
OK
veil $ list pid
1234
5678
veil $ resume
---  resumed (1247 events dropped while paused)  ---
```

While paused, events continue arriving in the ring buffer but are silently dropped at the `PausableSink` layer. The drop count is reported on resume.

A second CTRL-C while in the interactive prompt exits Veil entirely.

### Unix Socket Control

For scripted or external access, use `--control` to start a Unix socket server alongside tracing:

```bash
# Start Veil with a control socket
sudo ./bin/veil --module network --control /tmp/veil.sock

# In another terminal, query and modify filters
echo "status" | socat - UNIX-CONNECT:/tmp/veil.sock
echo "add port 443" | socat - UNIX-CONNECT:/tmp/veil.sock
echo "list port" | socat - UNIX-CONNECT:/tmp/veil.sock
echo "del port 443" | socat - UNIX-CONNECT:/tmp/veil.sock
```

The socket is created with mode 0666 so non-root users can connect (useful when the control client doesn't need to run as root).

### Control Commands

| Command | Description |
|---|---|
| `add <map> <key>` | Add a key to a filter map |
| `del <map> <key>` | Remove a key from a filter map |
| `list <map>` | List all keys in a filter map |
| `clear <map>` | Remove all keys from a filter map |
| `status` | Show loaded modules and active filters |
| `resume` | Resume tracing (interactive only) |
| `quit` / `exit` | Stop Veil |
| `help` | Show available commands |

**Map names:** `pid`, `uid`, `syscall`, `port`, `cpu`, `fault`, and their deny variants (`pid_deny`, `uid_deny`, etc.)

Keys are always decimal numbers. For syscalls, use the numeric syscall number. For fault types, use `0` (major) or `1` (minor).

### Multi-Module Routing

In multi-module mode, shared maps (`pid`, `uid`) route to all loaded modules. Module-specific maps (`syscall`, `port`, `cpu`, `fault`) route to their owning module only.

To target a specific module's map, use the 4-part form:

```
veil $ add network port 443         # add to network module only
veil $ add syscall pid 1234         # add PID filter only to syscall
veil $ list network port            # list network's port filter
```

Without the module prefix, shared maps fan out to all modules:

```
veil $ add pid 1234                 # adds PID 1234 to all loaded modules
```

---

## Practical Recipes

### Investigate slow application startup

```bash
# What files does the app touch on startup? (filename field shows absolute paths)
sudo ./bin/veil --module files -p $(pidof myapp) --enrich time --output json > startup-files.jsonl

# Are there major page faults stalling startup?
sudo ./bin/veil --module memory -p $(pidof myapp) --fault major --enrich time
```

### Find noisy processes

```bash
# Which processes make the most syscalls? (run for 10 seconds, then CTRL-C)
sudo timeout 10 ./bin/veil --module syscall --count-by comm

# Which processes cause the most context switches?
sudo timeout 10 ./bin/veil --module scheduler --count-by next_comm
```

### Monitor network connections in production

```bash
# JSON log of all TCP events, exclude internal health checks on port 8080
sudo ./bin/veil --module network --port '!8080' --output json --enrich time >> /var/log/tcp.jsonl

# Real-time connection monitoring with runtime filter adjustment
sudo ./bin/veil --module network --control /tmp/veil-net.sock
# Then in another terminal:
echo "add port 443" | socat - UNIX-CONNECT:/tmp/veil-net.sock
```

### Profile I/O patterns

```bash
# Which files are read most frequently? (absolute paths in output)
sudo timeout 30 ./bin/veil --module files --op read --count

# Which processes read from /etc?
sudo ./bin/veil --module files --op read --file /etc/

# Watch access to a specific file across all processes
sudo ./bin/veil --module files --file /etc/passwd

# Combined syscall + file view for a specific process
sudo ./bin/veil --module syscall,files -p $(pidof postgres) --enrich time
```

### Debug context switch overhead

```bash
# Watch who preempts your process
sudo ./bin/veil --module scheduler -p $(pidof myapp) --enrich time

# Count context switches per CPU
sudo timeout 10 ./bin/veil --module scheduler --count-by cpu
```

### Page fault analysis

```bash
# Are major faults happening? (indicates thrashing or cold cache)
sudo ./bin/veil --module memory --fault major --enrich all

# Count fault distribution
sudo timeout 10 ./bin/veil --module memory --count
```
