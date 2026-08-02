//go:build ignore

/*
 * Userspace probe (uprobe) tracing BPF program for Veil.
 *
 * Attaches to a user-chosen binary:symbol at load time. Unlike the other
 * modules the attach target is not fixed in the source; the program is
 * generic and userspace decides which symbol to probe.
 *
 * Two modes, selected by which programs userspace attaches:
 *   entry-only  - attach uprobe_emit. Each call emits an event (duration 0).
 *   latency     - attach uprobe_store + uretprobe_emit. Entry stashes a
 *                 timestamp keyed by pid_tgid; the return probe computes the
 *                 call duration and emits.
 *
 * Filtering (deny then allow) runs once at entry, so in latency mode the
 * return probe only fires for calls whose entry was already admitted.
 *
 * No PT_REGS access: the programs read only bpf_get_current_* helpers, so
 * the object is architecture-neutral (no arg capture in this version).
 *
 * Filter maps follow the same convention as other Veil modules:
 *   - pid_filter / pid_deny: filter by PID
 *   - uid_filter / uid_deny: filter by UID
 *   - filter_cfg: bitmask controlling which filters are active
 */

#include "headers/target_arch.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

/*
 * Event struct emitted to userspace. Must match the layout in
 * modules/uprobe/parse.go exactly.
 */
struct uprobe_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 pad;
    __u64 timestamp;
    __u64 duration_ns;  /* 0 in entry-only mode */
    __u8  comm[TASK_COMM_LEN];
};

/*
 * Scratch for entry -> return correlation in latency mode. Keyed by
 * pid_tgid, so it survives CPU migration and concurrent callers (one live
 * entry per thread). A self-recursive call overwrites its own entry; the
 * outer call's duration is then measured from the inner entry.
 */
struct uprobe_scratch {
    __u64 ts_enter;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u8  comm[TASK_COMM_LEN];
};

/* Ring buffer for uprobe events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  /* 16 MB */
} uprobe_events SEC(".maps");

/* Entry -> return scratch, keyed by pid_tgid */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct uprobe_scratch);
} enter_scratch SEC(".maps");

/*
 * Filter maps
 */

/* Allow maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} pid_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} uid_filter SEC(".maps");

/* Deny maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} pid_deny SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} uid_deny SEC(".maps");

/*
 * Bitmask array: which filters are active
 *
 * Bitmask layout (module-specific bits 2 and 5 unused, no third dimension):
 *   bit 0: pid allow
 *   bit 1: uid allow
 *   bit 3: pid deny
 *   bit 4: uid deny
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_cfg SEC(".maps");

/*
 * passes_filter applies the deny-then-allow filter logic. Returns 1 if the
 * event should be kept, 0 if it should be dropped.
 */
static __always_inline int passes_filter(__u32 pid, __u32 uid)
{
    __u32 cfg_key = 0;
    __u32 *cfg = bpf_map_lookup_elem(&filter_cfg, &cfg_key);
    if (cfg && *cfg) {
        __u32 mask = *cfg;

        /* Deny filters first */
        if ((mask & 8) && bpf_map_lookup_elem(&pid_deny, &pid))
            return 0;
        if ((mask & 16) && bpf_map_lookup_elem(&uid_deny, &uid))
            return 0;

        /* Allow filters */
        if ((mask & 1) && !bpf_map_lookup_elem(&pid_filter, &pid))
            return 0;
        if ((mask & 2) && !bpf_map_lookup_elem(&uid_filter, &uid))
            return 0;
    }
    return 1;
}

/*
 * Uprobe (entry-only mode): emit one event per call.
 */
SEC("uprobe/emit")
int uprobe_emit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32) bpf_get_current_uid_gid();

    if (!passes_filter(pid, uid))
        return 0;

    struct uprobe_event *e;
    e = bpf_ringbuf_reserve(&uprobe_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid         = pid;
    e->tid         = (__u32) pid_tgid;
    e->uid         = uid;
    e->pad         = 0;
    e->timestamp   = bpf_ktime_get_ns();
    e->duration_ns = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * Uprobe (latency mode): stash entry context for the return probe.
 * Filters here so the return probe only sees admitted calls.
 */
SEC("uprobe/store")
int uprobe_store(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32) bpf_get_current_uid_gid();

    if (!passes_filter(pid, uid))
        return 0;

    struct uprobe_scratch s = {};
    s.ts_enter = bpf_ktime_get_ns();
    s.pid      = pid;
    s.tid      = (__u32) pid_tgid;
    s.uid      = uid;
    bpf_get_current_comm(&s.comm, sizeof(s.comm));

    bpf_map_update_elem(&enter_scratch, &pid_tgid, &s, BPF_ANY);
    return 0;
}

/*
 * Uretprobe (latency mode): compute duration and emit.
 */
SEC("uretprobe/emit")
int uretprobe_emit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct uprobe_scratch *s = bpf_map_lookup_elem(&enter_scratch, &pid_tgid);
    if (!s)
        return 0;

    __u64 now = bpf_ktime_get_ns();

    struct uprobe_event *e;
    e = bpf_ringbuf_reserve(&uprobe_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&enter_scratch, &pid_tgid);
        return 0;
    }

    e->pid         = s->pid;
    e->tid         = s->tid;
    e->uid         = s->uid;
    e->pad         = 0;
    e->timestamp   = now;
    e->duration_ns = now - s->ts_enter;
    __builtin_memcpy(e->comm, s->comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&enter_scratch, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
