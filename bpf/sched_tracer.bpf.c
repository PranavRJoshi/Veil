// go:build ignore

/*
 * Scheduler tracing BPF program for Veil.
 *
 * Attaches to the tracepoint/sched/sched_switch to capture context switches.
 * Each event records which task was switched out (prev) and which was switched
 * in (next), along with the CPU core, scheduler priority, and the reason the
 * previous task was descheduled.
 *
 * Filter maps follow the same convention as other Veil modules:
 *   - pid_filter / pid_deny: filter by PID (matches both prev and next)
 *   - uid_filter / uid_deny: filter by UID (current task's UID)
 *   - cpu_filter / cpu_deny: filter by CPU core
 *   - filter_cfg: bitmask controlling which filters are active
 *
 * Bitmask layout:
 *   bit 0: pid allow
 *   bit 1: uid allow
 *   bit 2: cpu allow
 *   bit 3: pid deny
 *   bit 4: uid deny
 *   bit 5: cpu deny
 */

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * Event struct emitted to userspace. Must match the layout in
 * modules/scheduler/parse.go exactly.
 */
struct sched_event {
    __u32 prev_pid;
    __u32 next_pid;
    __u32 prev_tid;
    __u32 next_tid;
    __u32 uid;
    __u32 cpu;
    __u64 prev_state;
    __u64 timestamp;
    __u32 prev_prio;
    __u32 next_prio;
    __u8  prev_comm[16];
    __u8  next_comm[16];
};

/* Ring buffer for scheduler events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  /* 16 MB */
} sched_events SEC(".maps");

/* ----------------------------------------------------------------
 * Filter maps
 * ---------------------------------------------------------------- */

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);     /* CPU core number */
    __type(value, __u8);
} cpu_filter SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u8);
} cpu_deny SEC(".maps");

/* Bitmask array: which filters are active */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_cfg SEC(".maps");

/*
 * Tracepoint: sched/sched_switch
 *
 * The tracepoint args are available via the context pointer. The
 * vmlinux.h-generated type provides typed access to prev_pid,
 * prev_prio, prev_state, next_pid, next_prio, prev_comm, next_comm.
 */
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 prev_pid = ctx->prev_pid;
    __u32 next_pid = ctx->next_pid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32) uid_gid;

    __u32 cpu = bpf_get_smp_processor_id();

    /* ---- Filter logic ---- */
    __u32 cfg_key = 0;
    __u32 *cfg = bpf_map_lookup_elem(&filter_cfg, &cfg_key);
    if (cfg && *cfg) {
        __u32 mask = *cfg;

        /* Deny filters first */

        /* Bit 3: PID deny: match if either prev or next is denied */
        if (mask & 8) {
            if (bpf_map_lookup_elem(&pid_deny, &prev_pid) ||
                bpf_map_lookup_elem(&pid_deny, &next_pid))
                return 0;
        }

        /* Bit 4: UID deny */
        if ((mask & 16) && bpf_map_lookup_elem(&uid_deny, &uid))
            return 0;

        /* Bit 5: CPU deny */
        if ((mask & 32) && bpf_map_lookup_elem(&cpu_deny, &cpu))
            return 0;

        /* Allow filters */

        /* Bit 0: PID allow: match if either prev or next is allowed */
        if (mask & 1) {
            if (!bpf_map_lookup_elem(&pid_filter, &prev_pid) &&
                !bpf_map_lookup_elem(&pid_filter, &next_pid))
                return 0;
        }

        /* Bit 1: UID allow */
        if ((mask & 2) && !bpf_map_lookup_elem(&uid_filter, &uid))
            return 0;

        /* Bit 2: CPU allow */
        if ((mask & 4) && !bpf_map_lookup_elem(&cpu_filter, &cpu))
            return 0;
    }

    /* ---- Build event ---- */
    struct sched_event *e;
    e = bpf_ringbuf_reserve(&sched_events, sizeof(*e), 0);
    if (!e)
        return 0;

    /*
     * pid_tgid for the "current" task: note that in the sched_switch
     * context, "current" is the task being switched OUT (prev).
     */
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->prev_pid   = prev_pid;
    e->next_pid   = next_pid;
    e->prev_tid   = (__u32) pid_tgid;   /* TID of the prev task */
    e->next_tid   = 0;                  /* not available in this context */
    e->uid        = uid;
    e->cpu        = cpu;
    e->prev_state = ctx->prev_state;
    e->timestamp  = bpf_ktime_get_ns();
    e->prev_prio  = ctx->prev_prio;
    e->next_prio  = ctx->next_prio;

    /*
     * Copy comm names. The tracepoint provides prev_comm and
     * next_comm directly in its args.
     *
     * The problem with using __builtin_memcpy to copy 16 bytes
     * of data from ctx's fields to ringbuffer is that optimized
     * bpf program will transform the memcpy into multiple load/store
     * operations. In my case, two 8 bytes load store operations are
     * emitted by clang when -O2 is passed during compilation.
     * The bpf verifier emits the error of type:
     *     "dereference of modified ctx ptr R2 off = 8 disallowed"
     * which suggests that load/store approach added offset to the
     * context pointer, thereby modifying it, and then dereferencing
     * it. '__check_ptr_off_reg' is responsible for throwing out this
     * error. The link to source is:
     *     https://elixir.bootlin.com/linux/v5.15.179/source/kernel/bpf/verifier.c#L3989
     * Instead of relying on memcpy, we use bpf-helper to copy the data.
     */
    // __builtin_memcpy(e->prev_comm, ctx->prev_comm, 16);
    // __builtin_memcpy(e->next_comm, ctx->next_comm, 16);
    bpf_probe_read_kernel(e->prev_comm, 16, ctx->prev_comm);
    bpf_probe_read_kernel(e->next_comm, 16, ctx->next_comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
