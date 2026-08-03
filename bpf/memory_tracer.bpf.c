//go:build ignore

/*
 * Memory tracing BPF program for Veil.
 *
 * Attaches a kprobe and kretprobe on handle_mm_fault to capture page
 * fault events. The kprobe stashes process context (PID, TID, UID,
 * comm, faulting address) into a hash keyed by pid_tgid. The kretprobe
 * reads the scratch data back, classifies the fault as major or minor
 * from the return value, applies deny/allow filters, and emits to the
 * ring buffer.
 *
 * Entry-to-return correlation uses a hash keyed by pid_tgid: the entry
 * probe stashes context, the return probe looks it up and deletes it. This
 * survives CPU migration and concurrent faulters, which a single-slot
 * per-CPU scratch does not -- handle_mm_fault can sleep (a major fault waits
 * on disk), so the task may migrate or another may fault in between.
 *
 * Filter maps follow the same convention as other Veil modules:
 *   - pid_filter / pid_deny: filter by PID
 *   - uid_filter / uid_deny: filter by UID
 *   - fault_filter / fault_deny: filter by fault type (0=major, 1=minor)
 *   - filter_cfg: bitmask controlling which filters are active
 */

#include "headers/target_arch.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

/* From include/linux/mm_types.h */
#define VM_FAULT_MAJOR 0x04

/* Event types emitted to userspace */
#define EVT_MAJOR_FAULT 0
#define EVT_MINOR_FAULT 1

/*
 * Event struct emitted to userspace. Must match the layout in
 * modules/memory/parse.go exactly.
 */
struct mem_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u8  evt_type;
    __u8  pad[3];
    __u64 timestamp;
    __u64 address;
    __u8  comm[TASK_COMM_LEN];
};

/*
 * Scratch struct for kprobe -> kretprobe correlation, keyed by pid_tgid.
 */
struct fault_scratch {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u64 address;
    __u8  comm[TASK_COMM_LEN];
};

/* Ring buffer for memory events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  /* 16 MB */
} mem_events SEC(".maps");

/* Entry -> return scratch, keyed by pid_tgid */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct fault_scratch);
} fault_scratch SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);     /* fault type: 0=major, 1=minor */
    __type(value, __u8);
} fault_filter SEC(".maps");

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
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u8);
} fault_deny SEC(".maps");

/*
 * Bitmask array: which filters are active
 *
 * Bitmask layout:
 *   bit 0: pid allow
 *   bit 1: uid allow
 *   bit 2: fault allow
 *   bit 3: pid deny
 *   bit 4: uid deny
 *   bit 5: fault deny
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_cfg SEC(".maps");

/*
 * Kprobe: handle_mm_fault entry
 *
 * Signature (kernel 5.15):
 *   vm_fault_t handle_mm_fault(struct vm_area_struct *vma,
 *                              unsigned long address,
 *                              unsigned int flags,
 *                              struct pt_regs *regs)
 *
 * Stash pid/tid/uid/comm/address into the pid_tgid-keyed scratch map.
 */
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(kprobe_handle_mm_fault,
               struct vm_area_struct *vma,
               unsigned long address,
               unsigned int flags)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    struct fault_scratch s = {};
    s.pid     = pid_tgid >> 32;
    s.tid     = (__u32)pid_tgid;
    s.uid     = (__u32)uid_gid;
    s.address = address;
    bpf_get_current_comm(&s.comm, sizeof(s.comm));

    bpf_map_update_elem(&fault_scratch, &pid_tgid, &s, BPF_ANY);
    return 0;
}

/*
 * Kretprobe: handle_mm_fault return
 *
 * The return value contains VM_FAULT_* flags. VM_FAULT_MAJOR
 * indicates a major fault (disk I/O required); its absence means
 * a minor fault.
 *
 * All filtering (deny first, then allow) happens here, after
 * the fault type is known.
 */
SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(kretprobe_handle_mm_fault, unsigned long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct fault_scratch *s = bpf_map_lookup_elem(&fault_scratch, &pid_tgid);
    if (!s)
        return 0;

    /* Copy entry data out, then drop the scratch entry: this single delete
     * covers every return path below. */
    __u32 pid = s->pid;
    __u32 tid = s->tid;
    __u32 uid = s->uid;
    __u64 address = s->address;
    __u8  comm[TASK_COMM_LEN];
    __builtin_memcpy(comm, s->comm, TASK_COMM_LEN);
    bpf_map_delete_elem(&fault_scratch, &pid_tgid);

    /* Classify fault type from return value */
    __u32 fault_type = (ret & VM_FAULT_MAJOR) ? EVT_MAJOR_FAULT : EVT_MINOR_FAULT;

    /* Filter logic: deny first, then allow */
    __u32 cfg_key = 0;
    __u32 *cfg = bpf_map_lookup_elem(&filter_cfg, &cfg_key);
    if (cfg && *cfg) {
        __u32 mask = *cfg;

        /* Deny filters first */

        /* Bit 3: PID deny */
        if ((mask & 8) && bpf_map_lookup_elem(&pid_deny, &pid))
            return 0;

        /* Bit 4: UID deny */
        if ((mask & 16) && bpf_map_lookup_elem(&uid_deny, &uid))
            return 0;

        /* Bit 5: fault type deny */
        if ((mask & 32) && bpf_map_lookup_elem(&fault_deny, &fault_type))
            return 0;

        /* Allow filters */

        /* Bit 0: PID allow */
        if ((mask & 1) && !bpf_map_lookup_elem(&pid_filter, &pid))
            return 0;

        /* Bit 1: UID allow */
        if ((mask & 2) && !bpf_map_lookup_elem(&uid_filter, &uid))
            return 0;

        /* Bit 2: fault type allow */
        if ((mask & 4) && !bpf_map_lookup_elem(&fault_filter, &fault_type))
            return 0;
    }

    /* Build event */
    struct mem_event *e;
    e = bpf_ringbuf_reserve(&mem_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid       = pid;
    e->tid       = tid;
    e->uid       = uid;
    e->evt_type  = (__u8)fault_type;
    e->pad[0]    = 0;
    e->pad[1]    = 0;
    e->pad[2]    = 0;
    e->timestamp = bpf_ktime_get_ns();
    e->address   = address;

    __builtin_memcpy(e->comm, comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
