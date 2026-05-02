// go:build ignore

/*
 * This file is taken as input by bpf2go utility. The directory './modules/syscall'
 * is where the go file for this eBPF program will reside. The file
 * './modules/syscall/syscall.go' will then call the bpf2go interfaces that
 * is compatible with the below eBPF program.
 */

/*
 * The SEC macro we use here are to place the appropriate code or data
 * of the source into respective sections on the ELF file.
 *
 * - SEC(".maps") is used to convey the BPF map definition needs to be
 * created in the kernel before the program runs.
 * - SEC("tracepoint/raw_syscalls/sys_enter") encodes the program type--
 * which is a tracepoint program--and the attach point, which is
 * 'sys_enter' of raw syscalls.
 * - SEC("license") is set to GPL since there are some bpf helper functions
 * which require the caller function to be GPL compatible as well.
 */

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * This structure must match the syscallEvent structure that we defined in
 * modules/syscall/parse.go
 */
struct syscall_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    __u64 syscall_nr;
    __u8  comm[16];
};

/*
 * The ring buffer where the kernel writes to this buffer and the userspace
 * application reads from the ring buffer.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);	/* 16 MB */
} events SEC(".maps");

/*
 * Filter maps. The userspace populates these maps before the tracepoint
 * is attached. If a filter map is non-empty, only events matching an
 * entry in the map are submitted to the ring buffer.
 *
 * The convention is:
 *   - key   = the value to match (e.g. a PID)
 *   - value = __u8 (unused, just a placeholder; presence of key = match)
 *
 * The config map holds a bitmask indicating which filters are active.
 * Bit 0: PID filter active
 * Bit 1: UID filter active
 * Bit 2: syscall number filter active
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);        /* PID */
    __type(value, __u8);
} pid_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);        /* UID */
    __type(value, __u8);
} uid_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);        /* syscall number */
    __type(value, __u8);
} syscall_filter SEC(".maps");

/*
 * A single-element array map holding the filter bitmask.
 * Index 0 stores a __u32 bitmask:
 *   bit 0 = pid_filter active
 *   bit 1 = uid_filter active
 *   bit 2 = syscall_filter active
 *
 * If the bitmask is 0, no filtering is performed (all events pass).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_cfg SEC(".maps");

/*
 * Attach the raw_syscalls:sys_enter **tracepoint**.
 * the 'ctx' argument is used to fetch the syscall number and arguments.
 *
 * Uses the following 'bpf-helpers(7)' functions:
 *		- bpf_ringbuf_reserve
 *		- bpf_get_current_pid_tgid
 *		- bpf_ktime_get_ns
 *		- bpf_get_current_comm
 *		- bpf_ringbuf_submit
 *		- bpf_get_current_uid_gid
 *		- bpf_map_lookup_elem
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx)
{

	/*
	 * Get the current pid and tgid. A 64-bit integer is returned which
	 * contains the current tgid and pid, and created as such:
	 *
	 *		current_task->tgid << 32 | current_task->pid
	 *
	 * The signature of this function is:
	 *
	 *		u64
	 *		bpf_get_current_pid_tgid (void);
	 */
	__u64 pid_tgid	= bpf_get_current_pid_tgid();
    __u32 pid		= pid_tgid >> 32;
	/*
	 * Get the current uid and gid. A 64-bit integer is returned which
	 * contains the current gid and uid, and created as such:
	 *
	 *		current_gid << 32 | current_uid
	 *
	 * The signature of this function is:
	 *
	 *		u64
	 *		bpf_get_current_uid_gid (void);
	 */
    __u64 uid_gid	= bpf_get_current_uid_gid();
    __u32 uid		= (__u32) uid_gid;
	__u64 nr		= ctx->id;

	/*
     * Read the filter configuration bitmask. If any filter bit is set, check
	 * the corresponding filter map. If the map lookup fails (key not present),
	 * the event does not match and we return early.
     *
     * This check happens before bpf_ringbuf_reserve to avoid wasting ring buffer
	 * space on events that will be discarded.
	 *
	 * Notice the side-effect of this implementation. Suppose that we have set
	 * the filter bit for PID filter but did not assign any filter on the map.
	 * For such cases, it will drop every syscall events. This should be
	 * taken into consideration since now we allow the user to update the map
	 * at runtime using MapUpdater module. Since the filter configuration
	 * logic is identical for other modules, i.e., files and network currently,
	 * this applies to them as well.
     */
    __u32 cfg_key = 0;
    __u32 *cfg = bpf_map_lookup_elem(&filter_cfg, &cfg_key);
    if (cfg && *cfg) {
        __u32 mask = *cfg;
 
        /* Bit 0: PID filter */
        if ((mask & 1) && !bpf_map_lookup_elem(&pid_filter, &pid))
            return 0;
 
        /* Bit 1: UID filter */
        if ((mask & 2) && !bpf_map_lookup_elem(&uid_filter, &uid))
            return 0;
 
        /* Bit 2: syscall number filter */
        if ((mask & 4) && !bpf_map_lookup_elem(&syscall_filter, &nr))
            return 0;
    }

    struct syscall_event *e;

	/*
	 * Reserve 'size' bytes of payload in a ring buffer 'ringbuf'.
	 * 'flags' must be 0. The signature of this function is:
	 * 
	 *		void *
	 *		bpf_ringbuf_reserve (void *ringbuf, u64 size, u64 flags);
	 */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->tid = (__u32) pid_tgid;
    e->uid = uid;
    e->gid = (__u32)(uid_gid >> 32);

	/*
	 * Return the time elapsed since system boot, in nanoseconds.
	 * Does not include time the system was suspended.
	 *
	 * The signature of this function is:
	 *
	 *		u64
	 *		bpf_ktime_get_ns (void);
	 */
    e->timestamp  = bpf_ktime_get_ns();
    e->syscall_nr = nr;

	/*
	 * Copy the 'comm' attribute of the current task into 'buf' of
	 * 'size_of_buf'. The 'comm' attribute contains the name of the
	 * executable (excluding the path) for the current task. The
	 * 'size_of_buf' must be strictly positive. On success, the helper
	 * makes sure that the 'buf' is NUL-terminated. On failure, it is
	 * filled with zeroes.
	 *
	 * The signature of this function is:
	 *
	 *		long
	 *		bpf_get_current_comm (void *buf, u32 size_of_buf);
	 */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/*
	 * Submit reserved ring buffer sample, pointed to by 'data'. Refer to
	 * documentation on 'bpf_helpers(7)' for details of 'flag'. If 0 is
	 * specified in 'flags', an adaptive notification of new data
	 * availability is sent.
	 *
	 * See 'bpf_ringbuf_output()' for the definition of adaptive notification.
	 *
	 * The signature of this function is:
	 *
	 *		void
	 *		bpf_ringbuf_submit (void *data, u64 flags);
	 */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
