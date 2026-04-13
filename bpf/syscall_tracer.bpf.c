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
 * This structure must match the Event structure that we defined in
 * modules/syscall/parse.go
 */
struct syscall_event {
    __u32 pid;
    __u32 tid;
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
 * Attach the raw_syscalls:sys_enter **tracepoint**.
 * the 'ctx' argument is used to fetch the syscall number and arguments.
 *
 * Uses the following 'bpf_helpers(7)' functions:
 *		- bpf_ringbuf_reserve
 *		- bpf_get_current_pid_tgid
 *		- bpf_ktime_get_ns
 *		- bpf_get_current_comm
 *		- bpf_ringbuf_submit
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx)
{
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
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->tid        = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
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
    e->syscall_nr = ctx->id;

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
