//go:build ignore

#include "headers/target_arch.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * MAX_PATH_DEPTH: maximum number of dentry components collected per event.
 * COMPONENT_LEN:  maximum bytes per component (including null terminator).
 *
 * Path components are stored leaf-first (components[0] = filename,
 * components[1] = parent directory, ...). Userspace reassembles them in
 * reverse to produce the absolute path. Paths deeper than MAX_PATH_DEPTH
 * or with components longer than COMPONENT_LEN - 1 are truncated.
 */
#define MAX_PATH_DEPTH  12
#define COMPONENT_LEN   64

struct file_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    __u8  comm[16];
    __u8  op;                  /* 0=open, 1=read, 2=write */
    __u8  _pad[3];             /* explicit padding to align components to 4 bytes */
    __u8  components[MAX_PATH_DEPTH][COMPONENT_LEN];
};

#define OP_OPEN  0
#define OP_READ  1
#define OP_WRITE 2

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_events SEC(".maps");

/*
 * Filter maps: same convention as syscall_tracer.bpf.c.
 * Allow maps:  events must be in the map to pass.
 * Deny maps:   events must not be in the map to pass (deny takes precedence).
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

/*
 * Deny filter maps.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);        /* PID to exclude */
	__type(value, __u8);
} pid_deny SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);        /* UID to exclude */
	__type(value, __u8);
} uid_deny SEC(".maps");

/*
 * Filter configuration bitmask (single-element array map).
 *   bit 0 = pid_filter active
 *   bit 1 = uid_filter active
 *   bit 2 = [unused]
 *   bit 3 = pid deny filter active
 *   bit 4 = uid deny filter active
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_cfg SEC(".maps");

/*
 * fill_common populates the common fields of a file_event that has
 * already been reserved from the ring buffer. Returns 0 to indicate
 * the caller should proceed, or 1 if the event was filtered out
 * (caller should discard the reserved buffer).
 */
static __always_inline int fill_common(struct file_event *e, __u8 op)
{
    __u64 pid_tgid	= bpf_get_current_pid_tgid();
    __u32 pid		= pid_tgid >> 32;
    __u64 uid_gid	= bpf_get_current_uid_gid();
    __u32 uid		= (__u32)uid_gid;

    /* Check filter maps before doing any work */
    __u32 cfg_key = 0;
    __u32 *cfg = bpf_map_lookup_elem(&filter_cfg, &cfg_key);
    if (cfg && *cfg) {
        __u32 mask = *cfg;

		/*
		 * Handle deny filters first.
		 */
		if ((mask & 8) && bpf_map_lookup_elem(&pid_deny, &pid))
			return 1;

		if ((mask & 16) && bpf_map_lookup_elem(&uid_deny, &uid))
			return 1;

		/*
		 * Now work on allow filters
		 */
        if ((mask & 1) && !bpf_map_lookup_elem(&pid_filter, &pid))
            return 1;

        if ((mask & 2) && !bpf_map_lookup_elem(&uid_filter, &uid))
            return 1;
    }

    e->pid       = pid;
    e->tid       = (__u32)pid_tgid;
    e->uid       = uid;
    e->gid       = (__u32)(uid_gid >> 32);
    e->timestamp = bpf_ktime_get_ns();
    e->op        = op;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return 0;
}

/*
 * collect_path_fragments walks the dentry chain from leaf to root,
 * storing each path component directly into e->components[i].
 *
 * Because the loop is unrolled with #pragma unroll, each access
 * e->components[i] uses a compile-time constant offset from the ring
 * buffer event pointer. The BPF verifier can statically verify every
 * access is in-bounds without dynamic pointer arithmetic.
 *
 * Components are stored leaf-first: components[0] is the filename,
 * components[1] is its parent directory, and so on. The first slot
 * whose leading byte is zero (ring buffer memory is zero-initialized)
 * marks the end. Userspace reverses the array and joins with '/' to
 * produce the absolute path.
 *
 * bpf_probe_read_kernel_str is used with the constant size COMPONENT_LEN
 * so both the destination offset and the size are statically known.
 */
static __always_inline void collect_path_fragments(struct dentry *leaf,
                                                   struct file_event *e)
{
    struct dentry *dentry = leaf;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

        /* parent == dentry signals the filesystem root. */
        if (parent == dentry)
            break;

        __u32 name_len = BPF_CORE_READ(dentry, d_name.len);
        if (name_len == 0)
            break;

        const unsigned char *name_ptr =
            (const unsigned char *)BPF_CORE_READ(dentry, d_name.name);

        /*
         * e->components[i] is at a constant offset because i is
         * a compile-time constant after unrolling. COMPONENT_LEN is
         * also a constant. The verifier accepts both without issue.
         */
        bpf_probe_read_kernel_str(e->components[i], COMPONENT_LEN, name_ptr);

        dentry = parent;
    }
}

/*
 * Kprobe hooks on VFS functions. Each handler reserves a ring buffer
 * slot, applies filters via fill_common, collects path components via
 * collect_path_fragments, and submits. Filtered events are discarded.
 *
 * For vfs_open the path argument provides the dentry directly. For
 * vfs_read and vfs_write the dentry is read from file->f_path.
 */
SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_vfs_open, const struct path *path, struct file *file)
{
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    if (fill_common(e, OP_OPEN)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    collect_path_fragments(dentry, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read, struct file *file, char *buf, size_t count, loff_t *pos)
{
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    if (fill_common(e, OP_READ)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    collect_path_fragments(dentry, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    if (fill_common(e, OP_WRITE)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    collect_path_fragments(dentry, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
