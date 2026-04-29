//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256

struct file_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    __u8  comm[16];
    __u8  filename[MAX_FILENAME_LEN];
    __u8  op;       // 0=open, 1=read, 2=write
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
 * If a filter map is non-empty (indicated by filter_cfg bitmask),
 * only events whose key is present in the map are submitted.
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
 * Filter configuration bitmask (single-element array map).
 *   bit 0 = pid_filter active
 *   bit 1 = uid_filter active
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
 * 'dentry' is a structure which is primarily used by the VFS. The pathname
 * argument passed to VFS system calls such as 'open(2)', 'read(2)', 'write(2)'
 * etc are used by the VFS to search through the directory entry cache (aka
 * dcache or dentry cache). VFS related kernel probes that are used here only
 * contain the leaf name instead of the absolute path.
 *
 * For a complete documentation of VFS and dentry, check the link below:
 *		- https://www.kernel.org/doc/html/latest/filesystems/vfs.html
 *
 * This function is used by the read and write variant as the open variant
 * contains the path rather than the filename alone.
 *
 * TODO: Inspect some easier way to extract the filename if possible.
 *
 * BPF_CORE_READ is a CO-RE macro which was introduced in v0.0.6 of libbpf.
 * It is used to simplify BPF CO-RE relocatable read, especially when there
 * are few pointer chasing steps.
 *
 * As with macros in C, this one too expands to a layer of macros that can
 * be hard to track down. I'll try to demystify it later.
 *
 * The documentation for this macro can be found in the link below:
 *		- https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_CORE_READ/
 * The implementation detail can be located in the libbpf source:
 *		- https://github.com/libbpf/libbpf/blob/master/src/bpf_core_read.h#L525-L529
 *
 * Lastly, if you 'pahole(1)' in your system, consult the various structures that
 * are seen here for some further context.
 */
static __always_inline void resolve_name_from_file(struct file *f, __u8 *buf, __u32 size)
{
    struct dentry *dentry = BPF_CORE_READ(f, f_path.dentry);
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(buf, size, d_name.name);
}

/*
 * resolve_name_from_filename reads the leaf filename from struct path's
 * dentry. Used for vfs_open where filename is the first argument.
 */
static __always_inline void resolve_name_from_path(const struct path *p, __u8 *buf, __u32 size)
{
    struct dentry *dentry = BPF_CORE_READ(p, dentry);
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(buf, size, d_name.name);
}

/*
 * Kprobe hooks on VFS functions. Each function reserves a ring buffer
 * slot, checks filters via fill_common, resolves the filename, and
 * submits. If the event is filtered out, the slot is discarded.
 *
 * For vfs_open, we use the struct filename* first argument directly since
 * the struct file may not be fully initialized at entry time.
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
 
    resolve_name_from_path(path, e->filename, sizeof(e->filename));
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
 
    resolve_name_from_file(file, e->filename, sizeof(e->filename));
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
 
    resolve_name_from_file(file, e->filename, sizeof(e->filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
