//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256

struct file_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u8  comm[16];
    __u8  path[MAX_PATH_LEN];
    __u8  op;       // 0=open, 1=read, 2=write
};

#define OP_OPEN  0
#define OP_READ  1
#define OP_WRITE 2

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_events SEC(".maps");

// helper — fills common fields and resolves path
/*
 * Uses the following 'bpf-helpers(7)' functions:
 *		- bpf_ringbuf_reserve
 *		- bpf_get_current_pid_tgid
 *		- bpf_ktime_get_ns
 *		- bpf_get_current_comm
 *		- bpf_probe_read_kernel_str
 *		- bpf_ringbuf_submit
 */
static __always_inline int submit_event(struct file *f, __u8 op)
{
    struct file_event *e;

    e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid       = bpf_get_current_pid_tgid() >> 32;
    e->tid       = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->op        = op;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/*
	 * Read filename from dentry instead of bpf_d_path
	 */
	struct dentry *dentry = BPF_CORE_READ(f, f_path.dentry);
	struct qstr d_name = BPF_CORE_READ(dentry, d_name);
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), d_name.name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_vfs_open, const struct path *path, struct file *file)
{
    return submit_event(file, OP_OPEN);
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read, struct file *file, char *buf, size_t count, loff_t *pos)
{
    return submit_event(file, OP_READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    return submit_event(file, OP_WRITE);
}

char LICENSE[] SEC("license") = "GPL";
