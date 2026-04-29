//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET     2
#define AF_INET6    10

/*
 * A note on the below used BPF_KPROBE macro and simililar macros that appear
 * as function name. These macros are defined in 'bpf/bpf_tracing.h'. One
 * particular reason to prefer these macros over conventional alternative
 * is to abstract away the low-level machine dependent characteristics of
 * kernel probes. Kprobes are powerful tracing feature which allows the
 * user to probe [non-blacklisted] functions defined in the kernel.
 *
 * kprobe interface of BCC supports instrumenting the beginning of a function
 * and a function plus instruction offset. Other tools such as bpftrace
 * currently supports instrumenting the beginning of a function only.
 *
 * Furthermore, within Kprobes, there are can be two callbacks defined:
 * pre-handler, and post-handler. There is one rule when installing
 * some special pre-handler: if the pre-handler modifies the instruction
 * pointer, the return value from that handler must be !0. The post-handler
 * also should not be called anymore. This is explained in section 
 * 'Changing Execution Path' of Kernel Probes (Kprobes):
 *	- https://www.kernel.org/doc/html/latest/trace/kprobes.html#changing-execution-path
 * I should also make the reader aware that we don't really deal with such
 * pre-handler and post-handler in the following program.
 *
 * The following article provides a good introduction to Kprobes and how it
 * is implemented in the Linux kernel. Although the article is a bit old,
 * it is still worthwhile to understand the functionality of the Kprobe
 * interface provided by the kernel:
 *	- https://lwn.net/Articles/132196/
 * NOTE: JProbe interface has been removed from the Linux kernel since 2018.
 *
 * The following output is retrieved when cpp executes the macro for
 * tcp_v4_connect. Some additional whitespace and newlines have been
 * added to provide readability.
 *
 *		#pragma GCC diagnostic push
 *		# 196 "network_tracer.bpf.c"
 *		#pragma GCC diagnostic ignored "-Wignored-attributes"
 *		# 196 "network_tracer.bpf.c"
 *		 __attribute__((section("kprobe/tcp_v4_connect"), used))
 *		# 196 "network_tracer.bpf.c"
 *		#pragma GCC diagnostic pop
 *		int kprobe_tcp_v4_connect(struct pt_regs *ctx); 
 *		static __attribute__((always_inline)) 
 *		typeof(kprobe_tcp_v4_connect(0)) ____kprobe_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk);
 *
 *		typeof(kprobe_tcp_v4_connect(0)) kprobe_tcp_v4_connect(struct pt_regs *ctx)
 *		{
 *			# 197 "network_tracer.bpf.c"
 *			#pragma GCC diagnostic push
 *			# 197 "network_tracer.bpf.c"
 *			#pragma GCC diagnostic ignored "-Wint-conversion"
 *			# 197 "network_tracer.bpf.c"
 *		    return ____kprobe_tcp_v4_connect(ctx, (void *)(((const volatile struct user_pt_regs *)(ctx))->regs[0]));
 *			# 197 "network_tracer.bpf.c"
 *			#pragma GCC diagnostic pop
 *			# 197 "network_tracer.bpf.c"
 *		} 
 *		static __attribute__((always_inline))
 *		typeof(kprobe_tcp_v4_connect(0)) ____kprobe_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
 *		{
 *		    struct pid_info info = {};
 *		    __u64 pid_tgid = bpf_get_current_pid_tgid();
 *		    info.pid = pid_tgid >> 32;
 *		    __u64 uid_gid = bpf_get_current_uid_gid();
 *		    info.uid = (__u32)uid_gid;
 *		    bpf_get_current_comm(&info.comm, sizeof(info.comm));
 *		
 *		    bpf_map_update_elem(&sock_pid, &sk, &info, BPF_ANY);
 *		    return 0;
 *		}
 * 
 * Here, we can see that the macro expanded to declare another the standard
 * kprobe function:
 *		kprobe_tcp_v4_connect()
 * This name is extracted from the first argument to BPF_KPROBE() macro. It is
 * also used by the bpf2go program to locate the program object. For the kernel,
 * only, the section of elf file is necessary, which is dealt with using the SEC
 * macro. The 'kprobe_tcp_v4_connect()' function then internally calls 
 * '____kprobe_tcp_v4_connect()' to extract the events that was requested.
 *
 * Although the layers of abstraction may seem bizzare, it should be appreciated
 * since it allows portability and consistency across various kernel versions.
 * The "unabstraced" way would be to simply use the 'bpf(2)' system call along
 * with some additional help from 'perf_event_open(2)' system call. Similar to
 * how brittle the 'ioctl(2)' system call is, handling a functionality as powerful
 * as Kprobes needs to be done with great care.
 *
 * Like I've mentioned previously, the kprobe interface allows live patching of
 * kernel instruction. The way to instrument the kernel instruction using kprobe
 * is (excerpt from _BPF Performance Tools_ by Brendan Gregg):
 *
 *	1. If it's a kprobe:
 *		- Bytes from the target address are copied and saved by kprobes. The kprobe
 *		  interface assures that there are enough bytes to span their replacement
 *		  with a breakpoint instruction.
 *		- Target address is replaced by a breakpoint instruction. (or jmp if viable.)
 *		- Upon executing the target address, breakpoint is hit and the breakpoint
 *		  handler checks whether the breakpoint was installed by kprobes. For kprobe
 *		  installed breakpoint, the kprobe handler is executed.
 *		- After the handler is done, original instructions are executed, and the
 *		  instruction flow resumes.
 *		- When the kprobe is no longer required, the original bytes are copied back
 *		  to the target address, and the 
 *
 *	2. If it's a kretprobe:
 *		- A kprobe is created for the entry to the function.
 *		- Upon entry of the function, when the kprobe is hit, the return address is
 *		  saved and then replaced with a substitute function: kretprobe_trampoline().
 *		- When the function finally calls return (e.g., the ret instruction), the CPU
 *		  passes control to the trampoline function, which executes the kretprobe
 *		  handler.
 *		- The kretprobe handler finishes by returning to the saved return address.
 *		- When the kretprobe is no longer needed, the kprobe is removed.
 *
 * To avoid recursive trap condition, it is not possible to attach kprobe to the kprobe
 * function itself, along with some other blacklisted functions.
 *
 * The Linux kernel provides three interfaces to use Kprobes:
 *
 *	1. Kprobe API: register_kprobe() etc.
 *	2. Ftrace-based, via 'sys/kernel/debug/tracing/kprobe_events': where kprobes can be
 *	   enabled and disabled by writing configuration strings to this file.
 *	3. perf_event_open(): as used by perf(1) tool, and more recently by BPF tracing, as
 *	   support was added in the Linux 4.17 kernel.
 *
 * Out of most front-ends for eBPF, only BCC allows instrumenting function with an
 * instruction offset through the 'attach_kprobe()' and 'attach_kretprobe()' interface.
 */

/*
 * TCP states. The file 'vmlinux.h' file defines these symbols inside an
 * enum using the 'BPF_' prefix.
 *
 * NOTE: If you add constants here, also modify 'tcpStateNames' in parse.go
 * file.
 *
 * TODO: Check if we really need these define symbols or if the enumeration
 * constants from vmlinux.h is usable as well, provided we also modify
 * the symbols that are used in the functions below. Two additional constants
 * are missing here.
 */
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_LISTEN       10
#define TCP_CLOSING      11

/*
 * Event classification. Select appropriate event for the state transition.
 * See the tracepoint below for its usage. More additional events could be
 * defined since I didn't cover all the possible state transitions for now.
 *
 * NOTE: If you add more constants, make sure it is reflected in Event types
 * in parse.go file for network module.
 */
#define EVT_CONNECT      0
#define EVT_ESTABLISHED  1
#define EVT_CLOSE        2
#define EVT_FAILED       3
#define EVT_LISTEN       4

/* Data structure used for ring buffer */
struct net_event {
    __u32 pid;
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  evt_type;
    __u8  oldstate;
    __u8  newstate;
    __u8  pad;
    __u64 timestamp;
    __u8  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   /* 16 MB */
} net_events SEC(".maps");

/*
 * Since Linux 4.16, the sock:inet_sock_set_state tracepoint was added,
 * but it is possible that this tracepoint may run outside of process
 * context. This is also discussed in the Python script for 'tcpaccept'.
 *
 * PID correlation map. The sock:inet_sock_set_state tracepoint fires
 * in interrupt/softirq context for most state transitions, where
 * bpf_get_current_pid_tgid() returns a kernel thread; useless.
 *
 * The solution (used by BCC's tcptracer, Coroot, SysmonForLinux):
 *   1. Hook tcp_v4_connect (kprobe). Fires in process context before
 *      the SYN is sent. Stash PID+UID+comm keyed by socket pointer.
 *   2. Hook inet_csk_accept (kretprobe). Fires in process context when
 *      accept() returns. Stash PID+UID+comm for the accepted socket.
 *   3. Hook inet_listen (kprobe). Fires in process context when listen()
 *      is called. Stash PID+UID+comm keyed by socket pointer.
 *   4. In the tracepoint handler, look up the stashed info by socket pointer.
 */
struct pid_info {
    __u32 pid;
    __u32 uid;
    __u8  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock *);
    __type(value, struct pid_info);
} sock_pid SEC(".maps");

/*
 * Listening port -> pid_info map. When inet_listen fires, we stash
 * the PID keyed by the local port. When SYN_RECV->ESTABLISHED fires
 * on a child socket (which has the same local port as the listener),
 * we can look up the server's PID.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);         /* local port */
    __type(value, struct pid_info);
} listen_pid SEC(".maps");

/*
 * Filter maps, similar to one found in syscall and files.
 *   bit 0 = pid_filter active
 *   bit 1 = uid_filter active
 *   bit 2 = port_filter active
 */
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
    __uint(max_entries, 64);
    __type(key, __u16);     /* port number */
    __type(value, __u8);
} port_filter SEC(".maps");

/* filter configuration array */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_cfg SEC(".maps");

/*
 * check_pid_filter returns 1 if the event should be dropped (filtered out).
 * Returns 0 if the event passes all filters.
 */
static __always_inline int check_pid_filter(__u32 pid, __u32 uid)
{
    __u32 cfg_key = 0;
    __u32 *cfg = bpf_map_lookup_elem(&filter_cfg, &cfg_key);
    if (!cfg || !*cfg)
        return 0;   /* no filters active */

    __u32 mask = *cfg;

    if ((mask & 1) && !bpf_map_lookup_elem(&pid_filter, &pid))
        return 1;

    if ((mask & 2) && !bpf_map_lookup_elem(&uid_filter, &uid))
        return 1;

    return 0;
}

static __always_inline int check_port_filter(__u16 sport, __u16 dport)
{
    __u32 cfg_key = 0;
    __u32 *cfg = bpf_map_lookup_elem(&filter_cfg, &cfg_key);
	/* no filter, process the packet */
    if (!cfg || !*cfg)
        return 0;

    __u32 mask = *cfg;
	/* port filter was not active */
    if (!(mask & 4))
        return 0;

	/*
	 * If either of source or destination port from the kernel
	 * is contained within the map, then we return 0 to indicate
	 * it needs to be processed.
	 */
    if (bpf_map_lookup_elem(&port_filter, &sport))
        return 0;
    if (bpf_map_lookup_elem(&port_filter, &dport))
        return 0;

    return 1;   /* neither port matched; filter out */
}

/*
 * Kprobe on tcp_v4_connect: fires in process context when an outbound
 * TCP connection is initiated. We stash the PID, UID, and comm for
 * later retrieval in the tracepoint handler.
 *
 * Signature: int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 *
 * The function tcp_v4_connect is defined in linux/net/ipv4/tcp_ipv4.c
 */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk)
{
    struct pid_info info = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    info.uid = (__u32)uid_gid;

    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&sock_pid, &sk, &info, BPF_ANY);

    return 0;
}

/*
 * Kretprobe on inet_csk_accept: fires when accept() returns a new
 * connected socket. We stash the acceptor's PID for the new socket.
 *
 * Return value: struct sock * (the accepted socket)
 *
 * The function inet_csk_accept is defined in linux/net/ipv4/inet_connection_sock.c
 */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, struct sock *sk)
{
    if (!sk)
        return 0;

    struct pid_info info = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    info.uid = (__u32)uid_gid;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&sock_pid, &sk, &info, BPF_ANY);

    return 0;
}

/*
 * Kprobe on inet_listen(). Fires in process context when listen()
 * is called. Stashes PID so the CLOSE->LISTEN state transition
 * in the tracepoint handler can report the correct process.
 *
 * Signature: int inet_listen(struct socket *sock, int backlog)
 *
 * We extract struct sock from socket->sk.
 *
 * The function inet_listen is defined in linux/net/ipv4/af_inet.c
 */
SEC("kprobe/inet_listen")
int BPF_KPROBE(kprobe_inet_listen, struct socket *sock, int backlog)
{
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    struct pid_info info = {};

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    info.uid = (__u32)uid_gid;

    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&sock_pid, &sk, &info, BPF_ANY);

	/*
	 * When the server accepts a connection, a new socket is returned by the
	 * kernel, see 'accept(2)'. In the sock structure, a field __sk_common
	 * exists which is of type 'struct sock_common'. This structure contains
	 * an anonymous union that has a structure embedded within it as:
	 *
	 *		union {
	 *			__portpair		skc_portpair;
	 *			struct {
	 *				__be16		skc_dport;
	 *				__u16		skc_num;
	 *			};
	 *		};
	 *
	 * From the listening process's context, skc_num represents the source port
	 * and since it's already in host byte order, we need not transform it.
	 */
    __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	/* TODO: Could source/local port be zero? */
    if (lport)
        bpf_map_update_elem(&listen_pid, &lport, &info, BPF_ANY);

    return 0;
}

/*
 * The main tracepoint handler. Fires on every TCP state transition.
 *
 * The tracepoint context (struct trace_event_raw_inet_sock_set_state)
 * provides: skaddr, oldstate, newstate, sport, dport, family,
 * saddr/daddr (for IPv4), saddr_v6/daddr_v6 (for IPv6).
 *
 * The structure trace_event_raw_inet_sock_set_state is defined in
 * 'vmlinux.h'. There are quite a number of fields that is associated
 * with this tracepoint's format (see
 * /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format).
 *
 * We classify the state transition into a meaningful event type and
 * only emit events for transitions we care about. The PID is looked
 * up from our sock_pid map.
 */
SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	/* currently only supports IPv4 */
    if (ctx->family != AF_INET)
        return 0;

    __u8 oldstate = ctx->oldstate;
    __u8 newstate = ctx->newstate;

    /*
	 * Determine the state transition. We intentionally skip some transitions
	 * that aren't of interest to us.
     */
    __u8 evt_type;

	/*
	 * Currently, only the following state transitions are covered.
	 * More state transition may be covered later...
	 *
	 * TCP_CLOSE       -> TCP_SYN_SENT     - Outbound connection
	 * TCP_SYN_SENT    -> TCP_ESTABLISHED  - Outbound connection established
	 * TCP_SYN_RECV    -> TCP_ESTABLISHED  - Inbound connection established
	 * TCP_SYN_SENT    -> TCP_CLOSE        - Outbound connection failed
	 * TCP_ESTABLISHED -> TCP_FIN_WAIT1    - connection close
	 * TCP_ESTABLISHED -> TCP_CLOSE_WAIT   - connection close
	 * TCP_CLOSE       -> TCP_LISTEN       - awaiting connection
	 *
	 * TODO: For a server, the transition TCP_LISTEN -> TCP_SYN_RECV occurs
	 * during accept call. We don't include it here. Some additional transition
	 * occurs when the socket is being closed. We don't take that into account
	 * as well.
	 */
    if (oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT) {
        evt_type = EVT_CONNECT;
    } else if (oldstate == TCP_SYN_SENT && newstate == TCP_ESTABLISHED) {
        evt_type = EVT_ESTABLISHED;
    } else if (oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED) {
        evt_type = EVT_ESTABLISHED;
    } else if (oldstate == TCP_SYN_SENT && newstate == TCP_CLOSE) {
        evt_type = EVT_FAILED;
    } else if (oldstate == TCP_ESTABLISHED && newstate == TCP_FIN_WAIT1) {
        evt_type = EVT_CLOSE;
    } else if (oldstate == TCP_ESTABLISHED && newstate == TCP_CLOSE_WAIT) {
        evt_type = EVT_CLOSE;
    } else if (oldstate == TCP_CLOSE && newstate == TCP_LISTEN) {
        evt_type = EVT_LISTEN;
    } else {
        return 0;
    }

    /*
	 * Fetch the source and destination port. Still a bit uncertain
	 * of whether or not we need to perform byte order swap.
	 * On tcpaccept script, I saw the 'ntohs' macro being used
	 * for destination port, but also noticed that the port value
	 * is retrieved from the sock_common data structure, which explicitly
	 * uses the '__be16' type. In our case, the type for 'ctx' is defined
	 * in 'vmlinux.h', and the 'sport' and 'dport' field are defined with
	 * the type '__u16'.
	 *
	 * Also, the tracing output is accurate without explicit byte order
	 * conversion, so this seems to be correct...
     */
    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;

    /*
	 * If the user specified the interested port, this function
	 * will return 0 if the received packet has the port of our
	 * interest. Else, it will return 1, so we can return out early.
	 */
    if (check_port_filter(sport, dport))
        return 0;

    /*
     * Look up the PID from our correlation map. If not found (e.g.,
     * kernel-initiated state change), we still emit the event with
     * pid=0 as the connection status is still informational.
     */
    struct sock *sk = (struct sock *) ctx->skaddr;
    struct pid_info *info = bpf_map_lookup_elem(&sock_pid, &sk);

	/*
	 * For a listening socket, we need a workaround. The kprobe for connect
	 * call will be fired once a connection request is made, and the kprobe
	 * for accept call will be fired once a connection requested is accepted.
	 *
	 * When debugging this eBPF program, I noticed transition of 
	 *					SYN_RECV -> ESTABLISHED
	 * occurred in process context of the client even though it is for the
	 * server process. Since the kernel handles the three-way handshake for
	 * the user, when the client's ACK packet is being processed, the server's
	 * state also transitions and the process state is that of client's even
	 * though the transition is that of the server. 
	 *
	 * TODO: We could also try to check only the 'info' variable, and if its
	 * null, then check on 'listen_pid' map, skipping the checking of old and
	 * new state.
	 */
    if (!info && oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED) {
        info = bpf_map_lookup_elem(&listen_pid, &sport);
    }

    __u32 pid = info ? info->pid : 0;
    __u32 uid = info ? info->uid : 0;

    /* Check PID/UID filters */
    if (check_pid_filter(pid, uid))
        return 0;

    /* Reserve and populate the event */
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid       = pid;
    e->uid       = uid;
    e->saddr     = ctx->saddr[0] | (ctx->saddr[1] << 8) |
                   (ctx->saddr[2] << 16) | (ctx->saddr[3] << 24);
    e->daddr     = ctx->daddr[0] | (ctx->daddr[1] << 8) |
                   (ctx->daddr[2] << 16) | (ctx->daddr[3] << 24);
    e->sport     = sport;
    e->dport     = dport;
    e->evt_type  = evt_type;
    e->oldstate  = oldstate;
    e->newstate  = newstate;
    e->pad       = 0;
    e->timestamp = bpf_ktime_get_ns();

    if (info) {
        __builtin_memcpy(e->comm, info->comm, sizeof(e->comm));
    } else {
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
    }

    bpf_ringbuf_submit(e, 0);

    /*
     * Clean up the sock_pid entry when the connection closes.
     * This prevents the map from growing unbounded.
     */
    if (newstate == TCP_CLOSE || newstate == TCP_CLOSE_WAIT) {
        bpf_map_delete_elem(&sock_pid, &sk);
    }

	/*
	 * When the connection is closed and the process terminates,
	 * the state transitions from LISTEN to CLOSE. We need to
	 * update that in the 'listen_pid' map.
	 */
	if (newstate == TCP_CLOSE && oldstate == TCP_LISTEN) {
        bpf_map_delete_elem(&listen_pid, &sport);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
