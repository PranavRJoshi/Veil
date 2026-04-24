package network

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_arm64" NetworkTracer ../../bpf/network_tracer.bpf.c

/*
	********************************** NOTE **********************************

	The network module traces TCP connection lifecycle events using four
	BPF hooks:

	  1. tracepoint/sock/inet_sock_set_state - fires on every TCP state
	     transition. This is the main event source. Available since kernel
	     4.16 and part of the stable kernel ABI.

	  2. kprobe/tcp_v4_connect - fires in process context when connect()
	     is called. Used solely to stash the PID and comm into a BPF hash
	     map keyed by socket pointer, because the tracepoint fires in
	     interrupt context where bpf_get_current_pid_tgid() returns the
	     wrong PID.

	  3. kretprobe/inet_csk_accept - fires when accept() returns. Same
	     purpose as above but for inbound connections.

	  4. krpobe/inet_listen - fires when listen() is called. Like connect,
	     it is used for stashing PID, comm, and UID. Useful for tracing
	     server programs.

	State transitions are classified into meaningful event types:
	  CONNECT     - outbound connection initiated
	  ESTABLISHED - connection established (inbound or outbound)
	  CLOSE       - connection closing
	  FAILED      - connection attempt failed
	  LISTEN      - server started listening

	********************************** NOTE **********************************
*/

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/PranavRJoshi/Veil/internal/exterrs"
	"github.com/PranavRJoshi/Veil/internal/events"
	"github.com/PranavRJoshi/Veil/internal/loader"
)

/*
	FilterConfig holds the parsed filter values from CLI flags.
*/
type FilterConfig struct {
	PIDs     []uint32    /* -p flag: filter by PID */
	UIDs     []uint32    /* -u flag: filter by UID */
	Ports    []uint16    /* --port flag: filter by port number */
	CommName string      /* -n flag: filter by process name (userspace) */
}

/*
	ParseFilterConfig interprets the raw CLI flags map into a typed
	FilterConfig.
*/
func ParseFilterConfig(flags map[string]string) (FilterConfig, error) {
	var cfg FilterConfig

	if raw, ok := flags["pid"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid PID %q: %w", s, err)
			}
			cfg.PIDs = append(cfg.PIDs, uint32(v))
		}
	}

	if raw, ok := flags["uid"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid UID %q: %w", s, err)
			}
			cfg.UIDs = append(cfg.UIDs, uint32(v))
		}
	}

	if raw, ok := flags["port"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
			if err != nil {
				return cfg, fmt.Errorf("invalid port %q: %w", s, err)
			}
			cfg.Ports = append(cfg.Ports, uint16(v))
		}
	}

	if raw, ok := flags["name"]; ok {
		cfg.CommName = raw
	}

	return cfg, nil
}

/*
	NetworkModule traces TCP connection lifecycle events.
	The eBPF program defines three kprobes (including one
	kretprobe, but oh well) and one tracepoint.
*/
type NetworkModule struct {
	*loader.BaseProgram
	objs           NetworkTracerObjects
	tpState        link.Link          /* tracepoint/sock/inet_sock_set_state */
	kprobeConnect  link.Link          /* kprobe/tcp_v4_connect */
	kretAccept     link.Link          /* kretprobe/inet_csk_accept */
	kprobeListen   link.Link          /* kprobe/inet_listen */
	reader         *ringbuf.Reader
	Events         chan events.NetworkEvent
	filter         FilterConfig
}

/*
	New creates a NetworkModule with the given filter configuration.
*/
func New(filter FilterConfig) *NetworkModule {
	return &NetworkModule{
		BaseProgram: loader.NewBaseProgram("network_tracer"),
		Events:      make(chan events.NetworkEvent, 256),
		filter:      filter,
	}
}

/*
	populateFilters writes PID, UID, and port filter values into BPF maps.
	Bitmask convention:
	  bit 0 = pid_filter active
	  bit 1 = uid_filter active
	  bit 2 = port_filter active
*/
func (n *NetworkModule) populateFilters() error {
	var mask uint32
	placeholder := uint8(1)

	if len(n.filter.PIDs) > 0 {
		mask |= 1
		for _, pid := range n.filter.PIDs {
			if err := n.objs.PidFilter.Update(pid, placeholder, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("network: set pid filter %d: %w", pid, err)
			}
		}
	}

	if len(n.filter.UIDs) > 0 {
		mask |= 2
		for _, uid := range n.filter.UIDs {
			if err := n.objs.UidFilter.Update(uid, placeholder, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("network: set uid filter %d: %w", uid, err)
			}
		}
	}

	if len(n.filter.Ports) > 0 {
		mask |= 4
		for _, port := range n.filter.Ports {
			if err := n.objs.PortFilter.Update(port, placeholder, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("network: set port filter %d: %w", port, err)
			}
		}
	}

	if mask != 0 {
		cfgKey := uint32(0)
		if err := n.objs.FilterCfg.Update(cfgKey, mask, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("network: set filter config: %w", err)
		}
	}

	return nil
}

/*
	Load loads the BPF objects, populates filter maps, and attaches the
	tracepoint and kprobes.
*/
func (n *NetworkModule) Load() error {
	if err := LoadNetworkTracerObjects(&n.objs, nil); err != nil {
		return fmt.Errorf("network: load objects: %w", err)
	}

	if err := n.populateFilters(); err != nil {
		return err
	}

	var err error

	/*
		Attach the kprobe on tcp_v4_connect for PID correlation on
		outbound connections. This must happen before attaching the
		tracepoint so that the sock_pid map is populated before events
		start flowing.
	*/
	n.kprobeConnect, err = link.Kprobe("tcp_v4_connect", n.objs.KprobeTcpV4Connect, nil)
	if err != nil {
		return fmt.Errorf("network: attach tcp_v4_connect: %w", err)
	}

	/*
		Attach the kretprobe on inet_csk_accept for PID correlation on
		inbound (accepted) connections.
	*/
	n.kretAccept, err = link.Kretprobe("inet_csk_accept", n.objs.KretprobeInetCskAccept, nil)
	if err != nil {
		return fmt.Errorf("network: attach inet_csk_accept: %w", err)
	}

	/*
		Attach the kprobe on inet_listen for PID correlation on server process.
		Notice that we used a kernel return probe on accept call. This would imply
		that any server on the system that is listening isn't previously logged
		and their PID (and other info) are not stashed.
	*/
	n.kprobeListen, err = link.Kprobe("inet_listen", n.objs.KprobeInetListen, nil)
	if err != nil {
		return fmt.Errorf("network: attach inet_listen: %w", err)
	}

	/*
		Attach the main tracepoint. This is where all the TCP state
		transition events come from.
	*/
	n.tpState, err = link.Tracepoint("sock", "inet_sock_set_state", n.objs.HandleInetSockSetState, nil)
	if err != nil {
		return fmt.Errorf("network: attach inet_sock_set_state: %w", err)
	}

	rd, err := ringbuf.NewReader(n.objs.NetEvents)
	if err != nil {
		return fmt.Errorf("network: open ringbuf: %w", err)
	}
	n.reader = rd

	if err := n.MarkLoaded(); err != nil {
		return err
	}

	go n.poll()
	return nil
}

func (n *NetworkModule) Close() error {
	var errs []error

	if n.reader != nil {
		errs = append(errs, n.reader.Close())
	}
	if n.tpState != nil {
		errs = append(errs, n.tpState.Close())
	}
	if n.kprobeConnect != nil {
		errs = append(errs, n.kprobeConnect.Close())
	}
	if n.kretAccept != nil {
		errs = append(errs, n.kretAccept.Close())
	}
	if n.kprobeListen != nil {
		errs = append(errs, n.kprobeListen.Close())
	}

	n.objs.Close()
	close(n.Events)

	if err := n.MarkClosed(); err != nil {
		errs = append(errs, err)
	}

	return exterrs.Join(errs)
}

/*
	Run consumes events from the Events channel and prints formatted output.
*/
func (n *NetworkModule) Run(done <-chan struct{}) {
	for {
		select {
		case e, ok := <-n.Events:
			if !ok {
				return
			}
			fmt.Printf("[%s] pid=%-6d uid=%-5d comm=%-16s %-12s %s:%d -> %s:%d (%s->%s)\n",
				e.Kind,
				e.PID,
				e.UID,
				e.ProcessName(),
				EvtTypeName(e.EvtType),
				FormatIPv4(e.SrcAddr),
				e.SrcPort,
				FormatIPv4(e.DstAddr),
				e.DstPort,
				TCPStateName(e.OldState),
				TCPStateName(e.NewState),
			)
		case <-done:
			return
		}
	}
}

/*
	poll reads events from the ring buffer, applies userspace filters,
	and sends matching events to the channel.
*/
func (n *NetworkModule) poll() {
	for {
		record, err := n.reader.Read()
		if err != nil {
			return
		}

		e, err := parseEvent(record.RawSample)
		if err != nil {
			continue
		}

		/* Userspace filter: comm name (substring match) */
		if n.filter.CommName != "" && !strings.Contains(e.ProcessName(), n.filter.CommName) {
			continue
		}

		n.Events <- e
	}
}
