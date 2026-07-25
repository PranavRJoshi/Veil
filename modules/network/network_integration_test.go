//go:build integration && linux

package network

import (
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/testutil"
)

/*
	Integration tests for the network module.

	This module carries the most state: four hooks feeding two correlation
	maps. sock_pid is keyed by the socket and filled from process context
	by the connect and accept probes; listen_pid is keyed by the listening
	port and filled by inet_listen.

	The correlation matters because the tracepoint that classifies state
	transitions runs in softirq context, where the current task is
	unrelated to the socket's owner. Without a map hit the event carries
	pid 0, so asserting on the pid is what proves the correlation ran.

	Ordering constraint worth knowing: listen_pid is populated by the
	inet_listen kprobe, so a listener created before the module loads
	leaves no entry. Tests that depend on that fallback must load the
	module first.
*/

func selfPID() uint32 { return uint32(os.Getpid()) }

func selfPIDString() string { return strconv.FormatUint(uint64(selfPID()), 10) }

/*
	listenLocal opens an IPv4 loopback listener on an ephemeral port and
	returns it with that port. The module only hooks tcp_v4_connect, so
	the network must be v4.
*/
func listenLocal(t *testing.T) (net.Listener, uint16) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse listener address %q: %v", ln.Addr(), err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return ln, uint16(port)
}

/*
	connectOnce completes a full connect/accept/close cycle against ln, so
	the tracepoint sees the whole transition sequence on both ends.
*/
func connectOnce(t *testing.T, ln net.Listener) {
	t.Helper()

	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial %s: %v", ln.Addr(), err)
	}
	conn.Close()
	<-accepted
}

func isNetwork(c testutil.Captured) bool { return c.Module == "network" }

/*
	evtOn matches an event of the given type where port appears on the
	given side.
*/
func evtOn(evtType, side string, port uint16) func(testutil.Captured) bool {
	want := strconv.FormatUint(uint64(port), 10)
	return func(c testutil.Captured) bool {
		if !isNetwork(c) {
			return false
		}
		if got, ok := c.Field("evt_type"); !ok || got != evtType {
			return false
		}
		got, ok := c.Field(side)
		return ok && got == want
	}
}

/*
	Events raised from process context take their pid from sock_pid, which
	the connect and listen probes fill directly.
*/
func TestIntegrationNetworkListenAndConnectCarryPID(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{}, sink)
	testutil.StartModule(t, mod)

	/* Created after the module loads so the listen probe observes it. */
	ln, port := listenLocal(t)

	listen := sink.WaitFor(t, testutil.DefaultTimeout, evtOn("LISTEN", "sport", port))
	if pid, _ := listen.Field("pid"); pid != selfPIDString() {
		t.Errorf("LISTEN pid = %s, want %s", pid, selfPIDString())
	}

	connectOnce(t, ln)

	connect := sink.WaitFor(t, testutil.DefaultTimeout, evtOn("CONNECT", "dport", port))
	if pid, _ := connect.Field("pid"); pid != selfPIDString() {
		t.Errorf("CONNECT pid = %s, want %s", pid, selfPIDString())
	}
	if comm, _ := connect.Field("comm"); comm == "" {
		t.Error("CONNECT event has an empty comm")
	}
}

/*
	The accepted connection reaches ESTABLISHED inside the handshake, in
	softirq context and before accept() has returned, so sock_pid has no
	entry for the new socket yet. The pid can only come from listen_pid,
	keyed by the listening port.

	A pid of 0 here means that fallback did not fire and the event was
	attributed to nobody.
*/
func TestIntegrationNetworkAcceptRecoversPIDFromListenMap(t *testing.T) {
	testutil.RequireBPF(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{}, sink)
	testutil.StartModule(t, mod)

	ln, port := listenLocal(t)
	connectOnce(t, ln)

	/*
		The server side of the connection has the listening port as its
		source, which distinguishes it from the client's ESTABLISHED
		where that port is the destination.
	*/
	server := sink.WaitFor(t, testutil.DefaultTimeout, evtOn("ESTABLISHED", "sport", port))

	pid, _ := server.Field("pid")
	if pid == "0" {
		t.Error("server ESTABLISHED carries pid 0; the listen_pid fallback did not fire")
	} else if pid != selfPIDString() {
		t.Errorf("server ESTABLISHED pid = %s, want %s", pid, selfPIDString())
	}
}

/*
	A port filter matches when the port appears as either endpoint, and
	must exclude everything else.
*/
func TestIntegrationNetworkPortFilterMatchesEitherEnd(t *testing.T) {
	testutil.RequireBPF(t)

	/* Port must be known before the filter can be configured. */
	ln, port := listenLocal(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{Ports: []uint16{port}}, sink)
	stop := testutil.StartModule(t, mod)

	connectOnce(t, ln)
	sink.WaitFor(t, testutil.DefaultTimeout, evtOn("CONNECT", "dport", port))
	stop()

	want := strconv.FormatUint(uint64(port), 10)
	var sawSource, sawDest bool
	for _, c := range sink.Snapshot() {
		sport, _ := c.Field("sport")
		dport, _ := c.Field("dport")
		if sport != want && dport != want {
			t.Errorf("port filter admitted an event on neither end of %s: %v", want, c.Fields)
		}
		if sport == want {
			sawSource = true
		}
		if dport == want {
			sawDest = true
		}
	}

	/*
		Both ends occur in one connection: the client has it as
		destination, the server as source. Seeing only one would mean the
		filter is checking a single side.
	*/
	if !sawSource || !sawDest {
		t.Errorf("expected the port on both ends across %d events; source=%v dest=%v",
			sink.Len(), sawSource, sawDest)
	}
}

/*
	Deny takes precedence over allow. Two listeners give the assertion a
	positive control: the permitted port must still produce events while
	the denied one produces none.
*/
func TestIntegrationNetworkDenyPortBeatsAllow(t *testing.T) {
	testutil.RequireBPF(t)

	deniedLn, deniedPort := listenLocal(t)
	allowedLn, allowedPort := listenLocal(t)

	sink := testutil.NewCaptureSink()
	mod := New(FilterConfig{
		Ports:     []uint16{deniedPort, allowedPort},
		DenyPorts: []uint16{deniedPort},
	}, sink)
	stop := testutil.StartModule(t, mod)

	connectOnce(t, deniedLn)
	connectOnce(t, allowedLn)

	sink.WaitFor(t, testutil.DefaultTimeout, evtOn("CONNECT", "dport", allowedPort))
	stop()

	denied := strconv.FormatUint(uint64(deniedPort), 10)
	for _, c := range sink.Snapshot() {
		sport, _ := c.Field("sport")
		dport, _ := c.Field("dport")
		if sport == denied || dport == denied {
			t.Errorf("port %s was in both allow and deny but still emitted: %v", denied, c.Fields)
		}
	}
}
