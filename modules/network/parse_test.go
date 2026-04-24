package network

import (
	"encoding/binary"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	buildNetRaw constructs a 48-byte raw buffer matching the C struct net_event layout.
*/
func buildNetRaw(pid, uid, saddr, daddr uint32, sport, dport uint16, evtType, oldstate, newstate uint8, ts uint64, comm string) []byte {
	buf := make([]byte, 48)
	binary.LittleEndian.PutUint32(buf[0:4], pid)
	binary.LittleEndian.PutUint32(buf[4:8], uid)
	binary.LittleEndian.PutUint32(buf[8:12], saddr)
	binary.LittleEndian.PutUint32(buf[12:16], daddr)
	binary.LittleEndian.PutUint16(buf[16:18], sport)
	binary.LittleEndian.PutUint16(buf[18:20], dport)
	buf[20] = evtType
	buf[21] = oldstate
	buf[22] = newstate
	buf[23] = 0 /* pad */
	binary.LittleEndian.PutUint64(buf[24:32], ts)
	copy(buf[32:48], comm)
	return buf
}

func TestParseNetEventBasic(t *testing.T) {
	/* 10.0.2.15 in network byte order = 0x0F02000A */
	saddr := uint32(0x0F02000A)
	/* 93.184.216.34 = 0x22D8B85D */
	daddr := uint32(0x22D8B85D)

	raw := buildNetRaw(1234, 1000, saddr, daddr, 54268, 80, EvtConnect, 7, 2, 99999, "curl")

	e, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if e.Kind != events.KindNetwork {
		t.Errorf("expected KindNetwork, got %v", e.Kind)
	}
	if e.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", e.PID)
	}
	if e.UID != 1000 {
		t.Errorf("expected UID 1000, got %d", e.UID)
	}
	if e.SrcPort != 54268 {
		t.Errorf("expected sport 54268, got %d", e.SrcPort)
	}
	if e.DstPort != 80 {
		t.Errorf("expected dport 80, got %d", e.DstPort)
	}
	if e.EvtType != EvtConnect {
		t.Errorf("expected EvtConnect, got %d", e.EvtType)
	}
	if e.ProcessName() != "curl" {
		t.Errorf("expected comm 'curl', got %q", e.ProcessName())
	}
}

func TestParseNetEventShortRead(t *testing.T) {
	_, err := parseEvent(make([]byte, 47))
	if err == nil {
		t.Fatal("expected error for short buffer, got nil")
	}
}

func TestFormatIPv4(t *testing.T) {
	cases := []struct {
		addr     uint32
		expected string
	}{
		{0x0100007F, "127.0.0.1"},     /* 127.0.0.1 in little-endian */
		{0x00000000, "0.0.0.0"},
		{0xFFFFFFFF, "255.255.255.255"},
	}

	for _, c := range cases {
		got := FormatIPv4(c.addr)
		if got != c.expected {
			t.Errorf("FormatIPv4(0x%08X) = %q, want %q", c.addr, got, c.expected)
		}
	}
}

func TestEvtTypeName(t *testing.T) {
	cases := []struct {
		evtType  uint8
		expected string
	}{
		{EvtConnect, "CONNECT"},
		{EvtEstablished, "ESTABLISHED"},
		{EvtClose, "CLOSE"},
		{EvtFailed, "FAILED"},
		{EvtListen, "LISTEN"},
		{99, "EVT_99"},
	}

	for _, c := range cases {
		got := EvtTypeName(c.evtType)
		if got != c.expected {
			t.Errorf("EvtTypeName(%d) = %q, want %q", c.evtType, got, c.expected)
		}
	}
}

func TestTCPStateName(t *testing.T) {
	cases := []struct {
		state    uint8
		expected string
	}{
		{1, "ESTABLISHED"},
		{2, "SYN_SENT"},
		{7, "CLOSE"},
		{10, "LISTEN"},
		{99, "STATE_99"},
	}

	for _, c := range cases {
		got := TCPStateName(c.state)
		if got != c.expected {
			t.Errorf("TCPStateName(%d) = %q, want %q", c.state, got, c.expected)
		}
	}
}
