package network

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	net_event C struct layout (48 bytes):
	  offset  0:  pid       (uint32)
	  offset  4:  uid       (uint32)
	  offset  8:  saddr     (uint32, network byte order)
	  offset 12:  daddr     (uint32, network byte order)
	  offset 16:  sport     (uint16, host byte order)
	  offset 18:  dport     (uint16, host byte order)
	  offset 20:  evt_type  (uint8)
	  offset 21:  oldstate  (uint8)
	  offset 22:  newstate  (uint8)
	  offset 23:  pad       (uint8)
	  offset 24:  timestamp (uint64)
	  offset 32:  comm      ([16]byte)
*/
type rawNetEvent struct {
	PID       uint32
	UID       uint32
	SAddr     uint32
	DAddr     uint32
	SPort     uint16
	DPort     uint16
	EvtType   uint8
	OldState  uint8
	NewState  uint8
	Pad       uint8
	Timestamp uint64
	Comm      [16]byte
}

func parseEvent(raw []byte) (events.NetworkEvent, error) {
	if len(raw) < 48 {
		return events.NetworkEvent{}, fmt.Errorf("short read: %d bytes", len(raw))
	}

	re := rawNetEvent{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		UID:       binary.LittleEndian.Uint32(raw[4:8]),
		SAddr:     binary.LittleEndian.Uint32(raw[8:12]),
		DAddr:     binary.LittleEndian.Uint32(raw[12:16]),
		SPort:     binary.LittleEndian.Uint16(raw[16:18]),
		DPort:     binary.LittleEndian.Uint16(raw[18:20]),
		EvtType:   raw[20],
		OldState:  raw[21],
		NewState:  raw[22],
		Timestamp: binary.LittleEndian.Uint64(raw[24:32]),
	}
	copy(re.Comm[:], raw[32:48])

	return events.NetworkEvent{
		Event: events.Event{
			Kind:      events.KindNetwork,
			PID:       re.PID,
			UID:       re.UID,
			Timestamp: re.Timestamp,
			Comm:      re.Comm,
		},
		SrcAddr:  re.SAddr,
		DstAddr:  re.DAddr,
		SrcPort:  re.SPort,
		DstPort:  re.DPort,
		EvtType:  re.EvtType,
		OldState: re.OldState,
		NewState: re.NewState,
	}, nil
}

/*
	FormatIPv4 converts a uint32 in network byte order to a dotted-decimal
	string. The address is stored in network byte order (big-endian) as
	received from the kernel, so byte 0 is the most significant octet.
*/
func FormatIPv4(addr uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip.String()
}

/*
	Event type constants matching the BPF C definitions.
*/
const (
	EvtConnect     = 0
	EvtEstablished = 1
	EvtClose       = 2
	EvtFailed      = 3
	EvtListen      = 4
)

/*
	EvtTypeName returns a human-readable name for the event type.
*/
func EvtTypeName(t uint8) string {
	switch t {
	case EvtConnect:
		return "CONNECT"
	case EvtEstablished:
		return "ESTABLISHED"
	case EvtClose:
		return "CLOSE"
	case EvtFailed:
		return "FAILED"
	case EvtListen:
		return "LISTEN"
	default:
		return fmt.Sprintf("EVT_%d", t)
	}
}

/*
	TCP States. The key is identical to respective constants defined in
	the eBPF program.
*/
var tcpStateNames = map[uint8]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
}

/*
	Map helper function to convert the integer literal to appropriate TCP
	state name.
*/
func TCPStateName(state uint8) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("STATE_%d", state)
}
