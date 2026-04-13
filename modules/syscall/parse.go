package syscall

import (
	"encoding/binary"
	"fmt"

	"github.com/PranavRJoshi/go-kernscope/internal/events"
)

/*
	The information we care about when observing the sys_enter tracepoint...
	for now. Might have to add more fields later. This structure must match
	with the syscall_event structure we defined in the file in 'bpf' directory.
	Do note that the field orders must match as well, with same sizes, and
	accounting for padding as well...
*/
type syscallEvent struct {
	PID       uint32
	TID       uint32
	Timestamp uint64
	SyscallNr uint64
	Comm      [16]byte
}

func parseEvent(raw []byte) (events.Event, error) {
	if len(raw) < 40 {
		return events.Event{}, fmt.Errorf("short read: %d bytes", len(raw))
	}

	// LittleEndian because x86_64 — we'll make this configurable later
	se := syscallEvent{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		TID:       binary.LittleEndian.Uint32(raw[4:8]),
		Timestamp: binary.LittleEndian.Uint64(raw[8:16]),
		SyscallNr: binary.LittleEndian.Uint64(raw[16:24]),
	}
	copy(se.Comm[:], raw[24:40])

	return events.Event{
		Kind:      events.KindSyscall,
		PID:       se.PID,
		TID:       se.TID,
		Timestamp: se.Timestamp,
		Comm:      se.Comm,
		SyscallNr: se.SyscallNr,
	}, nil
}
