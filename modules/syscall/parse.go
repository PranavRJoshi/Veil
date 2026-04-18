package syscall

import (
	"encoding/binary"
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/events"
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
	UID       uint32
	GID       uint32
	Timestamp uint64
	SyscallNr uint64
	Comm      [16]byte
}

func parseEvent(raw []byte) (events.SyscallEvent, error) {
	if len(raw) < 48 {
		return events.SyscallEvent{}, fmt.Errorf("short read: %d bytes", len(raw))
	}

	// LittleEndian because x86_64 — we'll make this configurable later
	se := syscallEvent{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		TID:       binary.LittleEndian.Uint32(raw[4:8]),
		UID:       binary.LittleEndian.Uint32(raw[8:12]),
		GID:       binary.LittleEndian.Uint32(raw[12:16]),
		Timestamp: binary.LittleEndian.Uint64(raw[16:24]),
		SyscallNr: binary.LittleEndian.Uint64(raw[24:32]),
	}
	copy(se.Comm[:], raw[32:48])

	return events.SyscallEvent{
		Event: events.Event {
			Kind:      events.KindSyscall,
			PID:       se.PID,
			TID:       se.TID,
			UID:       se.UID,
			GID:       se.GID,
			Timestamp: se.Timestamp,
			Comm:      se.Comm,
		}, 
		SyscallNr: se.SyscallNr,
	}, nil
}
