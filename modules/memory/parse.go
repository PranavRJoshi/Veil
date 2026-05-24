package memory

import (
	"encoding/binary"
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	memEvent is the intermediate struct matching the BPF C layout.
	Used for binary deserialization before converting to events.MemoryEvent.
*/
type memEvent struct {
	PID       uint32
	TID       uint32
	UID       uint32
	EvtType   uint8
	Timestamp uint64
	Address   uint64
	Comm      [16]byte
}

const memEventSize = 48

func parseEvent(raw []byte) (events.MemoryEvent, error) {
	if len(raw) < memEventSize {
		return events.MemoryEvent{}, fmt.Errorf("short read: %d bytes (want %d)", len(raw), memEventSize)
	}

	me := memEvent{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		TID:       binary.LittleEndian.Uint32(raw[4:8]),
		UID:       binary.LittleEndian.Uint32(raw[8:12]),
		EvtType:   raw[12],
		Timestamp: binary.LittleEndian.Uint64(raw[16:24]),
		Address:   binary.LittleEndian.Uint64(raw[24:32]),
	}
	copy(me.Comm[:], raw[32:48])

	return events.MemoryEvent{
		Event: events.Event{
			Kind:      events.KindMemory,
			PID:       me.PID,
			TID:       me.TID,
			UID:       me.UID,
			Timestamp: me.Timestamp,
			Comm:      me.Comm,
		},
		EvtType: me.EvtType,
		Address: me.Address,
	}, nil
}

/*
	faultTypeName maps the numeric fault type to a human-readable string.
*/
func faultTypeName(t uint8) string {
	switch t {
		case 0:
			return "major"
		case 1:
			return "minor"
		default:
			return fmt.Sprintf("unknown(%d)", t)
	}
}
