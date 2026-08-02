package uprobe

import (
	"encoding/binary"
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/events"
)

type uprobeEvent struct {
	PID        uint32
	TID        uint32
	UID        uint32
	Pad        uint32
	Timestamp  uint64
	DurationNs uint64
	Comm       [16]byte
}

const uprobeEventSize = 48

func parseEvent(raw []byte) (events.UprobeEvent, error) {
	if len(raw) < uprobeEventSize {
		return events.UprobeEvent{}, fmt.Errorf("short read: %d bytes (want %d)", len(raw), uprobeEventSize)
	}

	ue := uprobeEvent{
		PID:        binary.LittleEndian.Uint32(raw[0:4]),
		TID:        binary.LittleEndian.Uint32(raw[4:8]),
		UID:        binary.LittleEndian.Uint32(raw[8:12]),
		Timestamp:  binary.LittleEndian.Uint64(raw[16:24]),
		DurationNs: binary.LittleEndian.Uint64(raw[24:32]),
	}
	copy(ue.Comm[:], raw[32:48])

	e := events.UprobeEvent{
		Event: events.Event{
			Kind:      events.KindUprobe,
			PID:       ue.PID,
			TID:       ue.TID,
			UID:       ue.UID,
			Comm:      ue.Comm,
			Timestamp: ue.Timestamp,
		},
		DurationNs: ue.DurationNs,
	}
	return e, nil
}
