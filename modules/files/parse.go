package files

import (
	"encoding/binary"
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	The following structure must match the one defined in file_access.bpf.c
*/
type fileEvent struct {
	PID       uint32
	TID       uint32
	Timestamp uint64
	Comm      [16]byte
	Path      [256]byte
	Op        uint8
}

/*
	Check the operation code.
*/
func opName(op uint8) string {
	switch op {
	case 0:
		return "open"
	case 1:
		return "read"
	case 2:
		return "write"
	default:
		return fmt.Sprintf("op_%d", op)
	}
}

/*
	Parse the path.
*/
func parsePath(raw [256]byte) string {
	for i, b := range raw {
		if b == 0 {
			return string(raw[:i])
		}
	}
	return string(raw[:])
}

/*
	Parse the file event information that was received.
*/
func parseEvent(raw []byte) (events.FileEvent, error) {
	if len(raw) < 281 {
		return events.FileEvent{}, fmt.Errorf("short read: %d bytes", len(raw))
	}

	fe := fileEvent{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		TID:       binary.LittleEndian.Uint32(raw[4:8]),
		Timestamp: binary.LittleEndian.Uint64(raw[8:16]),
		Op:        raw[280],
	}
	copy(fe.Comm[:], raw[16:32])
	copy(fe.Path[:], raw[32:288])

	return events.FileEvent{
		Event: events.Event{
			Kind:      events.KindFileAccess,
			PID:       fe.PID,
			TID:       fe.TID,
			Timestamp: fe.Timestamp,
			Comm:      fe.Comm,
		},
		Path: parsePath(fe.Path),
		Op:   opName(fe.Op),
	}, nil
}
