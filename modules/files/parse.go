package files

import (
	"encoding/binary"
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	The following structure must match the one defined in file_access.bpf.c,
	i.e., the file-based event sent by the bpf program.
*/
type fileEvent struct {
	PID         uint32
	TID         uint32
	UID         uint32
	GID         uint32
	Timestamp   uint64
	Comm        [16]byte
	FileName    [256]byte
	Op          uint8
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
	Parse the filename. The size of filename field is large for most files so
	we need to slice the byte array. If it occupies all the bytes, then we
	simply return the entire byte array as a string.
*/
func parseFileName(raw [256]byte) string {
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
	/*
		The actual size may be higher due to padding between fields,
		but we don't take that into account.
	*/
	if len(raw) < 297 {
		return events.FileEvent{}, fmt.Errorf("short read: %d bytes", len(raw))
	}

	fe := fileEvent{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		TID:       binary.LittleEndian.Uint32(raw[4:8]),
		UID:       binary.LittleEndian.Uint32(raw[8:12]),
		GID:       binary.LittleEndian.Uint32(raw[12:16]),
		Timestamp: binary.LittleEndian.Uint64(raw[16:24]),
		Op:        raw[296],
	}
	copy(fe.Comm[:], raw[24:40])
	copy(fe.FileName[:], raw[40:296])

	return events.FileEvent{
		Event: events.Event{
			Kind:      events.KindFileAccess,
			PID:       fe.PID,
			TID:       fe.TID,
			UID:       fe.UID,
			GID:       fe.GID,
			Timestamp: fe.Timestamp,
			Comm:      fe.Comm,
		},
		FileName:      parseFileName(fe.FileName),
		Op:            opName(fe.Op),
	}, nil
}
