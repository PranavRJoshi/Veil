package files

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/PranavRJoshi/Veil/internal/events"
)

/*
	The following structure must match the one defined in file_access.bpf.c.

	Binary layout (little-endian, no implicit padding beyond the explicit _pad):
	  [0:4]   pid
	  [4:8]   tid
	  [8:12]  uid
	  [12:16] gid
	  [16:24] timestamp
	  [24:40] comm
	  [40]    op
	  [41:44] _pad (3 bytes, explicit alignment before components)
	  [44:812] components[12][64]  (12 * 64 = 768 bytes)

	Total minimum size: 812 bytes.
*/
type fileEvent struct {
	PID        uint32
	TID        uint32
	UID        uint32
	GID        uint32
	Timestamp  uint64
	Comm       [16]byte
	Op         uint8
	Components [12][64]byte
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
	assembleFilePath reconstructs the absolute path from the component array.

	The BPF program stores components leaf-first: components[0] is the
	filename, components[1] is its parent directory, and so on. Each slot is
	null-terminated; a slot whose first byte is zero marks the end of the
	valid component list (ring buffer memory is zero-initialized).

	The components are reversed and joined with '/' to produce the absolute
	path. A single '/' is returned for the degenerate case (no components).
*/
func assembleFilePath(components [12][64]byte) string {
	parts := make([]string, 0, 12)
	for _, comp := range components {
		if comp[0] == 0 {
			break
		}
		end := 0
		for end < len(comp) && comp[end] != 0 {
			end++
		}
		parts = append(parts, string(comp[:end]))
	}
	if len(parts) == 0 {
		return "/"
	}
	/* Reverse: parts[0]=leaf, parts[n-1]=root-adjacent component. */
	for j, k := 0, len(parts)-1; j < k; j, k = j+1, k-1 {
		parts[j], parts[k] = parts[k], parts[j]
	}
	return "/" + strings.Join(parts, "/")
}

/*
	Parse the file event information that was received.
*/
func parseEvent(raw []byte) (events.FileEvent, error) {
	if len(raw) < 812 {
		return events.FileEvent{}, fmt.Errorf("short read: %d bytes", len(raw))
	}

	fe := fileEvent{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		TID:       binary.LittleEndian.Uint32(raw[4:8]),
		UID:       binary.LittleEndian.Uint32(raw[8:12]),
		GID:       binary.LittleEndian.Uint32(raw[12:16]),
		Timestamp: binary.LittleEndian.Uint64(raw[16:24]),
		Op:        raw[40],
	}
	copy(fe.Comm[:], raw[24:40])
	/* raw[41:44] is explicit padding -- skip */
	for i := 0; i < 12; i++ {
		copy(fe.Components[i][:], raw[44+i*64:44+(i+1)*64])
	}

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
		FileName: assembleFilePath(fe.Components),
		Op:       opName(fe.Op),
	}, nil
}
