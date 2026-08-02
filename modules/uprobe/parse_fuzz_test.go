package uprobe

import (
	"encoding/binary"
	"strings"
	"testing"
)

/*
	The uprobe record is 48 bytes carrying one 16-byte comm field.

	Run the full fuzzer with:
		go test -run FuzzParseEvent -fuzz FuzzParseEvent ./modules/uprobe/
*/

const uprobeRecordSize = 48

func FuzzParseEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, uprobeRecordSize-1))
	f.Add(make([]byte, uprobeRecordSize))
	f.Add(make([]byte, uprobeRecordSize+1))

	valid := make([]byte, uprobeRecordSize)
	binary.LittleEndian.PutUint32(valid[0:4], 1234)  /* pid */
	binary.LittleEndian.PutUint32(valid[4:8], 5678)  /* tid */
	binary.LittleEndian.PutUint32(valid[8:12], 1000) /* uid */
	binary.LittleEndian.PutUint64(valid[16:24], 999) /* timestamp */
	binary.LittleEndian.PutUint64(valid[24:32], 42)  /* duration_ns */
	copy(valid[32:48], "bash")
	f.Add(valid)

	/* Unterminated comm: every one of the 16 bytes is data. */
	fullComm := make([]byte, uprobeRecordSize)
	for i := 32; i < 48; i++ {
		fullComm[i] = 'x'
	}
	f.Add(fullComm)

	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := parseEvent(raw)

		if len(raw) < uprobeRecordSize {
			if err == nil {
				t.Fatalf("accepted a %d-byte record, want an error below %d",
					len(raw), uprobeRecordSize)
			}
			return
		}

		if err != nil {
			t.Fatalf("rejected a %d-byte record: %v", len(raw), err)
		}

		for _, tc := range []struct {
			name string
			got  uint32
			want uint32
		}{
			{"PID", e.PID, binary.LittleEndian.Uint32(raw[0:4])},
			{"TID", e.TID, binary.LittleEndian.Uint32(raw[4:8])},
			{"UID", e.UID, binary.LittleEndian.Uint32(raw[8:12])},
		} {
			if tc.got != tc.want {
				t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
			}
		}

		if got, want := e.Timestamp, binary.LittleEndian.Uint64(raw[16:24]); got != want {
			t.Errorf("Timestamp = %d, want %d", got, want)
		}
		if got, want := e.DurationNs, binary.LittleEndian.Uint64(raw[24:32]); got != want {
			t.Errorf("DurationNs = %d, want %d", got, want)
		}

		comm := e.ProcessName()
		if len(comm) > 16 {
			t.Errorf("comm is %d bytes, want at most 16: %q", len(comm), comm)
		}
		if strings.IndexByte(comm, 0) >= 0 {
			t.Errorf("comm contains a null byte: %q", comm)
		}
	})
}
