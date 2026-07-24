package scheduler

import (
	"encoding/binary"
	"strings"
	"testing"
)

/*
	The scheduler record is 80 bytes carrying two 16-byte comm fields.

	Run the full fuzzer with:
		go test -run FuzzParseEvent -fuzz FuzzParseEvent ./modules/scheduler/
*/

const schedRecordSize = 80

func putComm(raw []byte, off int, name string) {
	copy(raw[off:off+16], name)
}

func FuzzParseEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, schedRecordSize-1))
	f.Add(make([]byte, schedRecordSize))
	f.Add(make([]byte, schedRecordSize+1))

	/* A realistic switch: bash yielding to a kworker on cpu 2. */
	valid := make([]byte, schedRecordSize)
	binary.LittleEndian.PutUint32(valid[0:4], 1234)   /* prev_pid */
	binary.LittleEndian.PutUint32(valid[4:8], 5678)   /* next_pid */
	binary.LittleEndian.PutUint32(valid[8:12], 1234)  /* prev_tid */
	binary.LittleEndian.PutUint32(valid[12:16], 0)    /* next_tid, always 0 */
	binary.LittleEndian.PutUint32(valid[16:20], 1000) /* uid */
	binary.LittleEndian.PutUint32(valid[20:24], 2)    /* cpu */
	binary.LittleEndian.PutUint64(valid[24:32], 1)    /* prev_state: SLEEPING */
	binary.LittleEndian.PutUint64(valid[32:40], 999)  /* timestamp */
	binary.LittleEndian.PutUint32(valid[40:44], 120)  /* prev_prio */
	binary.LittleEndian.PutUint32(valid[44:48], 120)  /* next_prio */
	putComm(valid, 48, "bash")
	putComm(valid, 64, "kworker/2:1")
	f.Add(valid)

	/* Both comms unterminated: every one of the 16 bytes is data. */
	fullComms := make([]byte, schedRecordSize)
	for i := 48; i < 80; i++ {
		fullComms[i] = 'x'
	}
	f.Add(fullComms)

	/* An unmapped prev_state, exercising the hex fallback. */
	oddState := make([]byte, schedRecordSize)
	binary.LittleEndian.PutUint64(oddState[24:32], 0x555)
	f.Add(oddState)

	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := parseEvent(raw)

		if len(raw) < schedRecordSize {
			if err == nil {
				t.Fatalf("accepted a %d-byte record, want an error below %d",
					len(raw), schedRecordSize)
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
			{"PrevPID", e.PrevPID, binary.LittleEndian.Uint32(raw[0:4])},
			{"NextPID", e.NextPID, binary.LittleEndian.Uint32(raw[4:8])},
			{"PrevTID", e.PrevTID, binary.LittleEndian.Uint32(raw[8:12])},
			{"NextTID", e.NextTID, binary.LittleEndian.Uint32(raw[12:16])},
			{"UID", e.UID, binary.LittleEndian.Uint32(raw[16:20])},
			{"CPU", e.CPU, binary.LittleEndian.Uint32(raw[20:24])},
			{"PrevPrio", e.PrevPrio, binary.LittleEndian.Uint32(raw[40:44])},
			{"NextPrio", e.NextPrio, binary.LittleEndian.Uint32(raw[44:48])},
		} {
			if tc.got != tc.want {
				t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
			}
		}

		if got, want := e.PrevState, binary.LittleEndian.Uint64(raw[24:32]); got != want {
			t.Errorf("PrevState = %d, want %d", got, want)
		}
		if got, want := e.Timestamp, binary.LittleEndian.Uint64(raw[32:40]); got != want {
			t.Errorf("Timestamp = %d, want %d", got, want)
		}

		/*
			The base Event carries the prev side, which is what the
			generic pid/comm aliases in toFields depend on.
		*/
		if e.PID != e.PrevPID {
			t.Errorf("Event.PID = %d, want PrevPID %d", e.PID, e.PrevPID)
		}

		for _, c := range []string{commString(e.PrevComm), commString(e.NextComm)} {
			if len(c) > 16 {
				t.Errorf("comm is %d bytes, want at most 16: %q", len(c), c)
			}
			if strings.IndexByte(c, 0) >= 0 {
				t.Errorf("comm contains a null byte: %q", c)
			}
		}

		/* prevStateName is total: every value maps to some label. */
		if prevStateName(e.PrevState) == "" {
			t.Errorf("prevStateName(%d) returned an empty string", e.PrevState)
		}
	})
}
