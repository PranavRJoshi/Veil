package syscall

import (
	"encoding/binary"
	"testing"
)

/*
	parseEvent decodes bytes handed over by the kernel through the ring
	buffer. It must never panic, whatever it is given: a truncated record,
	a short read, or a layout that does not match what this build expects.

	Run the full fuzzer with:
		go test -run FuzzParseEvent -fuzz FuzzParseEvent ./modules/syscall/

	Without -fuzz it replays the seed corpus only, so it is cheap enough
	to leave in the normal test run.
*/
func FuzzParseEvent(f *testing.F) {
	/* Exact boundary either side of the 48-byte minimum. */
	f.Add([]byte{})
	f.Add(make([]byte, 47))
	f.Add(make([]byte, 48))
	f.Add(make([]byte, 49))

	/* A realistic record: pid/tid/uid/gid, timestamp, nr, comm. */
	valid := make([]byte, 48)
	binary.LittleEndian.PutUint32(valid[0:4], 4242)
	binary.LittleEndian.PutUint32(valid[4:8], 4243)
	binary.LittleEndian.PutUint32(valid[8:12], 1000)
	binary.LittleEndian.PutUint32(valid[12:16], 1000)
	binary.LittleEndian.PutUint64(valid[16:24], 1234567890)
	binary.LittleEndian.PutUint64(valid[24:32], 56)
	copy(valid[32:48], "veil-test")
	f.Add(valid)

	/* comm with no null terminator: every one of the 16 bytes is data. */
	unterminated := make([]byte, 48)
	for i := 32; i < 48; i++ {
		unterminated[i] = 'a'
	}
	f.Add(unterminated)

	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := parseEvent(raw)

		if len(raw) < 48 {
			if err == nil {
				t.Fatalf("accepted a %d-byte record, want an error below 48", len(raw))
			}
			return
		}

		if err != nil {
			t.Fatalf("rejected a %d-byte record: %v", len(raw), err)
		}

		/*
			Decoding is little-endian at fixed offsets, so every field
			must equal what the buffer holds. This catches an offset or
			width change that a "does not panic" check would miss.
		*/
		if got, want := e.PID, binary.LittleEndian.Uint32(raw[0:4]); got != want {
			t.Errorf("PID = %d, want %d", got, want)
		}
		if got, want := e.TID, binary.LittleEndian.Uint32(raw[4:8]); got != want {
			t.Errorf("TID = %d, want %d", got, want)
		}
		if got, want := e.UID, binary.LittleEndian.Uint32(raw[8:12]); got != want {
			t.Errorf("UID = %d, want %d", got, want)
		}
		if got, want := e.GID, binary.LittleEndian.Uint32(raw[12:16]); got != want {
			t.Errorf("GID = %d, want %d", got, want)
		}
		if got, want := e.Timestamp, binary.LittleEndian.Uint64(raw[16:24]); got != want {
			t.Errorf("Timestamp = %d, want %d", got, want)
		}
		if got, want := e.SyscallNr, binary.LittleEndian.Uint64(raw[24:32]); got != want {
			t.Errorf("SyscallNr = %d, want %d", got, want)
		}

		/*
			ProcessName stops at the first null, or returns all 16 bytes
			when there is none. It must never exceed the field width.
		*/
		if name := e.ProcessName(); len(name) > 16 {
			t.Errorf("ProcessName returned %d bytes, want at most 16: %q", len(name), name)
		}

		/* SyscallName must be total: every number maps to some string. */
		if SyscallName(e.SyscallNr) == "" {
			t.Errorf("SyscallName(%d) returned an empty string", e.SyscallNr)
		}
	})
}
