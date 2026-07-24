package memory

import (
	"encoding/binary"
	"strings"
	"testing"
)

/*
	The memory record is 48 bytes. Note the explicit hole: evt_type is a
	single byte at offset 12, followed by three bytes of padding so the
	timestamp lands 8-byte aligned at 16.

	Run the full fuzzer with:
		go test -run FuzzParseEvent -fuzz FuzzParseEvent ./modules/memory/
*/

const memRecordSize = 48

func FuzzParseEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, memRecordSize-1))
	f.Add(make([]byte, memRecordSize))
	f.Add(make([]byte, memRecordSize+1))

	/* A realistic minor fault. */
	valid := make([]byte, memRecordSize)
	binary.LittleEndian.PutUint32(valid[0:4], 4242)
	binary.LittleEndian.PutUint32(valid[4:8], 4243)
	binary.LittleEndian.PutUint32(valid[8:12], 1000)
	valid[12] = 1 /* minor */
	binary.LittleEndian.PutUint64(valid[16:24], 123456789)
	binary.LittleEndian.PutUint64(valid[24:32], 0x7f0102030000)
	copy(valid[32:48], "veil-test")
	f.Add(valid)

	/* Major fault, and a comm filling all 16 bytes with no terminator. */
	major := make([]byte, memRecordSize)
	major[12] = 0
	for i := 32; i < 48; i++ {
		major[i] = 'm'
	}
	f.Add(major)

	/* An out-of-range fault type, exercising the unknown() fallback. */
	odd := make([]byte, memRecordSize)
	odd[12] = 200
	f.Add(odd)

	/* Padding bytes set: they must not leak into any decoded field. */
	padded := make([]byte, memRecordSize)
	padded[13], padded[14], padded[15] = 0xff, 0xff, 0xff
	f.Add(padded)

	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := parseEvent(raw)

		if len(raw) < memRecordSize {
			if err == nil {
				t.Fatalf("accepted a %d-byte record, want an error below %d",
					len(raw), memRecordSize)
			}
			return
		}

		if err != nil {
			t.Fatalf("rejected a %d-byte record: %v", len(raw), err)
		}

		if got, want := e.PID, binary.LittleEndian.Uint32(raw[0:4]); got != want {
			t.Errorf("PID = %d, want %d", got, want)
		}
		if got, want := e.TID, binary.LittleEndian.Uint32(raw[4:8]); got != want {
			t.Errorf("TID = %d, want %d", got, want)
		}
		if got, want := e.UID, binary.LittleEndian.Uint32(raw[8:12]); got != want {
			t.Errorf("UID = %d, want %d", got, want)
		}
		if got, want := e.EvtType, raw[12]; got != want {
			t.Errorf("EvtType = %d, want %d", got, want)
		}
		if got, want := e.Timestamp, binary.LittleEndian.Uint64(raw[16:24]); got != want {
			t.Errorf("Timestamp = %d, want %d", got, want)
		}
		if got, want := e.Address, binary.LittleEndian.Uint64(raw[24:32]); got != want {
			t.Errorf("Address = %d, want %d", got, want)
		}

		if name := e.ProcessName(); len(name) > 16 {
			t.Errorf("ProcessName returned %d bytes, want at most 16: %q", len(name), name)
		} else if strings.IndexByte(name, 0) >= 0 {
			t.Errorf("ProcessName contains a null byte: %q", name)
		}

		/* faultTypeName is total: every byte value maps to some label. */
		if faultTypeName(e.EvtType) == "" {
			t.Errorf("faultTypeName(%d) returned an empty string", e.EvtType)
		}
	})
}
