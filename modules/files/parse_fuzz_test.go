package files

import (
	"encoding/binary"
	"strings"
	"testing"
)

/*
	The file event is the most involved decoder in Veil: an 812-byte record
	carrying a 12-slot array of 64-byte path components that assembleFilePath
	scans, reverses, and joins.

	Run the full fuzzer with:
		go test -run FuzzParseEvent -fuzz FuzzParseEvent ./modules/files/

	A note on choosing invariants. The fuzzer produces records the kernel
	never would -- a component holding a '/' byte, for instance, which a
	dentry name cannot contain. Assertions must therefore hold for every
	possible input, not merely realistic ones. Length bounds and "the path
	always begins with '/'" qualify; counting separators to infer the
	component count does not, and would fail on input that cannot occur.
*/

const (
	fileRecordSize = 812
	componentLen   = 64
	maxComponents  = 12
)

/*
	putComponent writes a null-terminated component into slot i.
*/
func putComponent(raw []byte, i int, name string) {
	off := 44 + i*componentLen
	copy(raw[off:off+componentLen], name)
}

func FuzzParseEvent(f *testing.F) {
	/* Boundaries either side of the minimum record size. */
	f.Add([]byte{})
	f.Add(make([]byte, fileRecordSize-1))
	f.Add(make([]byte, fileRecordSize))
	f.Add(make([]byte, fileRecordSize+1))

	/* A realistic record: /etc/hosts opened by a named process. */
	valid := make([]byte, fileRecordSize)
	binary.LittleEndian.PutUint32(valid[0:4], 4242)
	binary.LittleEndian.PutUint32(valid[4:8], 4243)
	binary.LittleEndian.PutUint32(valid[8:12], 1000)
	binary.LittleEndian.PutUint32(valid[12:16], 1000)
	binary.LittleEndian.PutUint64(valid[16:24], 987654321)
	copy(valid[24:40], "veil-test")
	valid[40] = 0 /* op = open */
	putComponent(valid, 0, "hosts")
	putComponent(valid, 1, "etc")
	f.Add(valid)

	/* Every slot filled, none null-terminated: the widest possible path. */
	saturated := make([]byte, fileRecordSize)
	for i := 0; i < maxComponents; i++ {
		off := 44 + i*componentLen
		for j := 0; j < componentLen; j++ {
			saturated[off+j] = 'a'
		}
	}
	f.Add(saturated)

	/* A gap in the middle: slot 1 empty must terminate the walk. */
	gapped := make([]byte, fileRecordSize)
	putComponent(gapped, 0, "leaf")
	putComponent(gapped, 2, "unreachable")
	f.Add(gapped)

	/* Unknown op code, exercising the op_%d fallback. */
	oddOp := make([]byte, fileRecordSize)
	oddOp[40] = 200
	putComponent(oddOp, 0, "file")
	f.Add(oddOp)

	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := parseEvent(raw)

		if len(raw) < fileRecordSize {
			if err == nil {
				t.Fatalf("accepted a %d-byte record, want an error below %d",
					len(raw), fileRecordSize)
			}
			return
		}

		if err != nil {
			t.Fatalf("rejected a %d-byte record: %v", len(raw), err)
		}

		/* Fixed-offset fields must equal what the buffer holds. */
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

		if name := e.ProcessName(); len(name) > 16 {
			t.Errorf("ProcessName returned %d bytes, want at most 16: %q", len(name), name)
		}

		/* opName is total: every byte value maps to some label. */
		if e.Op == "" {
			t.Errorf("Op is empty for op byte %d", raw[40])
		}

		/*
			assembleFilePath returns "/" when no components are present,
			and "/" + join(parts, "/") otherwise. Either way it is
			absolute and never empty.
		*/
		if !strings.HasPrefix(e.FileName, "/") {
			t.Errorf("FileName is not absolute: %q", e.FileName)
		}

		/*
			At most maxComponents parts, each at most componentLen bytes
			when unterminated, plus one separator apiece. This is the
			bound that holds regardless of what the fuzzer put in the
			component slots.
		*/
		if max := maxComponents*componentLen + maxComponents; len(e.FileName) > max {
			t.Errorf("FileName is %d bytes, want at most %d: %q",
				len(e.FileName), max, e.FileName)
		}

		/* A null byte in the path means a component scan overran. */
		if strings.IndexByte(e.FileName, 0) >= 0 {
			t.Errorf("FileName contains a null byte: %q", e.FileName)
		}
	})
}
