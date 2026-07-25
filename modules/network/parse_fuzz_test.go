package network

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

/*
	The network record is 48 bytes. Note the explicit hole: evt_type,
	oldstate and newstate occupy 20 through 22, followed by one pad byte so
	the timestamp lands 8-byte aligned at 24.

	Run the full fuzzer with:
		go test -run FuzzParseEvent -fuzz FuzzParseEvent ./modules/network/
*/

const netRecordSize = 48

func FuzzParseEvent(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, netRecordSize-1))
	f.Add(make([]byte, netRecordSize))
	f.Add(make([]byte, netRecordSize+1))

	/* A realistic outbound connection: 127.0.0.1:54321 -> 127.0.0.1:8080. */
	valid := make([]byte, netRecordSize)
	binary.LittleEndian.PutUint32(valid[0:4], 4242)
	binary.LittleEndian.PutUint32(valid[4:8], 1000)
	copy(valid[8:12], []byte{127, 0, 0, 1})  /* saddr, network order */
	copy(valid[12:16], []byte{127, 0, 0, 1}) /* daddr */
	binary.LittleEndian.PutUint16(valid[16:18], 54321)
	binary.LittleEndian.PutUint16(valid[18:20], 8080)
	valid[20] = EvtConnect
	valid[21] = 7 /* CLOSE */
	valid[22] = 2 /* SYN_SENT */
	binary.LittleEndian.PutUint64(valid[24:32], 987654321)
	copy(valid[32:48], "veil-test")
	f.Add(valid)

	/* Unknown event type and TCP states, exercising both fallbacks. */
	unknown := make([]byte, netRecordSize)
	unknown[20] = 200
	unknown[21] = 99
	unknown[22] = 250
	f.Add(unknown)

	/* comm filling all 16 bytes with no terminator. */
	fullComm := make([]byte, netRecordSize)
	for i := 32; i < 48; i++ {
		fullComm[i] = 'n'
	}
	f.Add(fullComm)

	/* The pad byte set: it must not leak into any decoded field. */
	padded := make([]byte, netRecordSize)
	padded[23] = 0xff
	f.Add(padded)

	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := parseEvent(raw)

		if len(raw) < netRecordSize {
			if err == nil {
				t.Fatalf("accepted a %d-byte record, want an error below %d",
					len(raw), netRecordSize)
			}
			return
		}

		if err != nil {
			t.Fatalf("rejected a %d-byte record: %v", len(raw), err)
		}

		if got, want := e.PID, binary.LittleEndian.Uint32(raw[0:4]); got != want {
			t.Errorf("PID = %d, want %d", got, want)
		}
		if got, want := e.UID, binary.LittleEndian.Uint32(raw[4:8]); got != want {
			t.Errorf("UID = %d, want %d", got, want)
		}
		if got, want := e.SrcPort, binary.LittleEndian.Uint16(raw[16:18]); got != want {
			t.Errorf("SrcPort = %d, want %d", got, want)
		}
		if got, want := e.DstPort, binary.LittleEndian.Uint16(raw[18:20]); got != want {
			t.Errorf("DstPort = %d, want %d", got, want)
		}
		if got, want := e.EvtType, raw[20]; got != want {
			t.Errorf("EvtType = %d, want %d", got, want)
		}
		if got, want := e.OldState, raw[21]; got != want {
			t.Errorf("OldState = %d, want %d", got, want)
		}
		if got, want := e.NewState, raw[22]; got != want {
			t.Errorf("NewState = %d, want %d", got, want)
		}
		if got, want := e.Timestamp, binary.LittleEndian.Uint64(raw[24:32]); got != want {
			t.Errorf("Timestamp = %d, want %d", got, want)
		}

		if name := e.ProcessName(); len(name) > 16 {
			t.Errorf("ProcessName returned %d bytes, want at most 16: %q", len(name), name)
		} else if strings.IndexByte(name, 0) >= 0 {
			t.Errorf("ProcessName contains a null byte: %q", name)
		}

		/* The naming helpers are total: every value maps to some label. */
		if EvtTypeName(e.EvtType) == "" {
			t.Errorf("EvtTypeName(%d) returned an empty string", e.EvtType)
		}
		for _, s := range []uint8{e.OldState, e.NewState} {
			if TCPStateName(s) == "" {
				t.Errorf("TCPStateName(%d) returned an empty string", s)
			}
		}

		/*
			Any 32-bit value is a valid IPv4 address, so formatting must
			always produce something net.ParseIP accepts. A malformed
			result would surface as an unparseable dotted quad.
		*/
		for _, addr := range []uint32{e.SrcAddr, e.DstAddr} {
			s := FormatIPv4(addr)
			if net.ParseIP(s) == nil {
				t.Errorf("FormatIPv4(%d) = %q, which does not parse as an IP", addr, s)
			}
		}
	})
}
