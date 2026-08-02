package uprobe

import (
	"encoding/binary"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

func benchRecord() []byte {
	raw := make([]byte, uprobeEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], 4242)
	binary.LittleEndian.PutUint32(raw[4:8], 4243)
	binary.LittleEndian.PutUint32(raw[8:12], 1000)
	binary.LittleEndian.PutUint64(raw[16:24], 1234567890)
	binary.LittleEndian.PutUint64(raw[24:32], 4200)
	copy(raw[32:48], "bash")
	return raw
}

var (
	benchEvent  events.UprobeEvent
	benchFields map[string]interface{}
	benchLine   string
)

func BenchmarkParseEvent(b *testing.B) {
	raw := benchRecord()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchEvent, _ = parseEvent(raw)
	}
}

func BenchmarkToFields(b *testing.B) {
	e, err := parseEvent(benchRecord())
	if err != nil {
		b.Fatal(err)
	}
	mod := New(FilterConfig{Target: Target{Path: "/usr/bin/bash", Symbol: "readline"}}, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchFields = mod.toFields(e)
	}
}

func BenchmarkTextFormat(b *testing.B) {
	e, err := parseEvent(benchRecord())
	if err != nil {
		b.Fatal(err)
	}
	mod := New(FilterConfig{Target: Target{Path: "/usr/bin/bash", Symbol: "readline"}}, nil)
	f := mod.toFields(e)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchLine = textFormat("uprobe", f)
	}
}
