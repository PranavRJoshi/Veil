package syscall

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
	"github.com/PranavRJoshi/Veil/internal/output"
)

/*
	benchRecord returns a realistic 48-byte syscall record for the decode
	and transform benchmarks.
*/
func benchRecord() []byte {
	raw := make([]byte, 48)
	binary.LittleEndian.PutUint32(raw[0:4], 4242)
	binary.LittleEndian.PutUint32(raw[4:8], 4243)
	binary.LittleEndian.PutUint32(raw[8:12], 1000)
	binary.LittleEndian.PutUint32(raw[12:16], 1000)
	binary.LittleEndian.PutUint64(raw[16:24], 1234567890)
	binary.LittleEndian.PutUint64(raw[24:32], 56)
	copy(raw[32:48], "bash")
	return raw
}

/*
	Package-level sinks keep the compiler from eliminating the work each
	benchmark measures.
*/
var (
	benchEvent  events.SyscallEvent
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
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchFields = syscallToFields(e)
	}
}

func BenchmarkTextFormat(b *testing.B) {
	e, err := parseEvent(benchRecord())
	if err != nil {
		b.Fatal(err)
	}
	f := syscallToFields(e)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchLine = textFormat("syscall", f)
	}
}

/*
	BenchmarkPipeline measures the full per-event userspace path: decode,
	transform to fields, and format. This is the cost that scales directly
	with event volume.
*/
func BenchmarkPipeline(b *testing.B) {
	raw := benchRecord()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e, err := parseEvent(raw)
		if err != nil {
			b.Fatal(err)
		}
		benchLine = textFormat("syscall", syscallToFields(e))
	}
}

/*
	BenchmarkTextEmit measures the real text-output cost per event: the
	module's own formatter wired into a text sink. Unlike the sink-overhead
	benchmark in internal/output (which uses a stub formatter), this is
	directly comparable to BenchmarkJSONSinkEmit.
*/
func BenchmarkTextEmit(b *testing.B) {
	e, err := parseEvent(benchRecord())
	if err != nil {
		b.Fatal(err)
	}
	f := syscallToFields(e)
	sink := output.NewTextSink(io.Discard, output.DispatchTextFormat(
		map[string]output.TextFormatFunc{"syscall": textFormat},
	))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sink.Emit("syscall", f); err != nil {
			b.Fatal(err)
		}
	}
}
