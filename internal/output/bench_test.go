package output

import (
	"io"
	"testing"
)

func benchEventFields() map[string]interface{} {
	return map[string]interface{}{
		"kind": "syscall", "pid": uint32(4242), "tid": uint32(4243),
		"uid": uint32(1000), "gid": uint32(1000), "timestamp": uint64(1234567890),
		"syscall_nr": uint64(56), "syscall": "openat", "comm": "bash",
	}
}

/*
	constFormat is a trivial formatter so the sink benchmark measures the
	sink's own overhead rather than the cost of formatting.
*/
func constFormat(module string, f map[string]interface{}) string { return "line" }

/*
	BenchmarkTextSinkEmit isolates the text sink's overhead: the lock and
	the write. It uses a stub formatter, so it excludes formatting cost and
	is not the real text-emit figure; see BenchmarkTextEmit in the syscall
	module for the full path.
*/
func BenchmarkTextSinkEmit(b *testing.B) {
	sink := NewTextSink(io.Discard, constFormat)
	f := benchEventFields()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink.Emit("syscall", f)
	}
}

/*
	BenchmarkJSONSinkEmit measures the JSON path, which marshals the field
	map on every event.
*/
func BenchmarkJSONSinkEmit(b *testing.B) {
	sink := NewJSONSink(io.Discard)
	f := benchEventFields()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink.Emit("syscall", f)
	}
}
