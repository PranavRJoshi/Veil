package count

import (
	"io"
	"testing"
)

/*
	BenchmarkCountEmit measures the aggregation hot path: extract the key
	field and increment its counter. Emitting the same event repeatedly
	exercises the common case of an already-seen key.
*/
func BenchmarkCountEmit(b *testing.B) {
	cs := NewCountSink(io.Discard, 10)
	f := map[string]interface{}{
		"syscall": "openat", "comm": "bash", "pid": uint32(1),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.Emit("syscall", f)
	}
}
