package events

import "testing"

func TestEventKindString(t *testing.T) {
	cases := []struct {
		kind     EventKind
		expected string
	}{
		{KindSyscall, "syscall"},
		{KindNetwork, "network"},
		{KindFileAccess, "file access"},
		{KindScheduler, "scheduler"},
		{KindMemory, "memory"},
		{EventKind(99), "unknown (99)"},
	}
 
	for _, c := range cases {
		got := c.kind.String()
		if got != c.expected {
			t.Errorf("EventKind(%d).String() = %q, want %q", c.kind, got, c.expected)
		}
	}
}

func TestProcessName_Short(t *testing.T) {
	e := Event{}
	copy(e.Comm[:], "bash")
 
	got := e.ProcessName()
	if got != "bash" {
		t.Errorf("ProcessName() = %q, want %q", got, "bash")
	}
}

/*
	The kernel writes 15 chars + 1 null terminator into the 16-byte
	comm field. Verify that the null terminator is stripped correctly.
*/
func TestProcessName_15CharsWithNull(t *testing.T) {
	e := Event{}
	name := "systemd-resolve" /* exactly 15 characters */
	copy(e.Comm[:], name)
	e.Comm[15] = 0 /* explicit null terminator */
 
	got := e.ProcessName()
	if got != "systemd-resolve" {
		t.Errorf("ProcessName() = %q, want %q", got, "systemd-resolve")
	}
}

/*
	When the process name is exactly 16 bytes, there is no null
	terminator. ProcessName should return all 16 bytes.
*/
func TestProcessName_Full16Bytes(t *testing.T) {
	e := Event{}
	copy(e.Comm[:], "0123456789abcdef")
 
	got := e.ProcessName()
	if got != "0123456789abcdef" {
		t.Errorf("ProcessName() = %q, want 16-char string", got)
	}
	if len(got) != 16 {
		t.Errorf("len = %d, want 16", len(got))
	}
}

/*
	An entirely zeroed comm field (no process name) should return
	an empty string.
*/
func TestProcessName_AllZero(t *testing.T) {
	e := Event{}
	got := e.ProcessName()
	if got != "" {
		t.Errorf("ProcessName() = %q, want empty string", got)
	}
}

/*
	Test a comm field with an embedded null byte. The kernel shouldn't
	produce this, but ProcessName should stop at the first null.
*/
func TestProcessName_EmbeddedNull(t *testing.T) {
	e := Event{}
	copy(e.Comm[:], "ab\x00cd")
 
	got := e.ProcessName()
	if got != "ab" {
		t.Errorf("ProcessName() = %q, want %q (stop at first null)", got, "ab")
	}
}

/*
	Test a single-character process name.
*/
func TestProcessName_SingleChar(t *testing.T) {
	e := Event{}
	e.Comm[0] = 'x'
 
	got := e.ProcessName()
	if got != "x" {
		t.Errorf("ProcessName() = %q, want %q", got, "x")
	}
}
