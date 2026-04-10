package events

import "testing"

func TestEventKindString (t *testing.T) {
    cases := []struct {
        kind     EventKind
        expected string
    }{
        {KindSyscall, "syscall"},
        {KindNetwork, "network"},
        {EventKind(99), "unknown (99)"},
	{KindMemory, "memory"},
    }

    for _, c := range cases {
        got := c.kind.String()
        if got != c.expected {
            t.Errorf("EventKind(%d).String() = %q, want %q", c.kind, got, c.expected)
        }
    }
}

func TestProcessName (t *testing.T) {
    e := Event{}
    copy(e.Comm[:], "bash")

    got := e.ProcessName()
    if got != "bash" {
        t.Errorf("ProcessName() = %q, want %q", got, "bash")
    }
}
