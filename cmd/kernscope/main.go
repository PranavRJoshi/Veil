package main

import (
	"fmt"
	"os"

	"github.com/PranavRJoshi/go-kernscope/internal/events"
)

func main () {
	e := events.Event {
		Kind:		events.KindSyscall,
		Pid:		1234,
		Tid:		1234,
		Timestamp:	9999999,
	}
	copy(e.Comm[:], "bash");

	fmt.Printf("[%s] pid = %-6d comm = %s\n",
			e.Kind,
			e.Pid,
			e.ProcessName(),
		)

	_ = os.Stdout
}
