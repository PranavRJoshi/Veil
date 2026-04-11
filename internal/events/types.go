package events

import "fmt"

/*
	EventKind type identifies which kernel subsystem the event came from.
*/
type EventKind uint8

/*
	Supported kernel subsystems for EventKind.
*/
const (
	KindSyscall EventKind = iota
	KindNetwork
	KindFileAccess
	KindScheduler
	KindMemory
)

/*
	String() method for EventKind used to return the stringified version of the enumeration defined above.
*/
func (k EventKind) String () string {
	switch k {
		case KindSyscall:
			return "syscall"
		case KindNetwork:
			return "network"
		case KindFileAccess:
			return "file access"
		case KindScheduler:
			return "scheduler"
		case KindMemory:
			return "memory"
		default:
			return fmt.Sprintf("unknown (%d)", k)
	}
}

/*
	The common "envelope" for everything coming out of the kernel.
*/
type Event struct {
	Kind			EventKind
	PID				uint32
	TID				uint32
	Comm			[16]byte		// kernel gives us 15 chars and 1 null terminator
	Timestamp		uint64
}

/*
	ProcessName() method of Event structure.
	A null terminator check is done, and the slice is returned,
	else all 16 bytes of Comm field is returned.
*/
func (e Event) ProcessName () string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}
