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
	UID				uint32
	GID				uint32
	Comm			[16]byte		// kernel gives us 15 chars and 1 null terminator
	Timestamp		uint64
}

/*
	SyscallEvent extends Event with the syscall number.
	Used for syscall module.
*/
type SyscallEvent struct {
	Event
	SyscallNr		uint64
}

/*
	FileEvent extends Event with FileName and Op.
	Used for files module.
*/
type FileEvent struct {
	Event
	FileName string
	Op string
}

/*
	NetworkEvent represents a TCP connection lifecycle event.
	Used for the network module. The event is classified into
	a meaningful type (connect, accept, close, failed, listen)
	rather than exposing raw TCP state numbers.
*/
type NetworkEvent struct {
	Event
	SrcAddr   uint32   /* IPv4 source address, network byte order */
	DstAddr   uint32   /* IPv4 destination address, network byte order */
	SrcPort   uint16   /* source port, host byte order */
	DstPort   uint16   /* destination port, host byte order */
	EvtType   uint8    /* EVT_CONNECT, EVT_ESTABLISHED, etc. */
	OldState  uint8    /* previous TCP state */
	NewState  uint8    /* new TCP state */
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
