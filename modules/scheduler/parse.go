package scheduler

import (
	"encoding/binary"
	"fmt"

	"github.com/PranavRJoshi/Veil/internal/events"
)

type schedEvent struct {
	PrevPID   uint32
	NextPID   uint32
	PrevTID   uint32
	NextTID   uint32
	UID       uint32
	CPU       uint32
	PrevState uint64
	Timestamp uint64
	PrevPrio  uint32
	NextPrio  uint32
	PrevComm  [8]byte
	NextComm  [8]byte
}

const schedEventSize = 64

func parseEvent(raw []byte) (events.SchedulerEvent, error) {
	if len(raw) < schedEventSize {
		return events.SchedulerEvent{}, fmt.Errorf("short read: %d bytes (want %d)", len(raw), schedEventSize)
	}

	se := schedEvent{
		PrevPID:   binary.LittleEndian.Uint32(raw[0:4]),
		NextPID:   binary.LittleEndian.Uint32(raw[4:8]),
		PrevTID:   binary.LittleEndian.Uint32(raw[8:12]),
		NextTID:   binary.LittleEndian.Uint32(raw[12:16]),
		UID:       binary.LittleEndian.Uint32(raw[16:20]),
		CPU:       binary.LittleEndian.Uint32(raw[20:24]),
		PrevState: binary.LittleEndian.Uint64(raw[24:32]),
		Timestamp: binary.LittleEndian.Uint64(raw[32:40]),
		PrevPrio:  binary.LittleEndian.Uint32(raw[40:44]),
		NextPrio:  binary.LittleEndian.Uint32(raw[44:48]),
	}
	copy(se.PrevComm[:], raw[48:56])
	copy(se.NextComm[:], raw[56:64])

	return events.SchedulerEvent{
		Event: events.Event{
			Kind:      events.KindScheduler,
			PID:       se.PrevPID,
			TID:       se.PrevTID,
			UID:       se.UID,
			Timestamp: se.Timestamp,
			/* Comm in the base Event uses prev_comm for consistency */
		},
		PrevPID:   se.PrevPID,
		NextPID:   se.NextPID,
		PrevTID:   se.PrevTID,
		NextTID:   se.NextTID,
		CPU:       se.CPU,
		PrevState: se.PrevState,
		PrevPrio:  se.PrevPrio,
		NextPrio:  se.NextPrio,
		PrevComm:  se.PrevComm,
		NextComm:  se.NextComm,
	}, nil
}

/*
	commString extracts a null-terminated string from a fixed-size byte
	array. Used for the 8-byte prev_comm and next_comm fields.
*/
func commString(b [8]byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b[:])
}

/*
	prevStateName maps the kernel's __TASK_* state values to human-readable
	names. The prev_state field in sched_switch uses these flags.

	Key values from include/linux/sched.h:
		0x0000 -> TASK_RUNNING
		0x0001 -> TASK_INTERRUPTIBLE
		0x0002 -> TASK_UNINTERRUPTIBLE
		0x0004 -> __TASK_STOPPED
		0x0008 -> __TASK_TRACED
		0x0010 -> EXIT_DEAD
		0x0020 -> EXIT_ZOMBIE
		0x0040 -> TASK_PARKED
		0x0080 -> TASK_DEAD
		0x0100 -> TASK_WAKEKILL
		0x0200 -> TASK_WAKING
		0x0400 -> TASK_NOLOAD
		0x0800 -> TASK_NEW
*/
func prevStateName(state uint64) string {
	switch state & 0x0FFF {
		case 0x0000:
			return "RUNNING"
		case 0x0001:
			return "SLEEPING"
		case 0x0002:
			return "DISK_SLEEP"
		case 0x0004:
			return "STOPPED"
		case 0x0008:
			return "TRACED"
		case 0x0010:
			return "EXIT_DEAD"
		case 0x0020:
			return "ZOMBIE"
		case 0x0040:
			return "PARKED"
		case 0x0080:
			return "DEAD"
		case 0x0800:
			return "NEW"
		default:
			return fmt.Sprintf("0x%x", state)
	}
}
