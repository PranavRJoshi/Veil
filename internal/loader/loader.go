package loader

import (
	"fmt"
)

/*
	State type is used to represent the various state of a loaded BPF program.
*/
type State uint8

/*
	Possible enumerables of a state.
*/
const (
	StateUnloaded State = iota
	StateLoaded
	StateClosed
)

/*
	String() method for the State data type.
*/
func (s State) String() string {
	switch s {
	case StateUnloaded:
		return "unloaded"
	case StateLoaded:
		return "loaded"
	case StateClosed:
		return "closed"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

/*
	The Program interface that every BPF module must satisfy.
	Load() attaches the program into the kernel. Close() will detach
	and cleanup.
*/
type Program interface {
	Load() error
	Close() error
	Name() string
	State() State
}

/*
	Modules will embed the BaseProgram structure. It is used to
	handle state tracking so individual modules don't have to
	track the state.

	BaseProgram does not implement Program. It will be further
	embedded into another structure which will implement the
	Program interface.
*/
type BaseProgram struct {
	name  string
	state State
}

/*
	A "constructor" for BaseProgram structure. Requires name.
	State defaults to StateUnloaded.
*/
func NewBaseProgram(name string) *BaseProgram {
	return &BaseProgram{
		name:  name,
		state: StateUnloaded,
	}
}

/*
	Accessor functions, or specifically getters for the fields
	of BaseProgram structure.
*/
func (b *BaseProgram) Name() string { return b.name }
func (b *BaseProgram) State() State { return b.state }

/*
	Mark the state of a BaseProgram instance to be 'StateLoaded'.
	The State of the BaseProgram must be 'StateUnloaded', otherwise
	it is already loaded.
*/
func (b *BaseProgram) MarkLoaded() error {
	if b.state != StateUnloaded {
		return fmt.Errorf("%s: cannot load from state %s", b.name, b.state)
	}
	b.state = StateLoaded
	return nil
}

/*
	Mark the state of a BaseProgram instance to be 'StateClosed'.
	A loaded program must first be unloaded and only closed.
*/
func (b *BaseProgram) MarkClosed() error {
	if b.state != StateLoaded {
		return fmt.Errorf("%s: cannot close from state %s", b.name, b.state)
	}
	b.state = StateClosed
	return nil
}

