package loader

import (
	"testing"
)

/*
	stubProgram structure implements Program for testing, simulates a real BPF
	module.
*/
type stubProgram struct {
	*BaseProgram
	loadErr error
}

/*
	returns a pointer to dynamically allocated stubProgram object.
*/
func newStub(name string, loadErr error) *stubProgram {
	return &stubProgram{
		BaseProgram: NewBaseProgram(name),
		loadErr:     loadErr,
	}
}

/*
	Load() method for stubProgram structure.
*/
func (s *stubProgram) Load() error {
	if s.loadErr != nil {
		return s.loadErr
	}
	return s.MarkLoaded()
}

/*
	Close() method for stubProgram structure.
*/
func (s *stubProgram) Close() error {
	return s.MarkClosed()
}

/*
	Test for BPF state machine.
*/
func TestStateMachine(t *testing.T) {
	/* allocate storage for BaseProgram. 'p' is a pointer to BaseProgram */
	p := NewBaseProgram("test")

	/* A BaseProgram structure must be initialized with StateUnloaded state */
	if p.State() != StateUnloaded {
		t.Fatalf("expected unloaded, got %s", p.State())
	}

	/* Change the state to StateLoaded, will throw an error if not StateUnloaded  */
	if err := p.MarkLoaded(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	/* State transition occurred above, so calling it again will be return err */
	if err := p.MarkLoaded(); err == nil {
		t.Fatal("expected error on double load, got nil")
	}
}
