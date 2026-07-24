package loader

import (
	"testing"
)

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
