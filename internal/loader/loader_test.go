package loader

import (
	"errors"
	"testing"
)

/*
	stubProgram structure implements Program for testing, simulates a real BPF
	module.
*/
type stubProgram struct {
	*BaseProgram
	loadErr  error
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

/*
	Test for Manager structure.
*/
func TestManagerLoadAll(t *testing.T) {
	/* Allocate memory for Manager structure */
	m := NewManager()

	/* Register programs */
	m.Register(newStub("prog_a", nil))
	m.Register(newStub("prog_b", nil))

	/*
		The LoadAll() method internally also calls the Load() method
		that is defined for Program interface. Only two elements are
		defined above. The Load() method is defined above.

		If non-nil value is present for loadErr, that is returned,
		else MarkLoaded() method will be called. This method will
		return nil only when state is not StateUnloaded.
	*/
	if err := m.LoadAll(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

/*
	Test for ManagerLoadAll where one of the element of Program interface
	does not have nil for loadErr field on stubProgram.
*/
func TestManagerLoadAllStopsOnError(t *testing.T) {
	sentinel := errors.New("load failed")

	m := NewManager()
	m.Register(newStub("prog_a", nil))
	/* registers the error that we defined above */
	m.Register(newStub("prog_b", sentinel))

	err := m.LoadAll()
	/* LoadAll will return the error, as expected. */
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	/*
		Ensure that the error returned is the one defined for sentinel,
		"load failed".

		error.Is walks the wrap chain, %w we used in LoadAll will implement
		the Unwrap method for the error interface.
	*/
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error in chain, got %v", err)
	}
}

/*
	Test for ManagerCloseAll. 
*/
func TestManagerCloseAllContinuesOnError(t *testing.T) {
	m := NewManager()
	m.Register(newStub("prog_a", nil))
	m.Register(newStub("prog_b", nil))

	_ = m.LoadAll()

	/*
		CloseAll method internally calls Close method when state is StateLoaded,
		which is defined above. Close method calls MarkClosed method.

		Unless state is StateLoaded, MarkClosed method returns non-nil.
	*/
	if err := m.CloseAll(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
