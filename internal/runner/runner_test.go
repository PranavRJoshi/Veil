package runner

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// fakeModule: test double satisfying Module interface
// ---------------------------------------------------------------------------

type fakeModule struct {
	name      string
	loadErr   error
	closeErr  error
	loaded    int32 // atomic
	closed    int32 // atomic
	runCalled int32 // atomic
}

func (m *fakeModule) Name() string { return m.name }

func (m *fakeModule) Load() error {
	if m.loadErr != nil {
		return m.loadErr
	}
	atomic.AddInt32(&m.loaded, 1)
	return nil
}

func (m *fakeModule) Close() error {
	atomic.AddInt32(&m.closed, 1)
	return m.closeErr
}

func (m *fakeModule) Run(done <-chan struct{}) {
	atomic.AddInt32(&m.runCalled, 1)
	<-done
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLoadAll_Success(t *testing.T) {
	a := &fakeModule{name: "a"}
	b := &fakeModule{name: "b"}
	mr := New(a, b)

	if err := mr.LoadAll(); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if atomic.LoadInt32(&a.loaded) != 1 {
		t.Error("module a not loaded")
	}
	if atomic.LoadInt32(&b.loaded) != 1 {
		t.Error("module b not loaded")
	}
	_ = mr.CloseAll()
}

func TestLoadAll_FailRollsBack(t *testing.T) {
	a := &fakeModule{name: "a"}
	b := &fakeModule{name: "b", loadErr: fmt.Errorf("boom")}
	c := &fakeModule{name: "c"}
	mr := New(a, b, c)

	err := mr.LoadAll()
	if err == nil {
		t.Fatal("expected error from LoadAll")
	}
	// a was loaded then should have been closed during rollback
	if atomic.LoadInt32(&a.loaded) != 1 {
		t.Error("module a should have been loaded before rollback")
	}
	if atomic.LoadInt32(&a.closed) != 1 {
		t.Error("module a should have been closed during rollback")
	}
	// c should never have been touched
	if atomic.LoadInt32(&c.loaded) != 0 {
		t.Error("module c should not have been loaded")
	}
}

func TestRunAll_BlocksUntilDone(t *testing.T) {
	a := &fakeModule{name: "a"}
	b := &fakeModule{name: "b"}
	mr := New(a, b)
	_ = mr.LoadAll()

	done := make(chan struct{})
	finished := make(chan struct{})

	go func() {
		mr.RunAll(done)
		close(finished)
	}()

	// Give goroutines time to start
	time.Sleep(20 * time.Millisecond)

	if atomic.LoadInt32(&a.runCalled) != 1 {
		t.Error("module a Run not called")
	}
	if atomic.LoadInt32(&b.runCalled) != 1 {
		t.Error("module b Run not called")
	}

	// Signal shutdown
	close(done)

	select {
		case <-finished:
			// ok
		case <-time.After(time.Second):
			t.Fatal("RunAll did not return after done was closed")
	}

	_ = mr.CloseAll()
}

func TestCloseAll_ReverseOrder(t *testing.T) {
	var order []string
	makeModule := func(name string) *orderTrackingModule {
		return &orderTrackingModule{name: name, order: &order}
	}

	a := makeModule("a")
	b := makeModule("b")
	c := makeModule("c")
	mr := New(a, b, c)
	_ = mr.LoadAll()
	_ = mr.CloseAll()

	if len(order) != 3 {
		t.Fatalf("expected 3 closes, got %d", len(order))
	}
	// Should be c, b, a (reverse)
	if order[0] != "c" || order[1] != "b" || order[2] != "a" {
		t.Errorf("expected [c b a], got %v", order)
	}
}

func TestNames(t *testing.T) {
	mr := New(&fakeModule{name: "net"}, &fakeModule{name: "sys"})
	names := mr.Names()
	if len(names) != 2 || names[0] != "net" || names[1] != "sys" {
		t.Errorf("Names = %v, want [net sys]", names)
	}
}

// ---------------------------------------------------------------------------
// orderTrackingModule: records close order
// ---------------------------------------------------------------------------

type orderTrackingModule struct {
	name  string
	order *[]string
}

func (m *orderTrackingModule) Name() string    { return m.name }
func (m *orderTrackingModule) Load() error     { return nil }
func (m *orderTrackingModule) Run(_ <-chan struct{}) {}
func (m *orderTrackingModule) Close() error {
	*m.order = append(*m.order, m.name)
	return nil
}
