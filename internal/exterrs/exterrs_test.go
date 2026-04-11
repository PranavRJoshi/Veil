package exterrs

import (
	"errors"
	"testing"
)

func TestJoin(t *testing.T) {
	sentinel1 := errors.New("error one")
	sentinel2 := errors.New("error two")

	cases := []struct {
		name     string
		input    []error
		wantNil  bool
		wantMsg  string
	}{
		{
			name:    "nil slice returns nil",
			input:   nil,
			wantNil: true,
		},
		{
			name:    "all nil errors returns nil",
			input:   []error{nil, nil},
			wantNil: true,
		},
		{
			name:    "single error",
			input:   []error{sentinel1},
			wantMsg: "error one",
		},
		{
			name:    "multiple errors joined with semicolon",
			input:   []error{sentinel1, sentinel2},
			wantMsg: "error one; error two",
		},
		{
			name:    "nil errors are skipped",
			input:   []error{sentinel1, nil, sentinel2},
			wantMsg: "error one; error two",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Join(c.input)

			if c.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}

			if got == nil {
				t.Fatalf("expected error, got nil")
			}

			if got.Error() != c.wantMsg {
				t.Errorf("got %q, want %q", got.Error(), c.wantMsg)
			}
		})
	}
}
