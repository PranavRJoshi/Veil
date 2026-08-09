package color

import (
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		noColor bool
		tty     bool
		want    bool
	}{
		{"never wins over tty", "never", false, true, false},
		{"always wins over no-tty", "always", false, false, true},
		{"always beats NO_COLOR", "always", true, false, true},
		{"auto on when tty and no NO_COLOR", "auto", false, true, true},
		{"auto off when piped", "auto", false, false, false},
		{"auto respects NO_COLOR", "auto", true, true, false},
		{"unknown mode treated as auto", "", false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolve(tt.mode, tt.noColor, tt.tty); got != tt.want {
				t.Errorf("resolve(%q, %v, %v) = %v, want %v", tt.mode, tt.noColor, tt.tty, got, tt.want)
			}
		})
	}
}

func TestWrapEnabled(t *testing.T) {
	s := Stream{enabled: true}
	got := s.Red("error:")
	if !strings.HasPrefix(got, "\x1b[31m") || !strings.HasSuffix(got, "\x1b[0m") {
		t.Errorf("Red did not wrap in SGR codes: %q", got)
	}
	if !strings.Contains(got, "error:") {
		t.Errorf("Red dropped the payload: %q", got)
	}
}

func TestStyleCodes(t *testing.T) {
	s := Stream{enabled: true}
	tests := []struct {
		got  string
		code string
	}{
		{s.Bold("x"), "1"},
		{s.Cyan("x"), "36"},
		{s.Red("x"), "31"},
		{s.Dim("x"), "2"},
	}
	for _, tt := range tests {
		want := "\x1b[" + tt.code + "mx\x1b[0m"
		if tt.got != want {
			t.Errorf("got %q, want %q", tt.got, want)
		}
	}
}

func TestWrapDisabledIsIdentity(t *testing.T) {
	s := Stream{enabled: false}
	for _, in := range []string{"error:", "ok:", ""} {
		if got := s.Red(in); got != in {
			t.Errorf("disabled Red(%q) = %q, want unchanged", in, got)
		}
		if got := s.Paint(3, in); got != in {
			t.Errorf("disabled Paint(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestPaintWrapsPalette(t *testing.T) {
	s := Stream{enabled: true}
	// Indices that are equal modulo the palette size must produce the same code.
	if got, wrapped := s.Paint(0, "x"), s.Paint(len(palette), "x"); got != wrapped {
		t.Errorf("Paint(0) = %q but Paint(len) = %q; want equal", got, wrapped)
	}
}

func TestZeroStreamDisabled(t *testing.T) {
	var s Stream
	if s.Enabled() {
		t.Error("zero-value Stream should be disabled")
	}
	if got := s.Green("ok:"); got != "ok:" {
		t.Errorf("zero-value stream colored output: %q", got)
	}
}
