// Package color provides opt-in ANSI coloring for Veil's own CLI messages
// (error/warning/ok and "did you mean" hints) and a per-module palette for
// multi-module text output. Coloring is resolved once per stream at startup
// from the --color mode, the NO_COLOR environment variable, and whether the
// stream is a terminal; when disabled every helper returns its input unchanged.
package color

import "os"

// Stream carries the resolved color state for one output stream. The zero
// value is disabled, so helpers are safe to call before Init.
type Stream struct {
	enabled bool
}

var (
	Stdout Stream
	Stderr Stream
)

const (
	codeRed    = "31"
	codeGreen  = "32"
	codeYellow = "33"
	codeCyan   = "36"
	codeDim    = "2"
	codeBold   = "1"
)

// palette holds the ANSI codes cycled through for per-module tinting; the
// first six give each of Veil's modules a distinct color.
var palette = []string{"36", "35", "34", "32", "33", "31"}

// Init resolves coloring for both standard streams from the requested mode
// ("auto", "always", "never"). Call once at startup before any colored output.
func Init(mode string) {
	noColor := os.Getenv("NO_COLOR") != ""
	Stdout = Stream{enabled: resolve(mode, noColor, isTTY(os.Stdout))}
	Stderr = Stream{enabled: resolve(mode, noColor, isTTY(os.Stderr))}
}

// resolve applies the precedence: an explicit mode wins, and only "auto"
// consults NO_COLOR and the terminal check.
func resolve(mode string, noColor, tty bool) bool {
	switch mode {
	case "never":
		return false
	case "always":
		return true
	default: // "auto"
		return !noColor && tty
	}
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// Enabled reports whether this stream will emit color codes.
func (s Stream) Enabled() bool { return s.enabled }

func (s Stream) wrap(code, str string) string {
	if !s.enabled {
		return str
	}
	return "\x1b[" + code + "m" + str + "\x1b[0m"
}

func (s Stream) Red(str string) string    { return s.wrap(codeRed, str) }
func (s Stream) Green(str string) string  { return s.wrap(codeGreen, str) }
func (s Stream) Yellow(str string) string { return s.wrap(codeYellow, str) }
func (s Stream) Cyan(str string) string   { return s.wrap(codeCyan, str) }
func (s Stream) Dim(str string) string    { return s.wrap(codeDim, str) }
func (s Stream) Bold(str string) string   { return s.wrap(codeBold, str) }

// Paint tints str with the palette color at index i, wrapping when i exceeds
// the palette size, so each module keeps a stable distinct color.
func (s Stream) Paint(i int, str string) string {
	if !s.enabled {
		return str
	}
	return s.wrap(palette[i%len(palette)], str)
}
