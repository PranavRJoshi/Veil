// Package suggest turns a mistyped token and the set of valid ones into a
// "did you mean" hint for an error message.
package suggest

import (
	"sort"
	"strings"
)

const minPrefix = 4

// Closest returns up to max candidates similar to target, best first. A
// candidate qualifies by a small edit distance (a typo) or a shared prefix (a
// near-miss inside a family of related names, e.g. epoll_pwait for
// epoll_wait). It returns nil when nothing is close, so a caller can drop the
// hint rather than mislead.
func Closest(target string, candidates []string, max int) []string {
	if target == "" || max <= 0 {
		return nil
	}
	t := strings.ToLower(target)
	thr := maxDist(len(t))

	type match struct {
		name   string
		dist   int
		prefix int
	}
	var matches []match
	for _, c := range candidates {
		lc := strings.ToLower(c)
		if lc == t {
			continue
		}
		d := distance(t, lc)
		p := commonPrefix(t, lc)
		if d > thr && p < minPrefix {
			continue
		}
		matches = append(matches, match{c, d, p})
	}

	sort.Slice(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		if a.dist != b.dist {
			return a.dist < b.dist
		}
		if a.prefix != b.prefix {
			return a.prefix > b.prefix
		}
		return a.name < b.name
	})
	if len(matches) == 0 {
		return nil
	}
	if len(matches) > max {
		matches = matches[:max]
	}

	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.name
	}
	return out
}

// maxDist scales the tolerated edit distance with token length so a short name
// is not matched to everything one insertion away.
func maxDist(n int) int {
	switch {
	case n <= 4:
		return 1
	case n <= 8:
		return 2
	default:
		return 3
	}
}

func commonPrefix(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

// distance is Levenshtein edit distance over bytes; all inputs here are ASCII.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
