// Package entityname finds a sensitive information entity name that looks like
// a built-in one, which is almost always a typo for it.
package entityname

import (
	"slices"
	"strings"
)

// LookalikeBuiltin returns the built-in name that name most likely meant, or
// "" when name is built in or not close to one. A name is close when it equals
// a built-in name with case and punctuation ignored or, at five or more
// characters, is a prefix of one or one edit away from it.
func LookalikeBuiltin(name string, builtins []string) string {
	if slices.Contains(builtins, name) {
		return ""
	}
	wanted := normalize(name)
	sorted := slices.Clone(builtins)
	slices.Sort(sorted)
	for _, builtin := range sorted {
		candidate := normalize(builtin)
		if candidate == wanted {
			return builtin
		}
		if len(wanted) >= 5 && (strings.HasPrefix(candidate, wanted) || withinOneEdit(wanted, candidate)) {
			return builtin
		}
	}
	return ""
}

func normalize(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// withinOneEdit reports whether a and b differ by at most one insertion,
// deletion, substitution or swap of neighbouring characters. Both are ASCII.
func withinOneEdit(a, b string) bool {
	if len(a)-len(b) > 1 || len(b)-len(a) > 1 {
		return false
	}
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	switch {
	case len(a) == len(b):
		if i == len(a) || a[i+1:] == b[i+1:] {
			return true
		}
		return i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
	case len(a) > len(b):
		return a[i+1:] == b[i:]
	default:
		return a[i:] == b[i+1:]
	}
}
