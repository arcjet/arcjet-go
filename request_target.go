package arcjet

import "strings"

// rawPathFromOriginFormTarget preserves the path bytes used by Web Bot Auth's
// @path component. A parsed URL may normalize escapes or dot segments, so a
// non-origin-form or non-ASCII target cannot supply this field safely.
func rawPathFromOriginFormTarget(target string) string {
	if !strings.HasPrefix(target, "/") {
		return ""
	}
	for i := range len(target) {
		b := target[i]
		if b <= 0x20 || b > 0x7e || b == '#' {
			return ""
		}
	}
	path, _, _ := strings.Cut(target, "?")
	return path
}
