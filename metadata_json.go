//go:build !goexperiment.jsonv2

package arcjet

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

var errInvalidUTF8 = errors.New("arcjet: metadata value contains invalid UTF-8")

// marshalJSON encodes value with the legacy encoding/json encoder: the default
// up to Go 1.26, and the one built with GOEXPERIMENT=nojsonv2 from Go 1.27.
//
// This encoder cannot be told to refuse invalid UTF-8, but it writes each
// invalid byte as the escape \ufffd and a genuine U+FFFD literally, so the
// escape in its output is an exact signal (see hasInvalidUTF8Escape). The one
// place the signal is lost is a string field tagged ",string", whose escape is
// escaped again and reads the same as a genuine "\ufffd" in its text; that
// value is sent with U+FFFD in place of its invalid bytes. In the other
// direction, a MarshalJSON that writes a genuine U+FFFD as the escape \ufffd
// reads as a substitution, so its key is dropped although it would have
// encoded. json/v2 gets both right.
//
// The output is also checked as a whole, because the encoder copies MarshalJSON
// output through without validating it, and protobuf rejects the whole request
// over one invalid string.
func marshalJSON(value any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return "", err
	}
	// Encode appends a newline that Marshal would not.
	out := strings.TrimSuffix(buf.String(), "\n")
	if hasInvalidUTF8Escape(out) || !utf8.ValidString(out) {
		return "", errInvalidUTF8
	}
	return out, nil
}

// hasInvalidUTF8Escape reports whether JSON output contains a replacement
// character that encoding/json substituted for an invalid UTF-8 byte.
//
// The legacy encoder writes a genuine U+FFFD literally but an invalid byte as
// the escape \ufffd, so the escape is an exact signal — at any nesting depth,
// with no traversal of the value. Backslash runs are counted so a string whose
// own text is "\ufffd" (encoded as "\\ufffd") is not mistaken for one.
func hasInvalidUTF8Escape(s string) bool {
	i := 0
	for i < len(s) {
		if s[i] != '\\' {
			i++
			continue
		}
		run := 0
		for i < len(s) && s[i] == '\\' {
			run++
			i++
		}
		// An odd run leaves one backslash acting as an escape introducer.
		if run%2 == 1 && strings.HasPrefix(s[i:], "ufffd") {
			return true
		}
	}
	return false
}
