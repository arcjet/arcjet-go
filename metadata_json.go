//go:build !goexperiment.jsonv2

package arcjet

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

var errInvalidUTF8 = errors.New("arcjet: metadata value contains invalid UTF-8")

// encoderEscapesInvalidUTF8 reports whether this build's encoding/json writes
// an invalid byte as the escape \ufffd, which is what makes the check in
// marshalJSON exact. The legacy encoder does. If a later Go release kept
// json/v2 as the implementation but stopped setting the goexperiment.jsonv2
// build tag, this file would be built against json/v2, which writes a literal
// U+FFFD instead; marshalJSON then refuses every U+FFFD rather than sending
// substituted bytes as if they were the value.
var encoderEscapesInvalidUTF8 = func() bool {
	out, err := json.Marshal(string([]byte{0xff}))
	return err == nil && string(out) == `"\ufffd"`
}()

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
	if !encoderEscapesInvalidUTF8 && strings.ContainsRune(out, utf8.RuneError) {
		return "", errInvalidUTF8
	}
	return out, nil
}

// hasInvalidUTF8Escape reports whether JSON output contains a replacement
// character that encoding/json substituted for an invalid UTF-8 byte, or an
// escaped UTF-16 surrogate that is not half of a pair.
//
// The legacy encoder writes a genuine U+FFFD literally but an invalid byte as
// the escape \ufffd, so the escape is an exact signal — at any nesting depth,
// with no traversal of the value. Backslash runs are counted so a string whose
// own text is "\ufffd" (encoded as "\\ufffd") is not mistaken for one.
//
// An unpaired surrogate escape can only come from MarshalJSON output, such as
// a json.RawMessage holding a string that JavaScript cut inside an emoji. It
// does not decode to valid UTF-8, and json/v2 refuses it, so refusing it here
// keeps the two builds' results the same.
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
		if run%2 == 0 {
			continue
		}
		if strings.HasPrefix(s[i:], "ufffd") {
			return true
		}
		r, ok := escapedUTF16(s[i:])
		switch {
		case !ok:
		case r >= 0xdc00 && r <= 0xdfff:
			return true
		case r >= 0xd800 && r <= 0xdbff:
			// A high surrogate needs a low one in the very next escape.
			if i+5 >= len(s) || s[i+5] != '\\' {
				return true
			}
			low, ok := escapedUTF16(s[i+6:])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return true
			}
			i += 11
		}
	}
	return false
}

// escapedUTF16 parses the code unit of a JSON escape whose backslash has
// already been consumed, so s starts at the "u".
func escapedUTF16(s string) (rune, bool) {
	if len(s) < 5 || s[0] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(s[1:5], 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}
