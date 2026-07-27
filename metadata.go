package arcjet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

// Metadata is structured metadata for correlation and analytics: string keys
// mapped to any JSON-serializable value, including nested maps and slices.
//
// Each top-level value is JSON-encoded by the SDK and stored verbatim, so exact
// int64 values survive. Metadata never affects a decision and is excluded from
// fingerprinting.
//
// Metadata is untrusted and is not redacted — do not put secrets or PII in it.
type Metadata map[string]any

// MetadataEncodeFailedCode is the warning code for a metadata key the SDK
// dropped before sending.
const MetadataEncodeFailedCode = "AJ1017"

const (
	// maxReportedKeyLength is the longest key name echoed into a warning,
	// matching the server's key cap.
	maxReportedKeyLength = 64
	// maxReportedKeys is the most key names listed in a single warning before
	// the list is elided.
	maxReportedKeys = 10
)

// MaxMetadataBytes is the SDK-side ceiling on the total metadata bytes in one
// request.
//
// This is a protocol backstop, not a copy of the server's policy limits, and it
// is deliberately well above them: the server caps a metadata map at 128 keys of
// 4 KiB (~512 KiB) and those caps are per-account and can be raised, so the SDK
// must never pre-empt them.
//
// What it protects against is the one immutable limit: a request over 1 MiB is
// rejected outright, before any per-key validation runs. A rejected request means
// no decision, which means a fail open — so without this ceiling, oversized
// attacker-derived metadata could change the security outcome, contrary to the
// guarantee that metadata never affects a decision. Counted as UTF-8 bytes of
// keys plus JSON-encoded values before compression, so the estimate is
// conservative.
const MaxMetadataBytes = 768 * 1024

// needsEscape reports whether a rune must be escaped before it goes in a warning
// message.
//
// C0 controls, DEL, the C1 range, and the Unicode line/paragraph separators are
// the characters that can break a log line or a JSON-ish log record. Surrogates
// are escaped because a lone one is not valid UTF-8 at all, and a warning is
// itself sent over the wire. Everything else, including ordinary non-ASCII text,
// is echoed as-is.
//
// Kept identical to needsEscape in arcjet-js and _needs_escape in arcjet-py so
// all three SDKs render the same warning for the same key.
func needsEscape(r rune) bool {
	return r < 0x20 ||
		(r >= 0x7f && r <= 0x9f) ||
		(r >= 0xd800 && r <= 0xdfff) ||
		r == 0x2028 ||
		r == 0x2029
}

// sanitizeKey renders a metadata key for inclusion in a warning message.
//
// Keys are user-controlled, and warnings end up in application logs and in
// server-side storage, so control characters are escaped (a newline in a key
// could otherwise forge a log entry) and the result is length-bounded.
func sanitizeKey(key string) string {
	var b strings.Builder
	length := 0
	for _, r := range key {
		var token string
		switch {
		case r == utf8.RuneError:
			// Ranging over a string yields RuneError for an invalid byte, which
			// would otherwise be indistinguishable from a literal U+FFFD.
			token = `\xef\xbf\xbd`
		case !needsEscape(r):
			token = string(r)
		case r <= 0xff:
			token = fmt.Sprintf(`\x%02x`, r)
		default:
			token = fmt.Sprintf(`\u%04x`, r)
		}
		// An escape token is ASCII, so its own length is its cost; a raw
		// character is one rune. Truncate on a whole token so the result is
		// never a half escape sequence or a split rune.
		cost := 1
		if token != string(r) {
			cost = len(token)
		}
		if length+cost > maxReportedKeyLength {
			return b.String() + "..."
		}
		b.WriteString(token)
		length += cost
	}
	return b.String()
}

// formatDropped renders the key list for a warning, eliding once it gets long.
func formatDropped(prefix, reason string, keys []string) string {
	listed := make([]string, 0, min(len(keys), maxReportedKeys))
	for _, key := range keys[:min(len(keys), maxReportedKeys)] {
		listed = append(listed, `"`+key+`"`)
	}
	joined := strings.Join(listed, ", ")
	if len(keys) > maxReportedKeys {
		joined += ", ..."
	}
	return fmt.Sprintf("%smetadata: %d key(s) %s: %s", prefix, len(keys), reason, joined)
}

// encodeMetadata JSON-encodes each top-level value of metadata for the wire.
//
// Encoding is the SDK's only client-side responsibility here. The limits — 128
// top-level keys, 4 KiB per serialized value, 10 levels of nesting, and key-name
// validity — are enforced server-side (they are configurable per account and can
// be raised), and every key the server drops comes back on the decision. The one
// drop the SDK must make itself is a value encoding/json cannot represent: a
// channel, a func, a cycle, NaN or an infinity, or a string that is not valid
// UTF-8 (which protobuf would reject).
//
// prefix identifies the source in the warning message (such as "rules[0]."),
// matching the server's convention.
//
// Encoding never panics and never affects a decision: a bad value costs that one
// key, not the call. It returns at most one warning, naming every key that had to
// be dropped, so one call can never flood the warning channel.
//
// Keys are processed in sorted order. Go map iteration is randomized, so unlike
// arcjet-js and arcjet-py — which preserve insertion order — sorting is the only
// way to make which-keys-survive and warning text reproducible.
func encodeMetadata(metadata Metadata, prefix string) (map[string]string, []Warning) {
	if len(metadata) == 0 {
		return nil, nil
	}

	encoded := make(map[string]string, len(metadata))
	var dropped []string

	for _, key := range slices.Sorted(maps.Keys(metadata)) {
		value, err := marshalMetadataValue(metadata[key])
		if err != nil || !utf8.ValidString(key) {
			dropped = append(dropped, sanitizeKey(key))
			continue
		}
		encoded[key] = value
	}

	if len(dropped) == 0 {
		return encoded, nil
	}
	return encoded, []Warning{{
		Code:    MetadataEncodeFailedCode,
		Message: formatDropped(prefix, "could not be JSON-encoded and were dropped", dropped),
	}}
}

// marshalMetadataValue JSON-encodes a single metadata value.
//
// HTML escaping is disabled so "<" and "&" are stored as themselves rather than
// as \u003c and \u0026, matching what arcjet-js and arcjet-py send.
//
// A string containing invalid UTF-8 is rejected rather than silently rewritten:
// encoding/json would replace those bytes with U+FFFD, quietly changing the
// value. Dropping the key instead matches arcjet-py and arcjet-js, which drop
// their equivalent (a lone surrogate) because protobuf cannot carry it.
func marshalMetadataValue(value any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return "", err
	}
	// Encode appends a newline that Marshal would not.
	out := strings.TrimSuffix(buf.String(), "\n")
	if hasInvalidUTF8Escape(out) {
		return "", errors.New("arcjet: metadata value contains invalid UTF-8")
	}
	return out, nil
}

// hasInvalidUTF8Escape reports whether JSON output contains a replacement
// character that encoding/json substituted for an invalid UTF-8 byte.
//
// The encoder writes a genuine U+FFFD literally but an invalid byte as the
// escape \ufffd, so the escape is an exact signal — at any nesting depth, with
// no traversal of the value. Backslash runs are counted so a string whose own
// text is "\ufffd" (encoded as "\\ufffd") is not mistaken for one.
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

// enforceMetadataBudget trims already-encoded metadata maps to MaxMetadataBytes
// in total.
//
// The maps are trimmed in place, in the order given, and within each map in
// sorted key order: keys are kept until the running total would exceed the
// budget, and every key after that is dropped. Pass the request envelope's map
// first and each rule's map after it, so the order is stable across calls.
//
// One request can carry several metadata maps (a Guard request has one per rule
// plus the envelope), so the ceiling has to be enforced across all of them rather
// than per map. See MaxMetadataBytes for why this exists at all.
//
// It returns at most one warning, naming the keys that were dropped.
func enforceMetadataBudget(metadataMaps []map[string]string) []Warning {
	total := 0
	var dropped []string

	for _, m := range metadataMaps {
		var over []string
		for _, key := range slices.Sorted(maps.Keys(m)) {
			if total > MaxMetadataBytes {
				over = append(over, key)
				continue
			}
			size := len(key) + len(m[key])
			if total+size > MaxMetadataBytes {
				over = append(over, key)
				// Nothing further fits either; keep scanning so every dropped
				// key is reported.
				total = MaxMetadataBytes + 1
				continue
			}
			total += size
		}
		for _, key := range over {
			delete(m, key)
			dropped = append(dropped, sanitizeKey(key))
		}
	}

	if len(dropped) == 0 {
		return nil
	}
	return []Warning{{
		Code: MetadataEncodeFailedCode,
		Message: formatDropped("", fmt.Sprintf(
			"exceeded the %d-byte request metadata budget and were dropped",
			MaxMetadataBytes,
		), dropped),
	}}
}

// warningsToProtoV2 converts SDK warnings into the v2 proto Warning messages
// carried by GuardRequest.local_warnings.
func warningsToProtoV2(warnings []Warning) []*decidev2.Warning {
	if len(warnings) == 0 {
		return nil
	}
	out := make([]*decidev2.Warning, 0, len(warnings))
	for _, w := range warnings {
		out = append(out, &decidev2.Warning{Code: w.Code, Message: w.Message})
	}
	return out
}
