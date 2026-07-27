package arcjet

import (
	"math"
	"strings"
	"testing"
)

func TestEncodeMetadataEmpty(t *testing.T) {
	for name, input := range map[string]Metadata{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			encoded, warnings := encodeMetadata(input, "")
			if len(encoded) != 0 || len(warnings) != 0 {
				t.Fatalf("encoded = %#v, warnings = %#v", encoded, warnings)
			}
		})
	}
}

func TestEncodeMetadataValues(t *testing.T) {
	// Values are JSON, so a string arrives quoted — this is what makes
	// metadata['env'] = '"staging"' the ClickHouse query form.
	encoded, warnings := encodeMetadata(Metadata{
		"env":         "staging",
		"user":        map[string]any{"id": "u_1"},
		"roles":       []string{"admin", "ops"},
		"duration_ms": 160,
		"score":       0.5,
		"success":     true,
		"nothing":     nil,
		"city":        "Zürich",
		"html":        "a<b&c",
	}, "")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v", warnings)
	}
	want := map[string]string{
		"env":         `"staging"`,
		"user":        `{"id":"u_1"}`,
		"roles":       `["admin","ops"]`,
		"duration_ms": "160",
		"score":       "0.5",
		"success":     "true",
		"nothing":     "null",
		"city":        `"Zürich"`,
		// HTML escaping is off, matching arcjet-js and arcjet-py.
		"html": `"a<b&c"`,
	}
	for key, expected := range want {
		if encoded[key] != expected {
			t.Errorf("encoded[%q] = %q, want %q", key, encoded[key], expected)
		}
	}
}

func TestEncodeMetadataInt64IsExact(t *testing.T) {
	// Go int64 is sent verbatim, so a value past 2^53 survives exactly — the same
	// as arcjet-py, and unlike arcjet-js whose numbers are float64 on the wire.
	const big int64 = math.MaxInt64
	encoded, _ := encodeMetadata(Metadata{"cursor": big}, "")
	if encoded["cursor"] != "9223372036854775807" {
		t.Fatalf("cursor = %q", encoded["cursor"])
	}
}

func TestEncodeMetadataDropsUnencodable(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle

	cases := map[string]any{
		"channel":  make(chan int),
		"func":     func() {},
		"nan":      math.NaN(),
		"inf":      math.Inf(1),
		"cycle":    cycle,
		"bad-utf8": string([]byte{0xff, 0xfe}),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, warnings := encodeMetadata(Metadata{"bad": value, "ok": 1}, "")
			if len(encoded) != 1 || encoded["ok"] != "1" {
				t.Fatalf("encoded = %#v", encoded)
			}
			if len(warnings) != 1 || warnings[0].Code != MetadataEncodeFailedCode {
				t.Fatalf("warnings = %#v", warnings)
			}
			if !strings.Contains(warnings[0].Message, `"bad"`) {
				t.Fatalf("message = %q", warnings[0].Message)
			}
		})
	}
}

func TestEncodeMetadataKeepsLegitimateReplacementCharacters(t *testing.T) {
	// encoding/json writes a genuine U+FFFD literally and an invalid byte as the
	// escape \ufffd, so only the latter is a drop. A value whose own text is
	// "\ufffd" must not be mistaken for one.
	encoded, warnings := encodeMetadata(Metadata{
		"real":    "\ufffd",
		"literal": `\ufffd not really`,
	}, "")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if len(encoded) != 2 {
		t.Fatalf("encoded = %#v", encoded)
	}
}

func TestEncodeMetadataDropsInvalidUTF8Key(t *testing.T) {
	// protobuf cannot carry an invalid-UTF-8 string, so the key must not reach it.
	encoded, warnings := encodeMetadata(Metadata{string([]byte{0xff}): 1, "ok": 1}, "")
	if len(encoded) != 1 || encoded["ok"] != "1" {
		t.Fatalf("encoded = %#v", encoded)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func TestEncodeMetadataOneWarningForManyDrops(t *testing.T) {
	// One encode call must never flood the warning channel, which the server
	// bounds and persists.
	input := Metadata{}
	for i := range 15 {
		input[string(rune('a'+i))] = make(chan int)
	}
	encoded, warnings := encodeMetadata(input, "")
	if len(encoded) != 0 {
		t.Fatalf("encoded = %#v", encoded)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if !strings.Contains(warnings[0].Message, "15 key(s)") {
		t.Fatalf("message = %q", warnings[0].Message)
	}
	if !strings.HasSuffix(warnings[0].Message, `"j", ...`) {
		t.Fatalf("message = %q", warnings[0].Message)
	}
}

func TestEncodeMetadataKeysAreSorted(t *testing.T) {
	// Go map iteration is randomized, so sorting is the only way to make
	// which-keys-survive and the warning text reproducible.
	input := Metadata{}
	for _, key := range []string{"c", "a", "b"} {
		input[key] = make(chan int)
	}
	_, warnings := encodeMetadata(input, "")
	if !strings.HasSuffix(warnings[0].Message, `"a", "b", "c"`) {
		t.Fatalf("message = %q", warnings[0].Message)
	}
}

func TestEncodeMetadataPrefix(t *testing.T) {
	_, warnings := encodeMetadata(Metadata{"bad": make(chan int)}, "rules[2].")
	if !strings.HasPrefix(warnings[0].Message, "rules[2].metadata: ") {
		t.Fatalf("message = %q", warnings[0].Message)
	}
}

func TestSanitizeKeyEscapes(t *testing.T) {
	// Keys are user-controlled and warnings reach logs and server storage, so a
	// newline must not be able to forge a log entry. The escape set and format are
	// identical across all three SDKs.
	cases := map[string]string{
		"ev\nil INFO forged": `ev\x0ail INFO forged`,
		"a\u2028b":           `a\u2028b`,
		"a\u0085b":           `a\x85b`,
		"plain-\u00fc":       "plain-\u00fc",
	}
	for input, want := range cases {
		if got := sanitizeKey(input); got != want {
			t.Errorf("sanitizeKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSanitizeKeyTruncatesOnTokenBoundary(t *testing.T) {
	// Never a half escape sequence, and never a split rune.
	long := sanitizeKey(strings.Repeat("x", 200))
	if len(long) > maxReportedKeyLength+3 {
		t.Fatalf("len = %d: %q", len(long), long)
	}
	if !strings.HasSuffix(long, "...") {
		t.Fatalf("no elision: %q", long)
	}

	// 63 runes plus an astral rune is exactly at the limit, so it survives whole.
	astral := sanitizeKey(strings.Repeat("a", 63) + "😀")
	if !strings.HasSuffix(astral, "😀") {
		t.Fatalf("astral rune split: %q", astral)
	}
}

func TestEnforceMetadataBudgetNoOp(t *testing.T) {
	m := map[string]string{"a": `"x"`, "b": `"y"`}
	if warnings := enforceMetadataBudget([]map[string]string{m}); len(warnings) != 0 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if len(m) != 2 {
		t.Fatalf("trimmed = %#v", m)
	}
}

func TestMaxMetadataBytesSitsAboveServerLimits(t *testing.T) {
	// The SDK ceiling is a protocol backstop, not a copy of server policy: the
	// server can accept ~512 KiB in one map, so the SDK must not trim that.
	if MaxMetadataBytes <= 128*4096 {
		t.Fatalf("MaxMetadataBytes = %d, must exceed the server's per-map maximum", MaxMetadataBytes)
	}
	if MaxMetadataBytes >= 1024*1024 {
		t.Fatalf("MaxMetadataBytes = %d, must stay under the 1 MiB protocol limit", MaxMetadataBytes)
	}
}

func TestEnforceMetadataBudgetTrimsAcrossMapsInOrder(t *testing.T) {
	envelope := map[string]string{"a_big": strings.Repeat("x", 500_000), "b_keep": "1"}
	rule := map[string]string{"c_big": strings.Repeat("y", 500_000), "d_tail": "2"}
	warnings := enforceMetadataBudget([]map[string]string{envelope, rule})

	// The envelope is served first; the rule map is starved.
	if len(envelope) != 2 {
		t.Fatalf("envelope = %v", mapKeys(envelope))
	}
	if len(rule) != 0 {
		t.Fatalf("rule = %v", mapKeys(rule))
	}
	if len(warnings) != 1 || warnings[0].Code != MetadataEncodeFailedCode {
		t.Fatalf("warnings = %#v", warnings)
	}
	if !strings.Contains(warnings[0].Message, "2 key(s)") ||
		!strings.Contains(warnings[0].Message, "request metadata budget") {
		t.Fatalf("message = %q", warnings[0].Message)
	}
}

func TestEnforceMetadataBudgetDropsAnOversizedValue(t *testing.T) {
	m := map[string]string{"huge": strings.Repeat("x", MaxMetadataBytes+1)}
	warnings := enforceMetadataBudget([]map[string]string{m})
	if len(m) != 0 {
		t.Fatalf("kept = %v", mapKeys(m))
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
