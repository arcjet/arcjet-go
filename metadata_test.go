package arcjet

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
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
		// encoding/json does not recover either panic.
		"panicking MarshalJSON": panickingMarshaler{},
		"nil embedded pointer": struct {
			*time.Time
			Name string
		}{Name: "x"},
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

type panickingMarshaler struct{}

func (panickingMarshaler) MarshalJSON() ([]byte, error) { panic("boom") }

// The panic value is application data and can be sensitive, so it must not
// reach the error.
func TestMarshalMetadataValuePanicErrorOmitsThePanicValue(t *testing.T) {
	_, err := marshalMetadataValue(panickingMarshaler{})
	if !errors.Is(err, errMetadataPanicked) || strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

// invalidUTF8 is a string encoding/json cannot carry as-is: it substitutes
// U+FFFD for each byte, quietly changing the value.
var invalidUTF8 = string([]byte{0xff, 0xfe})

// The types below exercise the methods encoding/json calls instead of encoding
// a value by reflection.

// rawJSONMarshaler returns its bytes from MarshalJSON unchanged.
type rawJSONMarshaler struct{ out string }

func (m rawJSONMarshaler) MarshalJSON() ([]byte, error) { return []byte(m.out), nil }

// rawTextMarshaler returns its bytes from MarshalText unchanged.
type rawTextMarshaler struct{ out string }

func (m rawTextMarshaler) MarshalText() ([]byte, error) { return []byte(m.out), nil }

// hexTextMarshaler holds arbitrary bytes and encodes them as hex, so invalid
// UTF-8 in its field never reaches the output.
type hexTextMarshaler struct{ raw string }

func (m hexTextMarshaler) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString([]byte(m.raw))), nil
}

// textKey is a non-string map key, which encoding/json encodes through
// MarshalText.
type textKey int

func (k textKey) MarshalText() ([]byte, error) {
	if k == 0 {
		return []byte(invalidUTF8), nil
	}
	return []byte("key"), nil
}

// textStringKey is a string-kinded map key that also implements MarshalText.
// The legacy encoder emits the string itself; json/v2 calls MarshalText.
type textStringKey string

func (textStringKey) MarshalText() ([]byte, error) { return []byte("key"), nil }

// pointerJSONMarshaler implements MarshalJSON on its pointer only, so
// encoding/json calls it only where the value is addressable and otherwise
// encodes the struct field by field.
type pointerJSONMarshaler struct{ Raw string }

func (*pointerJSONMarshaler) MarshalJSON() ([]byte, error) { return []byte(`"redacted"`), nil }

// embeddedUTF8 is promoted into utf8Outer, so its field is encoded as one of
// utf8Outer's own.
type embeddedUTF8 struct{ Inner string }

type utf8Outer struct {
	embeddedUTF8
	Outer string
}

// utf8OuterPtr embeds a pointer, which the encoder follows when it is non-nil.
type utf8OuterPtr struct {
	*embeddedUTF8
}

// utf8OuterTagged names its unexported embedded struct, so encoding/json writes
// it as an object under that name instead of flattening it.
type utf8OuterTagged struct {
	embeddedUTF8 `json:"inner"`
}

// conflictA and conflictB both promote Name at the same depth, so
// encoding/json omits it from conflictOuter altogether.
type conflictA struct{ Name string }

type conflictB struct{ Name string }

type conflictOuter struct {
	conflictA
	conflictB
}

// shadowOuter's own Name hides the one shadowInner promotes, so encoding/json
// writes only the shallower field.
type shadowInner struct{ Name string }

type shadowOuter struct {
	shadowInner
	Name string
}

// lazyJSONMarshaler dereferences its pointer, so calling MarshalJSON on its
// zero value panics. A field tagged omitzero never gets that far.
type lazyJSONMarshaler struct{ p *string }

func (l lazyJSONMarshaler) MarshalJSON() ([]byte, error) { return json.Marshal(*l.p) }

// optionalJSON is an optional value whose MarshalJSON refuses to encode it
// while it is unset, and whose IsZero lets omitzero leave it out.
type optionalJSON struct{ set bool }

func (o optionalJSON) IsZero() bool { return !o.set }

func (o optionalJSON) MarshalJSON() ([]byte, error) {
	if !o.set {
		return nil, errors.New("unset")
	}
	return []byte(`"set"`), nil
}

// nonEmptyJSON panics when asked to encode an empty string, which omitempty
// leaves out.
type nonEmptyJSON string

func (s nonEmptyJSON) MarshalJSON() ([]byte, error) {
	if s == "" {
		panic("nonEmptyJSON: empty")
	}
	return json.Marshal(string(s))
}

// assertDropsKey checks that encodeMetadata drops the key holding value with
// one MetadataEncodeFailedCode warning, and keeps its sibling.
func assertDropsKey(t *testing.T, value any) {
	t.Helper()
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
}

func TestEncodeMetadataDropsNestedInvalidUTF8(t *testing.T) {
	// A string anywhere in the value that encoding/json would rewrite must drop
	// the key, at any depth and however the encoder reached it.
	cases := map[string]any{
		"map value":    map[string]any{"k": invalidUTF8},
		"slice":        []any{"ok", invalidUTF8},
		"typed slice":  []string{"ok", invalidUTF8},
		"array":        [2]string{"ok", invalidUTF8},
		"nested key":   map[string]any{"outer": map[string]any{invalidUTF8: 1}},
		"struct field": struct{ Name string }{Name: invalidUTF8},
		"struct ptr":   &struct{ Name string }{Name: invalidUTF8},
		"tagged field": struct {
			Name string `json:"name,omitempty"`
		}{Name: invalidUTF8},
		"embedded field":      utf8Outer{embeddedUTF8: embeddedUTF8{Inner: invalidUTF8}},
		"embedded pointer":    utf8OuterPtr{embeddedUTF8: &embeddedUTF8{Inner: invalidUTF8}},
		"tagged embedded":     utf8OuterTagged{embeddedUTF8: embeddedUTF8{Inner: invalidUTF8}},
		"interface in struct": struct{ V any }{V: []any{invalidUTF8}},
		// MarshalJSON output is embedded without re-encoding its strings.
		"MarshalJSON": rawJSONMarshaler{out: `"` + invalidUTF8 + `"`},
		"MarshalJSON nested": map[string]any{
			"k": rawJSONMarshaler{out: `{"a":"` + invalidUTF8 + `"}`},
		},
		// MarshalText output is encoded as a JSON string.
		"MarshalText":     rawTextMarshaler{out: invalidUTF8},
		"MarshalText key": map[textKey]int{0: 1},
		// Encoded field by field where it is not addressable, so its field is
		// what reaches the output.
		"pointer MarshalJSON by value": pointerJSONMarshaler{Raw: invalidUTF8},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			assertDropsKey(t, value)
		})
	}
}

func TestEncodeMetadataKeepsLegitimateReplacementCharacters(t *testing.T) {
	// A genuine U+FFFD is valid UTF-8 and must be kept wherever it appears, and
	// so must a value whose own text is "\ufffd". json/v2 writes an invalid byte
	// as a literal U+FFFD, so its output alone cannot tell the two apart.
	encoded, warnings := encodeMetadata(Metadata{
		"real":        "\ufffd",
		"literal":     `\ufffd not really`,
		"nested":      map[string]any{"\ufffd": []any{"\ufffd", struct{ S string }{S: "\ufffd"}}},
		"MarshalJSON": rawJSONMarshaler{out: `"` + "\ufffd" + `"`},
		"MarshalText": rawTextMarshaler{out: "\ufffd"},
	}, "")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if len(encoded) != 5 {
		t.Fatalf("encoded = %#v", encoded)
	}
	if encoded["real"] != "\"\ufffd\"" {
		t.Fatalf("real = %q", encoded["real"])
	}
}

func TestEncodeMetadataKeepsInvalidUTF8TheEncoderNeverEmits(t *testing.T) {
	// Invalid UTF-8 that encoding/json does not write as a string cannot
	// change the value on the wire, so it is no reason to drop the key. Nor
	// may a marshaler the encoder would not call be called: it can fail or
	// panic on a value the encoder leaves out.
	lazy := struct {
		Lazy lazyJSONMarshaler `json:"lazy,omitzero"`
		N    int
	}{N: 1}
	cases := map[string]struct {
		value any
		want  string
	}{
		// []byte is encoded as base64.
		"bytes": {[]byte(invalidUTF8), `"//4="`},
		"skipped field": {struct {
			Name string `json:"-"`
			Kept int
		}{Name: invalidUTF8, Kept: 1}, `{"Kept":1}`},
		"unexported field": {struct {
			name string
			Kept int
		}{name: invalidUTF8, Kept: 1}, `{"Kept":1}`},
		// encoding/json omits a field promoted twice at one depth, and a
		// promoted field that a shallower one shadows.
		"conflicting promoted field": {conflictOuter{conflictA: conflictA{Name: invalidUTF8}}, `{}`},
		"shadowed promoted field": {
			shadowOuter{shadowInner: shadowInner{Name: invalidUTF8}, Name: "ok"},
			`{"Name":"ok"}`,
		},
		// The marshaler's output replaces the value, so its fields are never
		// encoded.
		"MarshalText":                     {hexTextMarshaler{raw: invalidUTF8}, `"fffe"`},
		"pointer MarshalJSON addressable": {&pointerJSONMarshaler{Raw: invalidUTF8}, `"redacted"`},
		"pointer MarshalJSON in slice":    {[]pointerJSONMarshaler{{Raw: invalidUTF8}}, `["redacted"]`},
		"nil marshaler":                   {(*rawJSONMarshaler)(nil), `null`},
		"nil embedded pointer":            {utf8OuterPtr{}, `{}`},
		"MarshalText key":                 {map[textKey]int{1: 1}, `{"key":1}`},
		// Fields the encoder omits, whose marshalers it never calls.
		"omitzero marshaler unsafe on zero": {lazy, `{"N":1}`},
		"omitzero marshaler erroring when unset": {struct {
			Region optionalJSON `json:"region,omitzero"`
		}{}, `{}`},
		"omitempty marshaler panicking when empty": {struct {
			Name nonEmptyJSON `json:"name,omitempty"`
			N    int
		}{N: 1}, `{"N":1}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, warnings := encodeMetadata(Metadata{"v": tc.value}, "")
			if len(warnings) != 0 {
				t.Fatalf("warnings = %#v", warnings)
			}
			if encoded["v"] != tc.want {
				t.Fatalf("encoded = %q, want %q", encoded["v"], tc.want)
			}
		})
	}
}

func TestEncodeMetadataStringKeyWithMarshalText(t *testing.T) {
	// The legacy encoder names a string-kinded key by the string itself, which
	// here is invalid, and json/v2 names it by its MarshalText. So the key is
	// dropped by one and kept as "key" by the other, but neither sends the
	// key with U+FFFD substituted.
	encoded, warnings := encodeMetadata(Metadata{
		"v": map[textStringKey]int{textStringKey(invalidUTF8): 1},
	}, "")
	dropped := len(encoded) == 0 && len(warnings) == 1
	kept := len(warnings) == 0 && encoded["v"] == `{"key":1}`
	if !dropped && !kept {
		t.Fatalf("encoded = %#v, warnings = %#v", encoded, warnings)
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

func TestSanitizeKeyEscapesQuotesAndBackslashes(t *testing.T) {
	// The key list wraps each name in double quotes, so a key containing one
	// could otherwise look like several keys.
	_, warnings := encodeMetadata(Metadata{`ev"il", "other`: make(chan int)}, "")
	if !strings.Contains(warnings[0].Message, "1 key(s)") {
		t.Fatalf("message = %q", warnings[0].Message)
	}
	// Only the two quotes the formatter itself added remain.
	if got := strings.Count(warnings[0].Message, `"`); got != 2 {
		t.Fatalf("quote count = %d in %q", got, warnings[0].Message)
	}
	if !strings.Contains(warnings[0].Message, `ev\x22il\x22, \x22other`) {
		t.Fatalf("message = %q", warnings[0].Message)
	}

	if got := sanitizeKey(`back\slash`); got != `back\x5cslash` {
		t.Fatalf("sanitizeKey = %q", got)
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

// Raw JSON can carry a UTF-16 surrogate escape that is not half of a pair,
// such as a string JavaScript cut inside an emoji. Every build drops it, and
// keeps a complete pair and text that only looks like an escape.
func TestEncodeMetadataRawSurrogateEscapesAgreeAcrossBuilds(t *testing.T) {
	for raw, wantKept := range map[string]bool{
		"\"\x5cud83d\x5cude00\"":      true,
		"\"\x5c\x5cud83d\"":           true,
		"\"\x5cud83d\"":               false,
		"\"\x5cude00\"":               false,
		"\"a\x5cud83dz\"":             false,
		"\"\x5cud83d\x5cud83d\"":      false,
		"\"\x5cud83d\x5cu0041\"":      false,
		"\"\x5c\x5c\x5cud83d\"":       false,
		"\"\x5cuD83D\"":               false,
		"{\"\x5cud83d\":1}":           false,
		"[\"ok\",\"\x5cud83d\x5cn\"]": false,
	} {
		t.Run(raw, func(t *testing.T) {
			encoded, warnings := encodeMetadata(Metadata{"k": json.RawMessage(raw)}, "")
			if kept := encoded["k"] != ""; kept != wantKept {
				t.Fatalf("kept = %v, want %v (encoded %q, warnings %#v)", kept, wantKept, encoded, warnings)
			}
		})
	}
}
