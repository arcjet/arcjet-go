//go:build goexperiment.jsonv2

package arcjet

import "testing"

// appendOnlyText implements only encoding.TextAppender, which json/v2 calls
// and the legacy encoder does not know.
type appendOnlyText struct{ raw string }

func (a appendOnlyText) AppendText(b []byte) ([]byte, error) { return append(b, a.raw...), nil }

// appendAndMarshalText returns different text from its two methods. json/v2
// calls AppendText.
type appendAndMarshalText struct{ raw string }

func (a appendAndMarshalText) AppendText(b []byte) ([]byte, error) {
	return append(b, a.raw...), nil
}

func (appendAndMarshalText) MarshalText() ([]byte, error) { return []byte("ok"), nil }

func TestEncodeMetadataJSONv2DropsInvalidUTF8(t *testing.T) {
	// Values only json/v2 writes with invalid UTF-8 replaced. The legacy
	// encoder does not call AppendText, and it escapes a ",string" field's
	// \ufffd a second time, which hides it (see metadata_json.go).
	cases := map[string]any{
		"AppendText":                  appendOnlyText{raw: invalidUTF8},
		"AppendText nested":           map[string]any{"k": appendOnlyText{raw: invalidUTF8}},
		"AppendText over MarshalText": appendAndMarshalText{raw: invalidUTF8},
		"string option": struct {
			Name string `json:",string"`
		}{Name: invalidUTF8},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			assertDropsKey(t, value)
		})
	}
}

func TestEncodeMetadataJSONv2KeepsEscapedReplacementCharacter(t *testing.T) {
	// A MarshalJSON may write a genuine U+FFFD as the escape \ufffd. The
	// legacy encoder cannot tell that from one it substituted, so it drops the
	// key (see metadata_json.go); json/v2 refuses only invalid UTF-8.
	encoded, warnings := encodeMetadata(Metadata{
		"v": rawJSONMarshaler{out: `"\ufffd"`},
	}, "")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if encoded["v"] != `"\ufffd"` {
		t.Fatalf("encoded = %q", encoded["v"])
	}
}
