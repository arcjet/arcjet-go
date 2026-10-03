//go:build !goexperiment.jsonv2

package arcjet

import "testing"

func TestEncoderEscapesInvalidUTF8OnTheLegacyEncoder(t *testing.T) {
	if !encoderEscapesInvalidUTF8 {
		t.Fatal("the legacy encoder no longer writes an invalid byte as an escape")
	}
}

// Built against an encoder that writes invalid bytes as a literal U+FFFD, the
// legacy check cannot tell substituted bytes from a genuine U+FFFD, so it
// refuses both rather than sending substituted bytes as the value.
func TestEncodeMetadataRefusesEveryReplacementCharacterWithoutTheEscapeSignal(t *testing.T) {
	encoderEscapesInvalidUTF8 = false
	t.Cleanup(func() { encoderEscapesInvalidUTF8 = true })

	encoded, warnings := encodeMetadata(Metadata{"real": "\xef\xbf\xbd", "ok": "fine"}, "")
	if len(encoded) != 1 || encoded["ok"] != `"fine"` {
		t.Fatalf("encoded = %#v", encoded)
	}
	if len(warnings) != 1 || warnings[0].Code != MetadataEncodeFailedCode {
		t.Fatalf("warnings = %#v", warnings)
	}
}
