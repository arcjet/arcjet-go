//go:build go1.27 && goexperiment.jsonv2

package arcjet

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

// marshalJSON encodes value with encoding/json's semantics on the json/v2
// implementation, the default from Go 1.27.
//
// Those semantics accept invalid UTF-8 and write each invalid byte as a
// literal U+FFFD, the same as a genuine one, so the output can no longer tell
// the two apart. AllowInvalidUTF8(false) makes the encoder refuse the value
// instead, wherever it meets the string: a Go string, a map key, or the output
// of MarshalJSON, MarshalText or AppendText. Checking the encoder's own work
// rather than walking the value means omitted, shadowed and conflicting fields,
// and methods the encoder would not call, are exactly as it treats them. Every
// other option is what json.NewEncoder with SetEscapeHTML(false) uses, so a
// valid value encodes to the same bytes.
//
// metadata_jsonv2_experiment.go is the same function for GOEXPERIMENT=jsonv2
// on Go 1.25 and 1.26. It is a separate file because go.mod's go line is 1.25,
// and a Go 1.27 toolchain refuses the json/v2 API in a file of that version
// unless its build constraint requires go1.27.
func marshalJSON(value any) (string, error) {
	out, err := jsonv2.Marshal(value,
		json.DefaultOptionsV1(),
		jsontext.EscapeForHTML(false),
		jsontext.AllowInvalidUTF8(false),
	)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
