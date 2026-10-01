//go:build !go1.27 && goexperiment.jsonv2

package arcjet

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

// marshalJSON is marshalJSON in metadata_jsonv2.go, for Go 1.25 and 1.26
// built with GOEXPERIMENT=jsonv2, where encoding/json also runs on json/v2.
func marshalJSON(value any) (string, error) {
	out, err := jsonv2.Marshal(value,
		json.DefaultOptionsV1(), //nolint:govet // stdversion: Go 1.27 API, present in 1.25 and 1.26 under GOEXPERIMENT=jsonv2
		jsontext.EscapeForHTML(false),
		jsontext.AllowInvalidUTF8(false),
	)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
