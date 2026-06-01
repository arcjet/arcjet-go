package arcjet

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// vendoredWasmModules are the gravity-input wasm modules vendored in this repo.
// They must retain their wit-bindgen "component-type" custom section: gravity
// reads the component's world from that section to regenerate the Go bindings
// (internal/local/*/bindings.go), so self-contained regeneration depends on it.
//
// rebuild-bindings.sh once stripped this section by writing gravity's output
// next to its input, overwriting the WIT-bearing module with a stripped core
// module. This test fails if that footgun (or anything else) strips the section
// again. See internal/local/rebuild-bindings.sh.
var vendoredWasmModules = []string{
	"internal/local/jsreq/js_req.wasm",
	"internal/local/redact/redact.wasm",
}

func TestVendoredWasmRetainsComponentTypeSection(t *testing.T) {
	for _, path := range vendoredWasmModules {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if !hasComponentTypeSection(t, data) {
				t.Errorf("%s has no wit-bindgen \"component-type\" custom section — it "+
					"looks stripped. gravity can no longer read its world, so `just wasm` "+
					"regeneration will fail with \"unable to find world\". Restore the "+
					"WIT-bearing module (see internal/local/rebuild-bindings.sh).", path)
			}
		})
	}
}

// hasComponentTypeSection reports whether the wasm module carries a custom
// section (section id 0) whose name starts with "component-type" — the
// wit-bindgen encoded world. It walks only the top-level section framing, which
// is all that is needed to inspect custom-section names.
func hasComponentTypeSection(t *testing.T, data []byte) bool {
	t.Helper()
	if len(data) < 8 || string(data[:4]) != "\x00asm" {
		t.Fatalf("not a wasm module (bad magic header)")
	}
	for i := 8; i < len(data); {
		id := data[i]
		i++
		size, n := binary.Uvarint(data[i:])
		if n <= 0 {
			t.Fatalf("malformed section length at offset %d", i)
		}
		i += n
		end := i + int(size)
		if end > len(data) {
			t.Fatalf("section length %d overruns module of %d bytes", size, len(data))
		}
		if id == 0 { // custom section: payload begins with a name vector (len + bytes)
			payload := data[i:end]
			nameLen, m := binary.Uvarint(payload)
			if m > 0 && m+int(nameLen) <= len(payload) {
				if strings.HasPrefix(string(payload[m:m+int(nameLen)]), "component-type") {
					return true
				}
			}
		}
		i = end
	}
	return false
}
