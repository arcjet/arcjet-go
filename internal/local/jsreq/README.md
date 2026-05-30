# `internal/local/jsreq`

Go host bindings for the `arcjet_analyze_js_req` WebAssembly component —
the same `js-req` world that arcjet-js (`@arcjet/analyze-wasm`) and
arcjet-py (`arcjet._analyze`) consume, so all three SDKs make identical
local decisions for bot detection, email validation, request filtering,
and sensitive-info detection.

## Regenerating

Three artefacts in this directory are derived; only `imports.go` and this
README are hand-maintained.

| File | Source |
|---|---|
| `js_req.wasm` | `arcjet/arcjet-analyze/bindings_js_req/dist/arcjet_analyze_js_req.wasm` (post-wizer, pre-component) |
| `bindings.go` | `gravity --world js-req --output bindings.go js_req.wasm`, then `s/^package js_req$/package jsreq/` on the first 5 lines |

To regenerate from a clean arcjet-analyze checkout:

```sh
cd ../arcjet/arcjet-analyze/bindings_js_req
make build-wasm          # cargo build + wizer + wasm-opt + wasm-tools component new

# back here:
cp ../arcjet/arcjet-analyze/bindings_js_req/dist/arcjet_analyze_js_req.wasm \
  internal/local/jsreq/js_req.wasm
gravity --world js-req --output internal/local/jsreq/bindings.go \
  internal/local/jsreq/js_req.wasm
sed -i '1,5 s/^package js_req$/package jsreq/' internal/local/jsreq/bindings.go
```

The wizered (but pre-`wasm-tools component new`) wasm is the right input
for wazero, which speaks core wasm rather than the Component Model. The
`wizer.initialize` snapshot is load-bearing — without it, bot detection
returns `"failed to detect bot: user agent parser unavailable"` because
`USER_AGENT_PARSER` only gets populated during init.
