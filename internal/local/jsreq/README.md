# `internal/local/jsreq`

Go host bindings for the `arcjet_analyze_js_req` WebAssembly component —
the same `js-req` world that arcjet-js (`@arcjet/analyze-wasm`) and
arcjet-py (`arcjet._analyze`) consume, so all three SDKs make identical
local decisions for bot detection, email validation, request filtering,
and sensitive-info detection.

## Regenerating

`bindings.go` is generated from `js_req.wasm`; only `imports.go` and this
README are hand-maintained. `js_req.wasm` retains its `component-type` WIT
custom section, so gravity reads the `js-req` world straight from the vendored
module — **regenerating needs no arcjet monorepo checkout**.

From the repo root (after `mise install` for the pinned gravity — see the
top-level `mise.toml`):

```sh
./internal/local/rebuild-bindings.sh
```

To pull a newer wasm build from a local arcjet monorepo checkout first, then
regenerate:

```sh
./internal/local/rebuild-bindings.sh --from-monorepo [path-to-arcjet]
```

The script runs `gravity --world js-req` and renames the emitted package from
`js_req` to `jsreq`.

`js_req.wasm` is the post-wizer, pre-component core module from
`arcjet-analyze/bindings_js_req/dist/arcjet_analyze_js_req.wasm`. wazero speaks
core wasm rather than the Component Model, and the `wizer.initialize` snapshot
is load-bearing — without it, bot detection returns `"failed to detect bot:
user agent parser unavailable"` because `USER_AGENT_PARSER` is populated during
init. The retained component-type WIT section adds ~2 KB and is ignored by
wazero at runtime.
