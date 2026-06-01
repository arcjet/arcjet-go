# `internal/local/redact`

Go host bindings for the `arcjet:redact` WebAssembly component — the same
`redact` world that arcjet-js (`@arcjet/redact-wasm`) and arcjet-py consume,
so all three SDKs redact sensitive information identically. The public
`github.com/arcjet/arcjet-go/redact` package wraps these bindings.

## Regenerating

`bindings.go` is generated from `redact.wasm`; only `imports.go` and this
README are hand-maintained. `redact.wasm` retains its `component-type` WIT
custom section, so gravity reads the `redact` world straight from the vendored
module — **regenerating needs no arcjet monorepo checkout**.

From the repo root (after `mise install` — see the top-level `mise.toml`):

```sh
./internal/local/rebuild-bindings.sh
```

To pull a newer wasm build from a local arcjet monorepo checkout first, then
regenerate:

```sh
./internal/local/rebuild-bindings.sh --from-monorepo [path-to-arcjet]
```

The `redact` world maps directly to `package redact`, so no package rename is
needed (unlike `jsreq`).

### Notes

- **No wizer.** Unlike `bindings_js_req`, the redact component has no
  initialization snapshot to bake in, so the post-`cargo build` core module is
  fed straight to wazero. `redact.wasm` is the core module from
  `arcjet-analyze/bindings_redact/dist/arcjet_analyze_bindings_redact.wasm`
  (not the `.component.wasm`). The retained component-type WIT section adds
  <1 KB and is ignored by wazero at runtime.
- **gravity version.** Generating this world needs a gravity that implements
  the `list<option<sensitive-info-entity>>` import-chain return type (gravity
  issue #9). The pinned `26c61be9` ref panics with
  `TODO(#9): handle return type - Slice(ValueOrOk(Interface))`; the pin in the
  top-level `mise.toml` (`fe2e11f`, "support variants, options, enum lift") has
  it.
- `imports.go` adapts the public detect/replace callbacks to the generated
  `IRedactCustomRedact` interface and applies fail-open defaults. The custom
  detect callback must return exactly one slot per input token — the component
  zips the result against the token window, silently dropping any tail.
