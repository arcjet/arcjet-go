# `internal/local/redact`

Go host bindings for the `arcjet:redact` WebAssembly component — the same
`redact` world that arcjet-js (`@arcjet/redact-wasm`) and arcjet-py consume,
so all three SDKs redact sensitive information identically. The public
`github.com/arcjet/arcjet-go/redact` package wraps these bindings.

## Regenerating

Two artefacts in this directory are derived; only `imports.go` and this
README are hand-maintained.

| File | Source |
|---|---|
| `redact.wasm` | `arcjet/arcjet-analyze/bindings_redact/dist/arcjet_analyze_bindings_redact.wasm` (the core module, **not** the `.component.wasm`) |
| `bindings.go` | `gravity --world redact --output bindings.go redact.wasm` |

To regenerate from a clean arcjet-analyze checkout:

```sh
cd ../arcjet/arcjet-analyze/bindings_redact
make build-wasm          # cargo build (wasm32-unknown-unknown) + wasm-tools component new

# back here:
cp ../arcjet/arcjet-analyze/bindings_redact/dist/arcjet_analyze_bindings_redact.wasm \
  internal/local/redact/redact.wasm
gravity --world redact --output internal/local/redact/bindings.go \
  internal/local/redact/redact.wasm
```

The world is `redact`, so gravity emits `package redact` directly — no
package rename step is needed (unlike `jsreq`).

### Notes

- **No wizer.** Unlike `bindings_js_req`, the redact component has no
  initialization snapshot to bake in, so the post-`cargo build` core module
  is fed straight to wazero. wazero speaks core wasm, so we embed the core
  module, not the `*.component.wasm` produced by `wasm-tools component new`.
- **gravity version.** Generating this world needs a gravity that implements
  the `list<option<sensitive-info-entity>>` import-chain return type (gravity
  issue #9). The pinned `26c61be9` ref panics with
  `TODO(#9): handle return type - Slice(ValueOrOk(Interface))`; build from
  `8601f51` ("support variants, options, enum lift") or newer.
- `imports.go` adapts the public detect/replace callbacks to the generated
  `IRedactCustomRedact` interface and applies fail-open defaults. The custom
  detect callback must return exactly one slot per input token — the component
  zips the result against the token window, silently dropping any tail.
