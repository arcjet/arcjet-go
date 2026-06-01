#!/usr/bin/env bash
#
# Rebuilds the gravity-generated Go bindings for the local wasm rules.
#
# By default it regenerates from the WebAssembly modules already vendored in
# this repo (internal/local/{jsreq,redact}/*.wasm). Those modules retain their
# `component-type` WIT custom section, so gravity reads the world straight from
# them — no arcjet monorepo checkout required:
#
#     ./internal/local/rebuild-bindings.sh
#
# Pass --from-monorepo to first refresh the vendored wasm from a local arcjet
# monorepo checkout (the only step that needs the monorepo). The path defaults
# to ../arcjet, or $ARCJET_MONOREPO, or the optional second argument:
#
#     ./internal/local/rebuild-bindings.sh --from-monorepo [path-to-arcjet]
#
# gravity is pinned in mise.toml; run `mise install` first (or install it with
# `cargo install --git https://github.com/arcjet/gravity \
#   --rev fe2e11f39ae0e48526f6c584783fcdfe0e0f25cc --locked`).
set -euo pipefail

cd "$(dirname "$0")/../.." # repo root

monorepo="${ARCJET_MONOREPO:-../arcjet}"
sync=0
if [ "${1:-}" = "--from-monorepo" ]; then
	sync=1
	[ -n "${2:-}" ] && monorepo="$2"
fi

# Prefer the mise-pinned gravity; fall back to one on PATH.
gravity=(gravity)
if command -v mise >/dev/null 2>&1; then
	gravity=(mise exec -- gravity)
fi
if ! "${gravity[@]}" --version >/dev/null 2>&1; then
	echo "error: gravity not found. Run 'mise install' (see mise.toml) or install it with" >&2
	echo "  cargo install --git https://github.com/arcjet/gravity --rev fe2e11f39ae0e48526f6c584783fcdfe0e0f25cc --locked" >&2
	exit 1
fi

if [ "$sync" -eq 1 ]; then
	echo ">> Refreshing vendored wasm from $monorepo"
	cp "$monorepo/arcjet-analyze/bindings_js_req/dist/arcjet_analyze_js_req.wasm" \
		internal/local/jsreq/js_req.wasm
	cp "$monorepo/arcjet-analyze/bindings_redact/dist/arcjet_analyze_bindings_redact.wasm" \
		internal/local/redact/redact.wasm
fi

echo ">> Generating internal/local/jsreq/bindings.go"
"${gravity[@]}" --world js-req --output internal/local/jsreq/bindings.go internal/local/jsreq/js_req.wasm
# gravity emits `package js_req`; the Go-idiomatic short form is `jsreq`.
sed -i.bak '1,5 s/^package js_req$/package jsreq/' internal/local/jsreq/bindings.go
rm -f internal/local/jsreq/bindings.go.bak

echo ">> Generating internal/local/redact/bindings.go"
"${gravity[@]}" --world redact --output internal/local/redact/bindings.go internal/local/redact/redact.wasm

echo ">> Verifying build"
go build ./...

echo ">> Done. Review 'git diff' on the generated bindings."
