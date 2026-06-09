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
	# The monorepo builds js_req in two variants (see its bindings_js_req
	# Makefile + the drop-wizer ADR): a no-Wizer variant for arcjet-js, and a
	# Wizer'd variant for arcjet-py/arcjet-go. We use the Wizer'd core so the
	# UserAgentParser stays pre-initialized (no per-request build cost; size is
	# not a constraint for an embedded Go binary).
	cp "$monorepo/arcjet-analyze/bindings_js_req/dist/arcjet_analyze_js_req.wizer.wasm" \
		internal/local/jsreq/js_req.wasm
	cp "$monorepo/arcjet-analyze/bindings_redact/dist/arcjet_analyze_bindings_redact.wasm" \
		internal/local/redact/redact.wasm
fi

# gravity writes bindings.go AND a companion (stripped) core wasm into the
# output file's directory. Generate into a temp dir and copy back only
# bindings.go, so the vendored *.wasm keep their `component-type` WIT custom
# section. That section is what lets gravity read the world straight from the
# vendored module — i.e. what makes regeneration self-contained. Writing
# gravity's output next to the vendored wasm would overwrite it with the
# stripped copy and break the next regeneration ("unable to find world").
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/jsreq" "$tmp/redact"

echo ">> Generating internal/local/jsreq/bindings.go"
"${gravity[@]}" --world js-req --output "$tmp/jsreq/bindings.go" internal/local/jsreq/js_req.wasm
# gravity emits `package js_req`; the Go-idiomatic short form is `jsreq`.
sed -i.bak '1,5 s/^package js_req$/package jsreq/' "$tmp/jsreq/bindings.go"
rm -f "$tmp/jsreq/bindings.go.bak"
cp "$tmp/jsreq/bindings.go" internal/local/jsreq/bindings.go

echo ">> Generating internal/local/redact/bindings.go"
"${gravity[@]}" --world redact --output "$tmp/redact/bindings.go" internal/local/redact/redact.wasm
cp "$tmp/redact/bindings.go" internal/local/redact/bindings.go

echo ">> Verifying build"
go build ./...

echo ">> Done. Review 'git diff' on the generated bindings."
