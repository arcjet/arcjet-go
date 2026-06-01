# Developer tasks for arcjet-go.
#
# These mirror the CI gate in .github/workflows/ci.yml so you can verify changes
# locally before pushing a branch or opening a PR. Run `just check` for the full
# gate.
#
# golangci-lint (and its formatters) is pinned in tools/go.mod via the `tool`
# directive. `go tool -modfile=tools/go.mod` runs that pinned version, while
# `./...` still resolves against the main module at the repo root.

golangci := "go tool -modfile=tools/go.mod golangci-lint"

# List available tasks.
default:
    @just --list

# Full CI-equivalent gate (tidy + lint + build + test); run before pushing.
check: tidy-check lint build test

# Auto-fix formatting (goimports import grouping, etc.).
format:
    {{ golangci }} fmt

# Lint with golangci-lint; also fails on unformatted code (matches CI Lint job).
lint:
    {{ golangci }} run ./...

# Lint and auto-apply fixes where the linters support it.
lint-fix:
    {{ golangci }} run --fix ./...

# Build all packages (matches the CI build step).
build:
    go build ./...

# Run tests the way CI does (race detector on, test order shuffled).
test:
    go test -race -shuffle=on ./...

# Tidy the main module and the tools module.
tidy:
    go mod tidy
    go -C tools mod tidy

# Verify go.mod / go.sum are tidy (matches the CI tidy gate); fails if not.
tidy-check:
    #!/usr/bin/env bash
    set -euo pipefail
    go mod tidy
    go -C tools mod tidy
    if [[ -n "$(git status --porcelain go.mod go.sum tools/go.mod tools/go.sum)" ]]; then
      echo "error: go.mod / go.sum are not tidy. Run 'just tidy' and commit the changes." >&2
      git --no-pager diff -- go.mod go.sum tools/go.mod tools/go.sum
      exit 1
    fi
