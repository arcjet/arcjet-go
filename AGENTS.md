# arcjet-go Agent Guide

This is the Go SDK for [Arcjet](https://arcjet.com), the runtime security
platform. `arcjet.NewClient` provides request protection for `net/http`
handlers; `arcjet.NewGuardClient` provides guard protection for non-HTTP code
paths (AI agent tool calls, MCP servers, background jobs, queue workers).

This is a **public, pre-release** module. Treat its exported API as a contract:
prefer additive changes and call out any breaking change explicitly.

## Validation — run `just` before pushing

Before pushing a branch or opening a PR, run the relevant `just` tasks and make
them pass locally. Do not leave validation for CI. The tasks mirror the CI gate
in `.github/workflows/ci.yml`.

| Need                         | Command           |
| ---------------------------- | ----------------- |
| Full CI-equivalent gate      | `just check`      |
| Lint (and format check)      | `just lint`       |
| Auto-fix formatting          | `just format`     |
| Lint with auto-fixes applied | `just lint-fix`   |
| Build                        | `just build`      |
| Tests (race + shuffle)       | `just test`       |
| Tidy go.mod / tools/go.mod   | `just tidy`       |
| Verify modules are tidy      | `just tidy-check` |

Run `just` (or `just default`) to list all tasks.

- For most changes, `just check` is the single command to run before pushing —
  it runs tidy-check, lint, build, and tests, exactly what CI enforces.
- During development, run the narrowest relevant task first (e.g. `just lint`
  or `just test`), then `just check` before pushing.
- `just lint` also fails on unformatted code (goimports import grouping). Run
  `just format` to fix formatting automatically rather than hand-editing
  imports.

## Notes

- `golangci-lint` is pinned in `tools/go.mod` via the `tool` directive; the
  `just` tasks invoke it through `go tool -modfile=tools/go.mod`, so there is
  nothing extra to install beyond the Go toolchain and `just`.
- `golangci-lint` skips files marked `// Code generated ... DO NOT EDIT`. If you
  convert a generated file to hand-maintained, it must then satisfy the full
  linter (`just lint`).
- The vendored decide proto under `internal/proto/decide/...` is generated from
  the `arcjet` monorepo's `make -C proto build-go`. It is intentionally
  namespaced (`arcjet.sdk.decide.*`) to avoid a protobuf global-registry
  collision when linked beside the monorepo's canonical decide proto; the
  Connect wire route is pinned by hand in the `*connect` packages. Do not
  hand-edit the `*.pb.go` files.
