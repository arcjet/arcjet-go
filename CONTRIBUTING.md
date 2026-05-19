# Contributing to arcjet-go

This guide covers the local
development workflow.

## Layout

Two Go modules live in this repo:

- `./go.mod` — the published SDK. Keep its dep graph minimal; consumers see
  every entry in their own go.sum.
- `./tools/go.mod` — a side module that pins development tools (currently just
  `golangci-lint`) via Go's `tool` directive. Kept separate so linter
  transitives don't leak into consumer projects.

## Commands

All commands run from the repo root.

| Task | Command |
| --- | --- |
| Build | `go build ./...` |
| Test | `go test ./...` |
| Test (CI-equivalent) | `go test -race -shuffle=on ./...` |
| Lint | `go tool -modfile=tools/go.mod golangci-lint run ./...` |
| Auto-fix lint issues | `go tool -modfile=tools/go.mod golangci-lint run --fix ./...` |
| Format | `go tool -modfile=tools/go.mod golangci-lint fmt ./...` |
| Tidy modules | `go mod tidy && go -C tools mod tidy` |

`-modfile=tools/go.mod` tells `go tool` to resolve `golangci-lint` from the
tools module while keeping the working directory at the repo root, so `./...`
matches the SDK code (not the tools module).

## Linting policy

Configured in [`.golangci.yml`](.golangci.yml). Two things worth knowing:

- **`new-from-rev: origin/main`** — only issues introduced by your branch are
  reported. Make sure `origin/main` is fetched locally (`git fetch origin
  main`) before running the linter, or you'll see the full baseline.
- **Comprehensive linter set** with per-linter rationale comments. If a check
  is wrong for a specific file, prefer a narrow `//nolint:<linter> // reason`
  over disabling the linter globally.

## Bumping pinned tool versions

```sh
cd tools
go get -tool github.com/golangci/golangci-lint/v2/cmd/golangci-lint@vX.Y.Z
go mod tidy
```

Commit `tools/go.mod` and `tools/go.sum`. CI picks the version up automatically
on the next run — there's no separate version file to keep in sync.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every PR, push
to `main`, and in the merge queue:

- **Lint** (arm64) — verifies `go.mod` / `tools/go.mod` are tidy, then runs
  golangci-lint.
- **Test** (arm64 + amd64 matrix) — `go build ./...` and `go test -race
  -shuffle=on ./...`.

Both jobs use the Go version from `go.mod` via `setup-go`'s
`go-version-file`. Action versions are pinned by commit SHA and the runner is
locked down with `step-security/harden-runner` in egress-block mode.
