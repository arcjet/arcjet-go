# Contributing to arcjet-go

External pull requests are disabled on this repo; contributions must be made via
forks. Please open an issue to discuss any significant changes before
implementing them.

This guide covers the local development workflow.

## Layout

Six Go modules live in this repo:

- `./go.mod` — the published SDK. Keep its dep graph minimal; consumers see
  every entry in their own go.sum.
- `./sensitiveinfo/rampart/go.mod` — the optional on-device Rampart backend.
  This is released in lockstep with the SDK, but remains a separate module so
  its ~15 MB embedded model does not ship to applications that do not use it.
- `./agentframework/go.mod` — integrates Arcjet Guard with Microsoft Agent
  Framework for Go. It stays a separate module because that framework is a
  public preview whose API may change, and because it needs a newer Go
  version than the root module.
- `./tools/go.mod` — a side module that pins development tools via Go's `tool`
  directive. Kept separate so tool transitives don't leak into consumer
  projects.
- `./examples/nethttp/go.mod` — the runnable example server. Its local
  `replace` directives make it exercise the working tree.
- `./examples/agentframework/go.mod` — the runnable Microsoft Agent Framework
  example. Its local `replace` directives make it exercise both the SDK and
  the agentframework module in the working tree.

## Commands

All commands run from the repo root.

| Task | Command |
| --- | --- |
| Build | `go build ./...` |
| Test | `go test ./...` |
| Test (CI-equivalent) | `go test -race -shuffle=on ./...` |
| Benchmark | `go test -run=^$ -bench=. -benchmem ./...` |
| Lint | `go tool -modfile=tools/go.mod golangci-lint run ./...` |
| Auto-fix lint issues | `go tool -modfile=tools/go.mod golangci-lint run --fix ./...` |
| Format | `go tool -modfile=tools/go.mod golangci-lint fmt ./...` |
| Check vulnerabilities | `just vuln` |
| Tidy modules | `just tidy` |

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

## Benchmarks

Benchmarks live alongside the code they exercise (`client_bench_test.go`,
`guard_bench_test.go`, `cache_bench_test.go`) and cover the public hot paths:
`Client.Protect` / `Client.ProtectDetails` (cache hit, cache miss, local
Wasm-deny), `Client.WithRule`, `DetailsFromRequest`, `GuardClient.Guard`,
Guard rule input binding, and the cache and hashing primitives shared by
both clients. All Connect RPCs are served in-process via `handlerTransport`,
so the benchmarks make no network calls and are safe to run anywhere.

- Run everything: `go test -run=^$ -bench=. -benchmem ./...`. The `-run=^$`
  skips ordinary tests so only `Benchmark*` functions execute; `-benchmem`
  prints allocations per op alongside ns/op.
- Run one: `go test -run=^$ -bench=BenchmarkProtect$ -benchmem` (anchor
  with `$` to avoid matching `BenchmarkProtectDetails*`).
- Compare two revisions: install `benchstat`
  (`go install golang.org/x/perf/cmd/benchstat@latest`), capture
  `-count=10 -benchtime=2s` output before and after your change, then
  diff with `benchstat before.txt after.txt`. Single runs are noisy —
  always use `benchstat` for any conclusion you want to act on.

When adding a benchmark, call `b.ReportAllocs()` and keep the setup outside
the timed loop with `b.ResetTimer()`. The benchmarks here are also
implicit smoke tests of the in-process Connect wiring, so they need to
keep passing in CI even though CI does not run them.

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

- **Lint** (arm64, Go 1.26) — verifies `go.mod` / `tools/go.mod` are tidy,
  then runs golangci-lint and `govulncheck` for the SDK and Rampart backend.
- **Test** (arm64 + amd64, each on Go 1.25 and Go 1.27) — `go build ./...`
  and `go test -race -shuffle=on ./...`. The Go 1.25 legs are named
  `Test (<os>)` and the Go 1.27 legs `Test (<os>, Go 1.27.x)`.
- **agentframework module** (arm64, Go 1.26) — verifies
  `agentframework/go.mod` is tidy, then runs golangci-lint, `govulncheck`,
  build, and race tests.

The Go 1.25 Test legs use the latest security-patched Go 1.25 release while
`go.mod` keeps the public compatibility floor at Go 1.25.0. The Lint job uses
the latest security-patched Go 1.26 release: `tools/go.mod` requires Go 1.26.0
(golangci-lint and `govulncheck` are development tools, not part of the SDK's
compatibility floor), and `govulncheck` then checks the patched standard
library. Lint does not move to Go 1.27: the pinned golangci-lint panics inside
staticcheck on the Go 1.27 standard library. The Go 1.27 Test legs use the
latest Go 1.27 release, because Go 1.27 runs `encoding/json` on json/v2 and the
SDK builds a different metadata encoder there (`metadata_jsonv2.go`). The
agentframework job uses the latest security-patched Go 1.26 release to match
`agentframework/go.mod`'s floor of Go 1.26.0. Action versions are pinned by
commit SHA and the runner is locked down with `step-security/harden-runner`
in egress-block mode.

Changes under `.github/workflows/` also run
[`.github/workflows/lint-workflows.yml`](.github/workflows/lint-workflows.yml),
which gates on `actionlint` and medium-or-higher `zizmor` findings. Run
`just lint-workflows` for the same checks locally; it needs
[uv](https://docs.astral.sh/uv/) for `zizmor`.

## Releasing

The SDK and optional Rampart backend are released from the same commit at the
same version. Rampart is not a standalone SDK: its separate Go module only
keeps the embedded model out of core SDK downloads. It therefore gets the
module-qualified tag Go requires, but not a separate GitHub release.

See the Go modules reference on
[mapping versions to commits](https://go.dev/ref/mod#vcs-version) for why a
module in a repository subdirectory needs that subdirectory in its tag.

Root releases are prepared by
[Release Please](https://github.com/googleapis/release-please), so commit
messages on `main` must be
[conventional commits](https://www.conventionalcommits.org/): `feat` makes a
minor release, `fix`, `deps` and the other types a patch release, and `!` or a
`BREAKING CHANGE` footer a major one.

1. Release Please keeps a release PR open against `main`. It bumps `Version` in
   `types.go`, the SDK requirement in `sensitiveinfo/rampart/go.mod`, both SDK
   requirements in `examples/nethttp/go.mod`, and the `arcjet-go` requirement
   in `examples/agentframework/go.mod` (the lines marked
   `x-release-please-version`), and writes `CHANGELOG.md`. It leaves the local
   `replace` directives and `examples/agentframework/go.mod`'s
   `agentframework` requirement alone; the latter moves only with an
   agentframework release.
2. Review the exported API changes since the previous release. Once v1 is
   published, incompatible API changes require a new major module version.
3. Merge the release PR once CI passes. Merging publishes nothing.
4. Run the [Release tags workflow](.github/workflows/release.yml) from `main`.
   Its preflight infers the version from `types.go`, verifies every lockstep
   version, and runs the release checks.
5. Someone other than you reviews the preflight summary and approves the
   protected `release-tags` environment. The gated job pushes every tag
   atomically with the release GitHub App, creates the GitHub release from the
   changelog, and marks the release PR `autorelease: tagged`. The
   [release automation runbook](docs/RELEASING.md) covers the one-time
   configuration and dry runs.
6. The tag push starts the Verify published modules workflow. Wait for it,
   then follow [After tagging](docs/RELEASING.md#after-tagging) in the runbook
   for the smoke test. Do not request the new versions from the Go module proxy
   before that workflow passes: the proxy caches a failed fetch for up to 30
   minutes, so an early request blocks the release for that long.

The `agentframework` module keeps its own `v0.x` version line because it
tracks a preview framework, but the workflow tags it in the same run as the
root module and from the same commit, so the SDK version it requires is
published alongside it. Release Please does not version it. To include it in
a release, merge a PR before the release PR that:

- sets `Version` in `agentframework/version.go` to the agentframework release
  version, without the leading `v`;
- sets the `arcjet-go` requirement in `agentframework/go.mod` to the root
  version in the open release PR;
- sets the `agentframework` requirement in `examples/agentframework/go.mod` to
  the agentframework release version.

Then merge the release PR and run the Release tags workflow with
**components** set to `root-and-agentframework`. Its preflight refuses the
release if those three disagree with each other or with `types.go`.
