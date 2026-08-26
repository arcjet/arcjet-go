# Contributing to arcjet-go

External pull requests are disabled on this repo; contributions must be made via
forks. Please open an issue to discuss any significant changes before
implementing them.

This guide covers the local development workflow.

## Layout

Four Go modules live in this repo:

- `./go.mod` — the published SDK. Keep its dep graph minimal; consumers see
  every entry in their own go.sum.
- `./sensitiveinfo/rampart/go.mod` — the optional on-device Rampart backend.
  This is released in lockstep with the SDK, but remains a separate module so
  its ~15 MB embedded model does not ship to applications that do not use it.
- `./tools/go.mod` — a side module that pins development tools via Go's `tool`
  directive. Kept separate so tool transitives don't leak into consumer
  projects.
- `./examples/nethttp/go.mod` — the runnable example server. Its local
  `replace` directives make it exercise the working tree.

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

- **Lint** (arm64) — verifies `go.mod` / `tools/go.mod` are tidy, then runs
  golangci-lint and `govulncheck` for the SDK and Rampart backend.
- **Test** (arm64 + amd64 matrix) — `go build ./...` and `go test -race
  -shuffle=on ./...`.

Both jobs use the latest security-patched Go 1.25 release while `go.mod` keeps
the public compatibility floor at Go 1.25.0. Action versions are pinned by
commit SHA and the runner is locked down with `step-security/harden-runner` in
egress-block mode.

## Releasing

The SDK and optional Rampart backend are released from the same commit at the
same version. Rampart is not a standalone SDK: its separate Go module only
keeps the embedded model out of core SDK downloads. It therefore gets the
module-qualified tag Go requires, but not a separate GitHub release.

See the Go modules reference on
[mapping versions to commits](https://go.dev/ref/mod#vcs-version) for why a
module in a repository subdirectory needs that subdirectory in its tag.

1. Create a release branch from an up-to-date `main`.
2. Set `Version` in `types.go` to the release version without the leading `v`.
3. Update the SDK requirement in `sensitiveinfo/rampart/go.mod` and both SDK
   requirements in `examples/nethttp/go.mod` to `v<version>`. Keep the local
   `replace` directives; downstream consumers ignore them.
4. Run `just tidy`, then `just check` and
   `go -C examples/nethttp test ./...`. `just check` includes lint, race tests,
   and reachable-vulnerability checks for both published modules.
5. Review the exported API changes since the previous release. Once v1 is
   published, incompatible API changes require a new major module version.
6. Merge the release PR to `main`, then create both annotated tags on the exact
   merge commit. The suffix of both tags must match `Version` exactly, including
   any prerelease suffix. For example, for version `1.2.3`:

   ```sh
   git tag -a v1.2.3 -m v1.2.3
   git tag -a sensitiveinfo/rampart/v1.2.3 \
     -m sensitiveinfo/rampart/v1.2.3
   ```

7. Push the root tag first, followed by the optional backend tag:

   ```sh
   git push origin v1.2.3
   git push origin sensitiveinfo/rampart/v1.2.3
   ```

8. Verify the public module graph from a fresh temporary module. Do not add
   local `replace` directives to this smoke test:

   ```sh
   SMOKE_DIR="$(mktemp -d)"
   cd "$SMOKE_DIR"
   go mod init example.com/arcjet-release-smoke
   GOPROXY=https://proxy.golang.org go get \
     github.com/arcjet/arcjet-go@v1.2.3 \
     github.com/arcjet/arcjet-go/sensitiveinfo/rampart@v1.2.3
   go mod download all
   ```

9. Create one GitHub release for the root tag. Mention that the optional Rampart
   backend was released in lockstep; do not create a second GitHub release for
   its module-qualified tag.
