# Contributing to arcjet-go

External pull requests are disabled on this repo; contributions must be made via
forks. Please open an issue to discuss any significant changes before
implementing them.

This guide covers the local development workflow.

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
| Benchmark | `go test -run=^$ -bench=. -benchmem ./...` |
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

## Releasing

Releasing is two reviewed steps: **merge the release PR**, then **approve the
release deployment**. The tag is the published artifact for a Go module (the
module proxy serves it on demand), so the approval gates the publish — the same
role the `pypi` environment plays for arcjet-py.

1. Land changes on `main` using
   [Conventional Commits](https://www.conventionalcommits.org) (`feat:`,
   `fix:`, `perf:`, …). The commit types drive the version bump and the
   CHANGELOG.
2. [Release Please](https://github.com/googleapis/release-please)
   ([config](.github/release-please-config.json),
   [workflow](.github/workflows/release-please.yml)) maintains a
   "chore: Release X.Y.Z" pull request that bumps the `Version` constant in
   [`types.go`](types.go) (matched by the `x-release-please-version` annotation
   on that line) and updates [`CHANGELOG.md`](CHANGELOG.md). It does **not** tag
   (`skip-github-release`). **Review #1:** review and merge that PR.
3. Merging the PR lands the version bump on `main`, which triggers
   [`release.yml`](.github/workflows/release.yml). That workflow stops at the
   **`release` environment** for approval. **Review #2:** a reviewer approves
   the deployment, and only then does Release Please (run with
   `skip-github-pull-request`) create the `vX.Y.Z` tag and the GitHub Release.
   The Go module proxy serves the tag, so
   `go get github.com/arcjet/arcjet-go@vX.Y.Z` and pkg.go.dev pick it up — there
   is no separate registry publish.

Because the tag is only ever created by the approved `release.yml` run, the
`Version` constant, the CHANGELOG, and the tag always agree, and no tag is ever
published without a second human approval.

Pre-1.0 (`bump-minor-pre-major`): `fix` bumps the patch; `feat` and breaking
changes bump the minor, so a breaking change won't jump to `v1.0.0`. Promote to
`v1` deliberately once the API is stable.

### Major versions

For `v2` and beyond, Go [semantic import versioning][siv] requires the `go.mod`
module path to gain a matching `/vN` suffix (e.g.
`module github.com/arcjet/arcjet-go/v2`) with all internal import paths updated —
a code change Release Please does not make for you. Land that first.

[siv]: https://go.dev/ref/mod#major-version-suffixes

### Release infrastructure (one-time setup)

Two pieces of repo configuration back the flow above. Both are set in GitHub,
not in this repo.

**1. The Release Please GitHub App** — opens/updates the release PR. A plain
`GITHUB_TOKEN` can't be used because commits it pushes don't re-trigger CI on
the release PR, so an App token is required.

- Reuse the same GitHub App the other Arcjet SDKs use (preferred), or create a
  new one: GitHub → org **Settings → Developer settings → GitHub Apps → New**.
  Grant **Repository permissions → Contents: Read and write** and **Pull
  requests: Read and write**; no webhook needed.
- **Install** the App on `arcjet/arcjet-go` (App settings → Install App → select
  the repo).
- Generate a **private key** (App settings → Private keys → Generate) and note
  the **App ID**.
- Add them as repo secrets (**Settings → Secrets and variables → Actions**):
  `RELEASE_PLEASE_APP_ID` (the App ID) and `RELEASE_PLEASE_APP_PRIVATE_KEY` (the
  full `.pem` contents). The workflow scopes the minted token to contents +
  pull-requests at runtime.

**2. The `release` environment** — the approval gate.

- **Settings → Environments → New environment** named exactly `release` (it must
  match `environment: release` in [`release.yml`](.github/workflows/release.yml)).
- Enable **Required reviewers** and add the people/team allowed to approve
  releases. Optionally restrict the environment's deployment branches to `main`.
- No environment secrets are needed; the release job creates the tag and the
  GitHub Release via the API with the built-in `GITHUB_TOKEN`.

With both in place, a release is: merge the release PR → approve the `release`
deployment → tag published.

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
