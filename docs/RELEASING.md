# Release automation

The [Release tags workflow](../.github/workflows/release.yml) creates the tags
that publish arcjet-go through the Go module proxy:

- `v<version>` for `github.com/arcjet/arcjet-go`
- `sensitiveinfo/rampart/v<version>` for the optional Rampart module
- `agentframework/v<agentframework version>` for the Microsoft Agent Framework
  module, on a run that selects it

Every tag is annotated and points at the same commit. The workflow pushes them
atomically, so a release cannot leave only some of the module tags behind.

The `components` input chooses what a run publishes. `root` publishes the root
and Rampart modules, which always move together at the same version.
`root-and-agentframework` publishes those and agentframework as well.

agentframework keeps its own `v0.x` version line, so it is versioned
independently, but it is never tagged on its own. Tagging it from the commit
that the root tag also points at is what makes the SDK version it requires
exist at the moment agentframework is published. `agentframework/go.mod`
replaces the SDK with the working tree, and consumers ignore that replace
directive, so releasing the two from one commit is also what lets every check
in this repository stand in for a consumer's view of the module.

The workflow has two jobs. The ungated preflight validates `main`, checks every
version and dependency pin, confirms both tags are unused, runs the release
checks, and writes the exact request to the workflow summary. Only then can a
reviewer approve the `release-tags` environment. The gated job mints a
short-lived GitHub App token and pushes the tags.

Every workflow change is checked by `actionlint` and `zizmor` in the
[workflow lint job](../.github/workflows/lint-workflows.yml). Actions are pinned
to immutable commit SHAs or container digests, checkout credentials are not
persisted, and the release jobs use explicit minimum permissions.

## One-time GitHub configuration

Configure all three controls before running the workflow. The workflow's normal
`GITHUB_TOKEN` is read-only and cannot substitute for the GitHub App.

### 1. GitHub App

Create an organization-owned GitHub App dedicated to releases:

1. Disable webhooks; this App does not receive events.
2. Grant the repository permission **Contents: Read and write**. Do not grant
   organization or account permissions.
3. Install it only on `arcjet/arcjet-go`.
4. Generate a private key and record the App's client ID.

The contents permission is the narrowest GitHub App permission that can create
Git tags. Repository rules, rather than a broader App permission, limit which
actors can create release tags.

### 2. Protected environment

In `arcjet/arcjet-go`, open **Settings -> Environments** and create an
environment named `release-tags`:

1. Add the release approvers under **Required reviewers**.
2. Enable **Prevent self-review**.
3. Under **Deployment branches and tags**, select **Selected branches and
   tags**, then allow only the `main` branch.
4. Add environment variable `RELEASE_APP_CLIENT_ID` with the App client ID.
5. Add environment secret `RELEASE_APP_PRIVATE_KEY` with the complete PEM
   private key.

Environment secrets are unavailable to the workflow until the protection rules
pass. Keeping the App key here, rather than as a repository secret, is what
makes approval a credential boundary.

### 3. Release-tag ruleset

Open **Settings -> Rules -> Rulesets**, create a **tag ruleset**, and use:

- Name: `release-tags`
- Enforcement status: **Active**
- Target tags, included by pattern:
  - `v*`
  - `sensitiveinfo/rampart/v*`
  - `agentframework/v*`
- Bypass list: only the release GitHub App, set to **Always allow**
- Tag protections:
  - **Restrict creations**
  - **Restrict updates**
  - **Restrict deletions**
  - **Block force pushes**

Do not add administrators, organization owners, roles, teams, users, or
`github-actions` to the bypass list. The three explicit patterns protect the
modules this workflow tags without accidentally treating every tag containing
a `v` as a release. If another submodule is published later, add its exact
`<module-path>/v*` pattern.

The GitHub App is allowed to bypass every rule in this ruleset because GitHub
does not offer per-rule bypasses. The workflow only creates new tags and refuses
to proceed when any tag it would create already exists; the App key remains
behind the environment approval gate.

A repository configured before the workflow tagged agentframework also has an
`agentframework-tags` ruleset covering `agentframework/v*` for a manual push.
It is redundant once the pattern appears above, and deleting it keeps the tag
protections in one place. Leaving it does not block a release: it never
restricted creations.

Read the ruleset back once it exists. With **Restrict creations** on and an
empty bypass list, nothing can create `v*` at all, and because a dry-run push
sends no ref update there is nothing for the ruleset to reject — so the
misconfiguration would first appear during a real release, after approval.

Check the bypass entry in **Settings -> Rules -> Rulesets**, or from an account
that administers the repository. GitHub returns `bypass_actors` only to a token
allowed to edit rulesets and omits the field entirely otherwise, so `maintain`
cannot distinguish a configured bypass list from an empty one, and reading the
absent field as empty reports a working ruleset as broken. The substitute field
`current_user_can_bypass` describes the caller, not the App.

```sh
gh api repos/arcjet/arcjet-go/rulesets --jq \
  '.[] | select(.target == "tag") | {name, rules: [.rules[].type], bypass: .bypass_actors}'
```

`release-tags` lists `creation` among its rules and names the release App in
`bypass_actors`.

## Running a release

1. Merge the release preparation PR to `main`. `Version` in `types.go`, the
   Rampart SDK requirement, and both example requirements must all contain the
   same version.
2. Open **Actions -> Release tags -> Run workflow**.
3. Select `main` and choose whether this is a dry run. The workflow infers the
   version from `types.go`.
4. Open the completed **Preflight** job and review its workflow summary. It
   shows both proposed tags, the exact commit, the inferred version, and the
   dry-run state.
5. Approve or reject the `release-tags` environment.

A dry run creates both annotated tags only in the ephemeral runner and performs
`git push --dry-run` with the GitHub App token. This validates the preflight,
environment, secret, App installation, token permission, Git authentication,
and push refspecs without changing the repository. A dry-run push sends no ref
update, so it cannot exercise the tag ruleset or prove that the App has bypass
permission. Review the active ruleset before the first real release; that push
is the first end-to-end test of the bypass configuration.

The real run creates every remote tag atomically and stops there. Do not
delete or repoint a published release tag; fix the problem and release a new
version instead.

The push then starts the
[Verify published modules workflow](../.github/workflows/verify-published-modules.yml),
which waits, asks `proxy.golang.org` for each module at its exact version, and
polls for up to 40 minutes. That request also adds the version to the index
that pkg.go.dev monitors, so documentation normally appears within a few
minutes of the module resolving.

The release job does not ask about a version it has just tagged, because
`proxy.golang.org` caches a failed fetch. A request that arrives before the ref
has propagated caches `unknown revision` for that version and blocks it for up
to the 30 minutes described in the [proxy FAQ](https://proxy.golang.org/#faq).
Asking early does not only fail; it creates the failure.

If the verification workflow is red, the tags are still published and correct.
Do not delete or repoint them, and do not rerun the release workflow, because
its preflight correctly rejects the existing tags. Wait for the window in the
FAQ to pass and rerun the verification workflow, then run the smoke test below.

## After tagging

Verify both public modules from a fresh temporary module, without local
`replace` directives:

```sh
VERSION=1.2.3
SMOKE_DIR="$(mktemp -d)"
cd "$SMOKE_DIR"
go mod init example.com/arcjet-release-smoke
GOPROXY=https://proxy.golang.org go get \
  "github.com/arcjet/arcjet-go@v${VERSION}" \
  "github.com/arcjet/arcjet-go/sensitiveinfo/rampart@v${VERSION}"
go mod download all
```

Create one GitHub release for the root tag. Mention that the optional Rampart
backend was released in lockstep; do not create a second GitHub release for its
module-qualified tag.

## References

- [GitHub: Managing environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [GitHub: Creating rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository)
- [GitHub: Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [Go modules: Mapping versions to commits](https://go.dev/ref/mod#vcs-version)
