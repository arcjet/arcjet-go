# testdata

## `guard-label-cases.json`

The labels every Arcjet validator must agree on, with the verdict each should
reach. It is a copy of `proto/decide/v2/guard-label-cases.json` in the `arcjet`
monorepo, which is the source of truth for the guard label grammar.

`guard_label_cases_test.go` runs every case through `ValidateGuardLabel`.

### Why a shared file rather than a table in the test

The grammar lives in one place per implementation: twice in the decide service,
once here, and once in each of the JavaScript and Python SDKs. Those copies
disagreed. The request-side validator accepted any Unicode letter while the
policy side accepted only lowercase ASCII, so a label such as
`getWeather.invoked` passed the request boundary, drew no `AJ1023`, and could
never match a published policy — silent at both layers.

A copy that drifts now fails by name against these cases.

### Regenerating

Run `just sync-guard-label-cases` in the `arcjet` monorepo, which writes this
file into each SDK checkout beside it.

Nothing enforces that this copy is current. The monorepo is private and this
repository is public, so no CI job here can read the source. A change to the
grammar updates every copy in the same change and bumps `revision` in the
source file. See
`docs/adrs/2026-09-15-each-sdk-checks-a-guard-label-before-sending-it.md` in
the monorepo.
