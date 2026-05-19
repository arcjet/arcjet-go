// Package arcjet provides the Go SDK for Arcjet, the runtime security platform
// for AI code.
//
// Use NewClient for request protection in net/http handlers and any router
// that exposes *http.Request. Always include Shield as a base rule, then
// layer route-specific rules with Client.WithRule, which returns a copy of
// the client without mutating the base. WithRule validates and pre-builds
// the rule's wire form, so it returns an error if the rule is misconfigured;
// keep the call near startup rather than on the hot path. Call Protect
// inside each handler — once per request — not in generic middleware that
// runs on every path.
//
// Use NewGuardClient for non-HTTP entry points: AI agent tool calls, MCP
// servers, queue consumers, and background jobs. Create the GuardClient and
// each rule once at package scope so per-rule result accessors have a stable
// reference. Call GuardClient.Guard at the specific operation with a
// hardcoded Label such as "tools.get_weather" — never an interpolated string
// like fmt.Sprintf("tools.%s", name), which defeats dashboard grouping. Each
// rate-limit rule needs an explicit Key at call time; when there is no user
// context (e.g. a stdio MCP server), pick a stable identifier such as the
// deployment name rather than an empty string.
//
// Arcjet is designed to fail open: if the service is unavailable, Protect and
// Guard return an error and the caller should continue serving.
package arcjet
