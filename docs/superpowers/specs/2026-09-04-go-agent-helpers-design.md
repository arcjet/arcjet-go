# Go agent helpers and the Microsoft Agent Framework module

Date: 2026-09-04

## Summary

Add the framework-agnostic agent helper layer that arcjet-js and arcjet-py
already have to the Go SDK, and build on it a separate module that integrates
Arcjet Guard with Microsoft Agent Framework for Go (MAF). The helper layer is
stable API in the root module. The MAF module tracks a preview framework and
is documented as such.

Trigger: a design partner asked about MAF support. Their exact usage is not
yet known, so the surfaces are built in the order function tools, MCP tools,
agent middleware, with the workflow package left to a final analysis phase.

## Findings the design rests on

- arcjet-go has the guard client, rule builders, capture, metadata, and a
  correlation ID field, but no equivalent of the JS `guardAction` or Python
  `guard_action`, no fail-closed wrapper, no denial payload, and no context
  helper. The README says so in its Guard section.
- The JS helpers split into an agnostic engine (`arcjet-guard/src/agents`,
  about 900 lines) and per-vendor adapters. Python folded the agnostic layer
  into `arcjet.guard` and put frameworks in subpackages, with its own layering
  ADR (2026-08-13). No Arcjet repository or ADR mentions MAF.
- MAF for Go tagged v0.1.0 on 2026-09-01, requires Go 1.26, and calls itself
  public preview. arcjet-go is on Go 1.25 with CI pinned to 1.25.x.
- MAF extension points, verified against commit 86079f9:
  - `tool.FuncTool` has `Call(ctx, jsonArgs string) (any, error)`. Authored
    tools, MCP client tools from `mcptool.ListTools`, and agent-as-tool all
    implement it.
  - `agent.Middleware` wraps the whole run. Agent-level middleware runs before
    history and context providers and before the provider-owned tool loop.
    Tools from `agent.Config.Tools` become `WithTool` run options at
    construction and are prepended on every run, so middleware sees every
    tool as an option. The loop discovers tools with
    `agent.AllOptions(opts, agent.WithTool)` and itself rewrites the option
    slice by type-asserting each option's value to `tool.Tool`.
  - The tool loop has no per-call hook. A tool that returns an error reaches
    the model as "Error: Function failed." unless `IncludeDetailedErrors` is
    set, and three consecutive errors abort the run. A plain result is
    wrapped in a `FunctionResultContent` with the correct call ID and is not
    validated against the return schema.
  - The context passed to a tool carries only the agent and an internal
    tracer. The call ID is not in it.
  - `agent.Session` exposes a provider thread ID (`ServiceID`) and a state bag.
  - `toolapproval` is human-in-the-loop with auto-approval rules. Hosted tools
    execute at the provider.

## Decisions

1. **Layering (Approach A).** Agnostic helpers live in the root `arcjet`
   package with the `Guard` prefix the package already uses. The engine is an
   unexported function behind `GuardAction`. There is no internal engine
   package: it would create an import cycle with the root, and the MAF
   adapters need only the public error types as their seam.
2. **MAF module.** Path `github.com/arcjet/arcjet-go/agentframework`, package
   `agentframework`, own `go.mod` at Go 1.26 with `replace` back to the root
   like `sensitiveinfo/rampart`. Tags take the nested form
   `agentframework/v0.x`. No framework version in the path: a Go `/vN` suffix
   means our own major, and Go's one-major-per-build rule means two MAF majors
   cannot coexist in a consumer anyway. The supported MAF range lives in
   `go.mod` and the README.
3. **Commitment.** Root additions are stable API under the repo's additive
   policy. The MAF module's README and package doc state that it tracks a
   preview framework and may change with it.
4. **Fail posture.** Helpers fail closed by default per the 2026-07-27 ADR.
   The zero value of the option is deny.
5. **Denial envelope.** A denial is returned to the model as a successful tool
   result carrying the shared payload, never as an error.
6. **Correlation carrier.** The Go `context.Context`. Only helpers read it;
   the core `Guard` and `Capture` calls keep their documented behaviour of
   never inheriting from ambient context. Nothing generates an ID.
7. **Two ADRs in the arcjet monorepo.** A layering ADR before code, recording
   decisions 1, 2, 5, and 6. A surfaces ADR after the middleware phase,
   modelled on the Eve one (2026-08-06), recording where a MAF Go agent can
   and cannot be guarded.

## Root package API

```go
type OnGuardError int
const (
    OnGuardErrorDeny OnGuardError = iota // zero value
    OnGuardErrorAllow
)

type GuardActionInputs struct {
    Actor  string
    Inputs map[string]GuardPolicyInput
    Rules  []GuardRuleInput
}

type GuardActionPolicy struct {
    Action        string                      // required; sent as the guard Label
    Actor         string
    Inputs        map[string]GuardPolicyInput
    Rules         []GuardRuleInput            // may be empty; Guard is still called
    // Resolve, when set, computes Actor, Inputs, and Rules at call time and
    // replaces the static fields above. An error counts as unevaluated policy.
    Resolve       func(ctx context.Context) (GuardActionInputs, error)
    Metadata      Metadata
    CorrelationId string                      // explicit; else read from ctx
    OnGuardError  OnGuardError
}

func GuardAction[T any](ctx context.Context, client *GuardClient,
    policy GuardActionPolicy, fn func(context.Context) (T, error)) (T, error)

type GuardDeniedError struct {
    Action   string
    Decision GuardDecision
}

type GuardUnavailableError struct {
    Action   string
    Decision *GuardDecision // the fail-open decision, when one was returned
    Err      error          // the error Guard returned, when non-nil
}
// Unwrap returns Err so errors.Is still matches a programmer error such as
// ErrInvalidLabel. Go's client returns both a decision and an error on a
// transport failure, so unlike JS both fields can be set.

type GuardDenialResult struct {
    ArcjetDenied      bool   `json:"arcjetDenied"`
    Reason            string `json:"reason"`
    Message           string `json:"message"`
    Retryable         bool   `json:"retryable"`
    RetryAfterSeconds *int   `json:"retryAfterSeconds,omitempty"`
}
func NewGuardDenialResult(d GuardDecision) GuardDenialResult
func NewGuardUnavailableResult() GuardDenialResult

func ContextWithCorrelationId(ctx context.Context, id string) context.Context
func CorrelationIdFromContext(ctx context.Context) (string, bool)

type SecurityMetadata struct {
    User, Agent, Workflow, DataClass, Destination, Reversibility, Resource string
}
func (m SecurityMetadata) Metadata() Metadata // empty fields omitted
```

Message texts and the JSON field names match the JS `ArcjetDenialResult` in
`arcjet-guard/src/agents/denial.ts`: a rate-limit denial says it may be
retried after N seconds or "later" when no reset time exists; any other denial
says do not retry and explain the denial to the user; the unavailable payload
says the security check could not be completed and carries reason `ERROR`,
`retryable: true`, and `retryAfterSeconds: 5`.

Omitted on purpose: a correlation ID generator (the Eve ADR found a generated
ID splits the sequence, and the Go SDK has no logger to warn about an
uncorrelated call, so the skill documents this) and a capture-action helper
(with the context helper, a capture is one call on the existing `Capture`).

## Engine semantics

1. Guard is called on every path that reaches policy evaluation, including
   one with no rules, because the server selects remote policy by label. A
   `Resolve` failure is the single exception, and item 9 covers it.
2. A DENY decision captures `outcome: "denied"` with the decision ID and
   returns `*GuardDeniedError`, regardless of posture.
3. An unevaluated policy, meaning Guard returned an error or the decision is
   not a clean ALLOW: under deny, capture `outcome: "unavailable"` and return
   `*GuardUnavailableError` without running fn. Under allow, run fn and
   capture `outcome: "degraded"`. A clean ALLOW is one whose conclusion is
   ALLOW and whose `HasFailedOpen()` is false; any other conclusion,
   including one the SDK does not recognise, is unevaluated and fails
   closed.
4. A clean ALLOW runs fn. If fn returns an error, capture `outcome: "error"`
   and return that error unchanged. Otherwise capture `outcome: "success"`.
5. The capture event carries the action, the resolved correlation ID, the
   decision ID only when non-empty, and the policy metadata with the
   `outcome` key written last so a caller cannot overwrite it. Capture never
   fails the action.
6. Correlation precedence: explicit policy field, then context, then none.
7. Retry hint: a `RATE_LIMIT` denial derives seconds from the denying rule's
   `ResetAtUnixSeconds`, clamped at zero. Unavailable uses five seconds.
   Other denials carry no hint and are not retryable.
8. Programmer errors from Guard take the unevaluated path and, under deny,
   are wrapped by `*GuardUnavailableError` so `errors.Is` still identifies
   them.
9. A `Resolve` error takes the unevaluated path without calling Guard. Under
   deny it returns `*GuardUnavailableError` wrapping the resolver's error.
   Under allow, fn runs and the outcome is `degraded`.

## The `agentframework` module

### Function tools

```go
type ToolPolicy struct {
    Action       string
    Actor        func(ctx context.Context, args json.RawMessage) (string, error)
    Inputs       func(ctx context.Context, args json.RawMessage) (map[string]arcjet.GuardPolicyInput, error)
    Rules        func(ctx context.Context, args json.RawMessage) ([]arcjet.GuardRuleInput, error)
    Metadata     arcjet.Metadata
    OnGuardError arcjet.OnGuardError
    OnDeny       func(arcjet.GuardDecision) any
}

func GuardTool(client *arcjet.GuardClient, t tool.FuncTool, policy ToolPolicy) (tool.FuncTool, error)
func MustGuardTool(client *arcjet.GuardClient, t tool.FuncTool, policy ToolPolicy) tool.FuncTool

func Args[In any](fn func(context.Context, In) ([]arcjet.GuardRuleInput, error)) func(context.Context, json.RawMessage) ([]arcjet.GuardRuleInput, error)
```

Constructors validate a nil client, a nil tool, and an empty `Action` at wiring time and return an error, following `functool.New`; `MustGuardTool` panics for package-level initialization.

The wrapper embeds the tool so name, description, and both schemas pass
through. `Call` runs the underlying call inside `GuardAction`. A
`*GuardDeniedError` becomes the denial payload returned as a successful
result, or the `OnDeny` value. A `*GuardUnavailableError` becomes the
unavailable payload. Any other error passes through untouched. The three resolvers run inside the policy's `Resolve` hook, so a resolver error counts as unevaluated policy.

The wrapper implements `tool.ApprovalRequiredTool` by delegating, returning
false when the underlying tool does not implement it, so a human approval
gate survives wrapping.

The wrapper carries an unexported marker so `GuardTools` can skip a tool that
is already guarded.

`Args` must mirror `functool`'s input wrapping: a non-struct input type
arrives as `{"arg0": ...}`. The plan verifies this against
`tool/functool/func.go` before shipping the helper.

### MCP

```go
func GuardTools(client *arcjet.GuardClient, tools []tool.Tool,
    policy func(tool.Tool) (ToolPolicy, bool)) ([]tool.Tool, error)
```

Wraps each tool that implements `tool.FuncTool`, does not already carry the
marker, and for which the policy function returns true. Everything else
passes through unchanged. The policy function is where a caller switches on
the tool name to pick a hardcoded label. MCP client tools from
`mcptool.ListTools` are function tools, so no MCP-specific code is needed. A
guarded tool passes into `mcptool.AddTool` unchanged. Hosted tools, including
the provider-executed MCP server declaration, cannot be reached.

### Agent middleware

```go
type InboundPolicy struct {
    Action       string
    Rules        func(ctx context.Context, text string) ([]arcjet.GuardRuleInput, error)
    Actor        func(ctx context.Context, messages []*message.Message) (string, error)
    Metadata     arcjet.Metadata
    OnGuardError arcjet.OnGuardError
    OnDeny       func(arcjet.GuardDecision) *agent.ResponseUpdate
}

type MiddlewareConfig struct {
    Tools   func(tool.Tool) (ToolPolicy, bool)
    Inbound *InboundPolicy
}

func GuardMiddleware(client *arcjet.GuardClient, cfg MiddlewareConfig) (agent.Middleware, error)
```

Per run:

1. If `Inbound` is set, concatenate the user-role text of the incoming
   messages and evaluate it through `GuardAction`. Agent-level middleware runs
   before history injection, so this is the new turn only. A denial, or an
   unavailable guard under the default posture, yields one assistant
   `ResponseUpdate` (the `OnDeny` value, or assistant text carrying the
   denial message) and never calls next.
2. If `Tools` is set, clone the option slice, drop every option whose value
   is a `tool.Tool`, and re-add each through `GuardTools`. This reaches
   agent-level and per-run tools alike.
3. If the context has no correlation ID and the run has a session with a
   non-empty `ServiceID`, put that ID on the context passed to next.

Correlation precedence inside the framework is therefore: explicit policy
field, context, session thread ID, none.

### Documented, not built

- Agent-as-tool is a function tool; use `GuardTool`.
- The approval middleware and its auto-approval rules are human-in-the-loop,
  not a policy gate. No adapter.
- Observation of tool spans can come from the framework's OpenTelemetry
  middleware through the OTLP ingest path (ADR 2026-07-21).
- Hosted tools execute at the provider and cannot be intercepted.
- The workflow package is a separate surface analysed in the final phase.

## Testing

**Root.** `GuardAction` is exercised against an in-process Decide server as
the existing guard tests do, one named test per engine rule, plus
literal-value assertions on every field of both denial payload constructors.

**Module.** A fake provider built through the public `agent.ProviderConfig`
emits a function call for a named tool on the first turn and echoes the tool
result on the second, with the framework's own `toolautocall` middleware
installed so the real dispatch path runs. Tests cover: denial and unavailable
payloads arrive as successful function results with the right call ID; an
ordinary tool error still reaches the loop as an error; approval-required
status survives wrapping; `GuardTools` wraps function tools and passes others
through; the middleware guards agent-level and per-run tools; inbound denial
yields one assistant update and never invokes the provider; the marker
prevents double evaluation; the session thread ID lands on the guard request
when the context has no correlation ID.

**Mutation checks.** Before claiming coverage, break each default and
invariant, name the failing test, restore, and record counts. The two that
matter most: flipping the zero value of `OnGuardError`, and returning the
denial as an error instead of a result.

## Repository mechanics

- A third module joins the justfile and CI fan-out alongside rampart: build,
  test with race, lint with the pinned golangci-lint, tidy and tidy-check,
  govulncheck. CI installs Go 1.26 for that module's steps; the root stays on
  1.25.
- Renovate gains the framework dependency.
- `examples/agentframework/` is compiled by hand like `examples/nethttp/`,
  outside the gate.
- `AGENTS.md` gains a module table row.

## Deliverables across repositories

| Repository | Deliverable |
| --- | --- |
| `arcjet` | Layering ADR (before code); surfaces ADR (after middleware) |
| `arcjet-go` | Root helpers; `agentframework` module; example; README, AGENTS.md, CI, justfile |
| `skills` | `integrate-arcjet-guard-agent-framework-go`; umbrella table and `guards_go.md` updated; eval fixture |
| `arcjet-plugin` | Mirror of the skill under `plugins/arcjet/skills/` |
| `arcjet-docs` | `guards/agent-framework-go.mdx` and quick-start snippets, unsuffixed because no JS or Python page exists |

## Phases

1. Layering ADR in `arcjet`.
2. Root helpers, tests, README section.
3. Module scaffold, CI and justfile fan-out, `GuardTool`, `Args`.
4. `GuardTools` and MCP coverage.
5. `GuardMiddleware` with inbound screening and session correlation.
6. Surfaces ADR in `arcjet`.
7. Example, skill (two copies), eval fixture, docs page.
8. Workflow package analysis, opening with a reconciliation task against the
   then-current MAF and the partner's stated usage.
9. Remove the plan files from the branch before merge.

## Open items

- The partner's actual MAF usage: which surfaces, which provider, whether
  they use the workflow package or the approval middleware.
- Whether the partner also uses MAF for .NET or Python. Arcjet has no .NET
  SDK and arcjet-py has no MAF adapter.
- Whether the partner is on Go 1.26.
