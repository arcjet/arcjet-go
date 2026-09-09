# Arcjet Guard for Microsoft Agent Framework (Go)

`github.com/arcjet/arcjet-go/agentframework` guards
[Microsoft Agent Framework for Go](https://github.com/microsoft/agent-framework-go)
tool calls and agent runs with [Arcjet Guard](../README.md#arcjet-guard).

> Microsoft Agent Framework for Go is a public preview. This module tracks it
> and may change with it. Its own version stays at `v0.x` until the
> framework's API settles. The [`go.mod`](go.mod) requirement names the
> version this module is built and tested against. Go treats a requirement as
> a lower bound, so a build that already selects a newer framework compiles
> against that one.

## Install

Requires Go 1.26 (the framework's floor).

```sh
go get github.com/arcjet/arcjet-go/agentframework@latest
```

## Which helper

| You have | Use | Blocks a call? |
| --- | --- | --- |
| A `tool.FuncTool` you build with `functool.New` | `GuardTool` | Yes, the model gets a denial result |
| Tools from `mcptool.ListTools`, or any tool list | `GuardTools` | Yes, per tool the policy selects |
| An agent whose tools the model picks, or user text to screen | `GuardMiddleware` | Yes, for tools and for inbound text |
| An agent-as-tool from `agenttool.New` | `GuardTool` (it is a function tool) | Yes |
| Any other Go function | `arcjet.GuardAction` in the root module | Yes, returns an error |

Hosted tools (`hostedtool.WebSearch`, `hostedtool.MCPServer`, and the rest)
execute at the provider. Nothing in Go runs them, so they cannot be guarded.
The `toolapproval` middleware and `tool.ApprovalRequiredFunc` are human
approval, not policy: wrapping an approval-required tool keeps its approval
status, and an Arcjet decision never stands in for a person's answer.

## Quick start

```go
package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/microsoft/agent-framework-go/agent"
	"github.com/microsoft/agent-framework-go/provider/anthropicprovider"
	"github.com/microsoft/agent-framework-go/tool"
	"github.com/microsoft/agent-framework-go/tool/functool"

	"github.com/arcjet/arcjet-go"
	"github.com/arcjet/arcjet-go/agentframework"
)

var guard = must(arcjet.NewGuardClient(arcjet.GuardConfig{Key: os.Getenv("ARCJET_KEY")}))

var (
	refundLimit = must(arcjet.GuardTokenBucket(arcjet.GuardTokenBucketOptions{
		Mode: arcjet.ModeLive, RefillRate: 5, Interval: time.Hour, Capacity: 5, Bucket: "refunds-per-user",
	}))
	promptScan = must(arcjet.GuardPromptInjection(arcjet.GuardPromptInjectionOptions{Mode: arcjet.ModeLive}))
)

type refundArgs struct {
	OrderNumber string `json:"orderNumber"`
}

var issueRefund = functool.MustNew(functool.Config{Name: "issue_refund", Description: "Refund an order"},
	func(ctx context.Context, in refundArgs) (string, error) {
		return "refunded " + in.OrderNumber, nil
	})

func main() {
	userID := "user_alice"
	guarded := agentframework.MustGuardTool(guard, issueRefund, agentframework.ToolPolicy{
		Action: "refund.issued",
		Actor:  func(context.Context, json.RawMessage) (string, error) { return userID, nil },
		Rules: agentframework.Args(func(_ context.Context, in refundArgs) ([]arcjet.GuardRuleInput, error) {
			return []arcjet.GuardRuleInput{refundLimit.Key(userID, 1)}, nil
		}),
		Metadata: arcjet.SecurityMetadata{User: userID, Reversibility: "irreversible"}.Metadata(),
	})

	inbound, err := agentframework.GuardMiddleware(guard, agentframework.MiddlewareConfig{
		Inbound: &agentframework.InboundPolicy{
			Action: "message.received",
			Rules: func(_ context.Context, text string) ([]arcjet.GuardRuleInput, error) {
				return []arcjet.GuardRuleInput{promptScan.Text(text)}, nil
			},
		},
	})
	if err != nil {
		panic(err)
	}

	a := anthropicprovider.NewAgent(anthropic.NewClient(), anthropicprovider.AgentConfig{
		Model:        os.Getenv("ANTHROPIC_MODEL"),
		Instructions: "You help customers with orders. If a tool call is denied by security policy, do not retry it; explain the denial to the user.",
		Config: agent.Config{
			Tools:       []tool.Tool{guarded},
			Middlewares: []agent.Middleware{inbound},
		},
	})

	// One correlation ID per conversation so every decision lands on one Sequence.
	ctx := arcjet.ContextWithCorrelationID(context.Background(), "conversation_123")
	resp, err := a.RunText(ctx, "Refund order o-1").Collect()
	if err != nil {
		panic(err)
	}
	println(resp.String())
	_ = guard.Close(context.Background())
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
```

## Denials are results, not errors

The framework turns a tool error into the fixed text `Error: Function
failed.` unless `IncludeDetailedErrors` is set, and it allows three
consecutive rounds of failing tool calls before the fourth ends the run. So a
guarded tool never returns an error for a denial. It returns
`arcjet.GuardDenialResult` as its result:

```json
{"arcjetDenied":true,"reason":"RATE_LIMIT","message":"Arcjet denied this call (RATE_LIMIT). It may be retried after 30 seconds.","retryable":true,"retryAfterSeconds":30}
```

Set `ToolPolicy.OnDeny` to return something else. The wrapped tool's own
errors pass through unchanged.

## Fail closed by default

When policy cannot be evaluated (Arcjet unreachable, a deadline, a rule
error, a resolver error, an invalid label), the tool does not run and the
model receives `arcjet.NewGuardUnavailableResult()`, whose `reason` is `ERROR`
with a five second retry hint. `GuardMiddleware` ends the run with that
message as assistant text. Set `OnGuardError: arcjet.OnGuardErrorAllow` on a
policy to run anyway; the capture outcome is then `degraded`. A `DENY` always
blocks.

`OnGuardErrorAllow` covers availability only. A request Arcjet could not use
at all, such as an invalid `Action` or a rule whose key is empty, is denied
whatever `OnGuardError` is set to: the alternative is running the tool under
policy that never ran. Those errors wrap `arcjet.ErrGuardMisconfigured`.

## Correlation

Put an ID you already have on the context before `Run`:

```go
ctx = arcjet.ContextWithCorrelationID(ctx, conversationID)
```

For work that outlives one call, store the ID on the session instead, and
`GuardMiddleware` uses it whenever the context carries none:

```go
session.Set(agentframework.CorrelationIDStateKey, conversationID)
```

Session state is serialized with the session, so the ID survives a session
that is persisted and restored. A `ToolPolicy` or `InboundPolicy` may also set
`CorrelationID` directly, which wins over both.

`agent.Session.ServiceID` is deliberately not used. It belongs to the
provider, and the OpenAI Responses, AG-UI, A2A and Copilot providers all
rewrite it during a run, so a conversation keyed on it would scatter across
many IDs. Nothing is generated: an uncorrelated run produces decisions that
join no Sequence.

## Which tools the middleware sees

Agent-level middleware runs before the framework's tool loop, and tools from
`agent.Config.Tools` and from a per-run `agent.WithTool` both arrive as run
options, so `MiddlewareConfig.Tools` reaches all of them. A tool already
wrapped by `GuardTool` is not wrapped again.

That last point has one exception worth knowing. The check relies on a marker
only a `GuardTool` result carries, and a wrapper that embeds `tool.FuncTool`
hides it, because Go promotes only that interface's own methods. So
`tool.ApprovalRequiredFunc(guarded)` reads as unguarded and is guarded a
second time: one model call then spends two Guard evaluations and two
rate-limit tokens. Apply `GuardTool` outermost:

```go
guarded := agentframework.MustGuardTool(client, tool.ApprovalRequiredFunc(t), policy)
```

`GuardTool` forwards the approval requirement, so wrapping in that order
keeps the human gate.

Two sources are out of reach, because both add tools after the agent
middleware chain has run:

| Source | Why the middleware cannot see it |
| --- | --- |
| A `ContextProvider` appending `agent.WithTool` from its `Invoking` hook | The context providers run inside the agent's own invoke, after the middleware |
| `toolautocall.Config.AdditionalTools` | Merged straight into the callable set, so it never becomes a run option |

Wrap tools from either source with `GuardTool` where you create them. A tool
wrapped there is guarded wherever it is later contributed from, and
`GuardTools` and `GuardMiddleware` will not wrap it a second time.
