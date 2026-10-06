package agentframework

import (
	"context"
	"iter"
	"log/slog"
	"sync/atomic"

	"github.com/microsoft/agent-framework-go/agent"
	"github.com/microsoft/agent-framework-go/message"
	"github.com/microsoft/agent-framework-go/tool"

	"github.com/arcjet/arcjet-go"
)

// ungovernedLogged makes the ungoverned warning fire once per process rather
// than once per construction. An agent typically builds a middleware and
// several tools, and a line each would bury the fact that governance is off
// under repetition.
var ungovernedLogged atomic.Bool

// logUngoverned emits the single warning that this process is running without
// Arcjet governance.
//
// It writes to [slog.Default], which is where the SDK's own diagnostics go
// when GuardConfig.Log is unset. The pass-through constructors keep the
// signatures of the guarded ones, so there is no config of theirs to carry a
// logger; an application that wants the line elsewhere redirects slog.
func logUngoverned() {
	if ungovernedLogged.Swap(true) {
		return
	}
	slog.Default().Warn("agentframework: running ungoverned, no Arcjet Guard client was configured, so tool calls and inbound text are not evaluated")
}

// GuardMiddlewareOrPassThrough is [GuardMiddleware], except that a nil client
// returns a middleware which does nothing instead of an error.
//
// It is the opt-in for a local run with no ARCJET_KEY, where
// [arcjet.NewGuardClient] fails with [arcjet.ErrMissingKey] and leaves the
// caller with no client. Passing the nil through is the request: governance is
// off for this process, which is logged once, by [slog.Default]. Production
// must not take this path. Nothing is screened, no decision is made, and no
// capture event is recorded, so the run is invisible in the Arcjet dashboard.
//
// cfg is still validated. An Action a typo would make Guard reject fails here
// exactly as it would with a client, so the local run that has no key is also
// the run that catches the mistake.
func GuardMiddlewareOrPassThrough(client *arcjet.GuardClient, cfg MiddlewareConfig) (agent.Middleware, error) {
	if client != nil {
		return GuardMiddleware(client, cfg)
	}
	if cfg.Inbound != nil {
		if err := validateAction(cfg.Inbound.Action); err != nil {
			return nil, err
		}
	}
	logUngoverned()
	return passThroughMiddleware{}, nil
}

// passThroughMiddleware hands the run straight to next. It does not propagate
// the session correlation ID: with nothing guarded and nothing captured there
// is no Sequence for an ID to join.
type passThroughMiddleware struct{}

func (passThroughMiddleware) Run(next agent.RunFunc, ctx context.Context, messages []*message.Message, opts ...agent.Option) iter.Seq2[*agent.ResponseUpdate, error] {
	return next(ctx, messages, opts...)
}

// GuardToolOrPassThrough is [GuardTool], except that a nil client returns t
// itself instead of an error. See [GuardMiddlewareOrPassThrough] for when to
// reach for this and what it costs.
//
// The tool is returned unwrapped, so a call carries no Arcjet code at all. A
// nil tool and an invalid policy Action are still errors.
func GuardToolOrPassThrough(client *arcjet.GuardClient, t tool.FuncTool, policy ToolPolicy) (tool.FuncTool, error) {
	if client != nil {
		return GuardTool(client, t, policy)
	}
	if isNilValue(t) {
		return nil, errNilTool
	}
	if err := validateAction(policy.Action); err != nil {
		return nil, err
	}
	logUngoverned()
	return t, nil
}

// GuardToolsOrPassThrough is [GuardTools], except that a nil client returns
// every tool unwrapped instead of an error. See [GuardMiddlewareOrPassThrough]
// for when to reach for this and what it costs.
//
// policy still runs, and the Action it returns for each tool it claims is
// still validated, so the set of tools that would have been guarded and the
// policies they would have used are both checked without a key.
func GuardToolsOrPassThrough(client *arcjet.GuardClient, tools []tool.Tool, policy func(tool.Tool) (ToolPolicy, bool)) ([]tool.Tool, error) {
	if client != nil {
		return GuardTools(client, tools, policy)
	}
	out, err := selectTools(tools, policy, func(t tool.FuncTool, p ToolPolicy) (tool.Tool, error) {
		if err := validateAction(p.Action); err != nil {
			return nil, err
		}
		return t, nil
	})
	if err != nil {
		return nil, err
	}
	logUngoverned()
	return out, nil
}
