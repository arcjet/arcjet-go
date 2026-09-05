package agentframework

import (
	"context"
	"errors"
	"iter"
	"reflect"
	"strings"

	"github.com/microsoft/agent-framework-go/agent"
	"github.com/microsoft/agent-framework-go/message"
	"github.com/microsoft/agent-framework-go/tool"

	"github.com/arcjet/arcjet-go"
)

// InboundPolicy screens the user text of a run before the provider is
// called. Rules receives the concatenated text of the run's user-role
// messages. Actor receives the messages themselves.
type InboundPolicy struct {
	Action       string
	Rules        func(ctx context.Context, text string) ([]arcjet.GuardRuleInput, error)
	Actor        func(ctx context.Context, messages []*message.Message) (string, error)
	Metadata     arcjet.Metadata
	OnGuardError arcjet.OnGuardError
	// OnDeny, when set, builds the single response update returned on a DENY
	// decision. By default the update is assistant text carrying the
	// arcjet.GuardDenialResult message. It is not called when the guard is
	// unavailable; that path returns the arcjet.NewGuardUnavailableResult
	// message.
	OnDeny func(arcjet.GuardDecision) *agent.ResponseUpdate
}

// MiddlewareConfig configures GuardMiddleware. Both fields are optional; a
// config with neither set produces a middleware that only propagates the
// session correlation ID.
type MiddlewareConfig struct {
	// Tools picks a policy for each tool the run can see, whether it came
	// from agent.Config.Tools or from a per-run agent.WithTool option. It is
	// applied through GuardTools, so tools it declines, non-function tools,
	// and tools already wrapped by GuardTool pass through unchanged.
	Tools func(tool.Tool) (ToolPolicy, bool)
	// Inbound screens the run's user text before the provider is called.
	Inbound *InboundPolicy
}

type guardMiddleware struct {
	client *arcjet.GuardClient
	cfg    MiddlewareConfig
}

// GuardMiddleware returns an agent.Middleware for agent.Config.Middlewares.
// Agent-level middleware runs before history and context providers and
// before the provider-owned tool loop, so it sees only the new turn's
// messages and every tool as a run option.
//
// Per run it: puts the session's service ID on the context as the
// correlation ID when the context has none; screens the user text when
// Inbound is set, ending the run with one assistant update on a denial or an
// unavailable guard; and replaces every tool option with its guarded form
// when Tools is set.
func GuardMiddleware(client *arcjet.GuardClient, cfg MiddlewareConfig) (agent.Middleware, error) {
	if client == nil {
		return nil, errNilClient
	}
	if cfg.Inbound != nil && cfg.Inbound.Action == "" {
		return nil, errMissingAction
	}
	return &guardMiddleware{client: client, cfg: cfg}, nil
}

func (m *guardMiddleware) Run(next agent.RunFunc, ctx context.Context, messages []*message.Message, opts ...agent.Option) iter.Seq2[*agent.ResponseUpdate, error] {
	ctx = withSessionCorrelation(ctx, opts)
	if m.cfg.Inbound != nil {
		if update, blocked := m.screenInbound(ctx, messages); blocked {
			return singleUpdate(update, nil)
		}
	}
	if m.cfg.Tools != nil {
		guarded, err := guardToolOptions(m.client, opts, m.cfg.Tools)
		if err != nil {
			return singleUpdate(nil, err)
		}
		opts = guarded
	}
	return next(ctx, messages, opts...)
}

func singleUpdate(update *agent.ResponseUpdate, err error) iter.Seq2[*agent.ResponseUpdate, error] {
	return func(yield func(*agent.ResponseUpdate, error) bool) {
		yield(update, err)
	}
}

// screenInbound evaluates the inbound policy. It reports blocked=true with
// the update to return when the run must not continue.
func (m *guardMiddleware) screenInbound(ctx context.Context, messages []*message.Message) (*agent.ResponseUpdate, bool) {
	p := m.cfg.Inbound
	text := userText(messages)
	policy := arcjet.GuardActionPolicy{
		Action:       p.Action,
		Metadata:     p.Metadata,
		OnGuardError: p.OnGuardError,
		Resolve: func(ctx context.Context) (arcjet.GuardActionInputs, error) {
			var in arcjet.GuardActionInputs
			var err error
			if p.Actor != nil {
				if in.Actor, err = p.Actor(ctx, messages); err != nil {
					return in, err
				}
			}
			if p.Rules != nil {
				if in.Rules, err = p.Rules(ctx, text); err != nil {
					return in, err
				}
			}
			return in, nil
		},
	}
	_, err := arcjet.GuardAction(ctx, m.client, policy, func(context.Context) (struct{}, error) {
		return struct{}{}, nil
	})
	if err == nil {
		return nil, false
	}
	if denied, ok := errors.AsType[*arcjet.GuardDeniedError](err); ok {
		if p.OnDeny != nil {
			if update := p.OnDeny(denied.Decision); update != nil {
				return update, true
			}
		}
		return assistantText(arcjet.NewGuardDenialResult(denied.Decision).Message), true
	}
	// *arcjet.GuardUnavailableError, or any other failure: block.
	return assistantText(arcjet.NewGuardUnavailableResult().Message), true
}

// userText joins the text of the user-role messages with newlines.
func userText(messages []*message.Message) string {
	parts := make([]string, 0, len(messages))
	for _, msg := range messages {
		if msg == nil || msg.Role != message.RoleUser {
			continue
		}
		if text := msg.String(); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
}

func assistantText(text string) *agent.ResponseUpdate {
	return &agent.ResponseUpdate{
		Role:     message.RoleAssistant,
		Contents: message.Contents{&message.TextContent{Text: text}},
	}
}

// toolOptionType identifies the option type agent.WithTool produces, so
// guardToolOptions can select tool options by the option's own type rather
// than by whether its value happens to implement tool.Tool. The latter would
// also match an unrelated option whose value coincidentally has a Name and a
// Description method, dropping that option from the rebuilt list.
var toolOptionType = reflect.TypeOf(agent.WithTool(nil))

// guardToolOptions removes every tool option and re-adds each tool through
// GuardTools. The framework's own tool loop
// (agent/harness/toolautocall.prepareOptionsForLastIteration) collects tools
// the same type-exact way, with agent.AllOptions(opts, agent.WithTool), but
// its own drop step asserts opt.MAFValue().(tool.Tool), which also matches an
// unrelated option whose value happens to have a Name and a Description
// method. guardToolOptions is deliberately type-exact on both halves, so an
// option is dropped only when it truly is a tool option.
func guardToolOptions(client *arcjet.GuardClient, opts []agent.Option, policy func(tool.Tool) (ToolPolicy, bool)) ([]agent.Option, error) {
	var tools []tool.Tool
	for t := range agent.AllOptions(opts, agent.WithTool) {
		tools = append(tools, t)
	}
	rest := make([]agent.Option, 0, len(opts))
	for _, o := range opts {
		if reflect.TypeOf(o) == toolOptionType {
			continue
		}
		rest = append(rest, o)
	}
	guarded, err := GuardTools(client, tools, policy)
	if err != nil {
		return nil, err
	}
	for _, t := range guarded {
		rest = append(rest, agent.WithTool(t))
	}
	return rest, nil
}

// withSessionCorrelation puts the session's service ID on the
// context when the context carries no correlation ID yet, so every guard and
// capture in the run joins one Sequence. It never generates an ID.
func withSessionCorrelation(ctx context.Context, opts []agent.Option) context.Context {
	if _, ok := arcjet.CorrelationIdFromContext(ctx); ok {
		return ctx
	}
	session, ok := agent.GetOption(opts, agent.WithSession)
	if !ok || session == nil || session.ServiceID() == "" {
		return ctx
	}
	return arcjet.ContextWithCorrelationId(ctx, session.ServiceID())
}
