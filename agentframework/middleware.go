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

// CorrelationIDStateKey is the [agent.Session] state key GuardMiddleware
// reads a correlation ID from when the context carries none. Set it once,
// with an ID the application already has:
//
//	session.Set(agentframework.CorrelationIDStateKey, conversationID)
//
// Session state is serialized with the session, so the ID survives a session
// that is persisted and restored. Nothing here generates an ID.
const CorrelationIDStateKey = "arcjet.correlationId"

// InboundPolicy screens the user text of a run before the provider is
// called. Rules receives the concatenated text of the run's user-role
// messages. Actor receives the messages themselves.
type InboundPolicy struct {
	Action string
	Rules  func(ctx context.Context, text string) ([]arcjet.GuardRuleInput, error)
	Actor  func(ctx context.Context, messages []*message.Message) (string, error)
	// Inputs are typed values exposed to remote policies configured for
	// this label. Like Rules and Actor, an error counts as unevaluated
	// policy.
	Inputs func(ctx context.Context, text string) (map[string]arcjet.GuardPolicyInput, error)
	// CorrelationID, when set, wins over the ID carried by the context and
	// over the session's stored ID.
	CorrelationID string
	Metadata      arcjet.Metadata
	OnGuardError  arcjet.OnGuardError
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
	// and tools already wrapped by GuardTool pass through unchanged, unless
	// a wrapper such as tool.ApprovalRequiredFunc hides the marker; see
	// GuardTools.
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
// messages, and it sees the tools the run carries as options.
//
// Per run it: puts the session's stored correlation ID on the context when
// the context has none; screens the user text when Inbound is set, ending
// the run with one assistant update on a denial or an unavailable guard;
// and replaces each tool option with its guarded form when Tools is set.
//
// A blocked inbound turn returns without calling next, so the agent's
// history and context providers do not see that turn or the refusal: they
// run inside the invoke this middleware wraps. Screening cannot both stop
// the provider being called and still run the work that happens beneath it.
//
// Two sources of tools are out of its reach. A ContextProvider may append
// agent.WithTool from its Invoking hook, which runs inside the agent's own
// invoke, after this middleware; only a provider-level middleware would see
// those, and the bundled provider constructors do not expose that seam.
// toolautocall.Config.AdditionalTools are merged straight into the callable
// set without ever becoming an option, so no middleware at any layer sees
// them. Tools from either source run unguarded unless the application wraps
// them with GuardTool itself.
func GuardMiddleware(client *arcjet.GuardClient, cfg MiddlewareConfig) (agent.Middleware, error) {
	if client == nil {
		return nil, errNilClient
	}
	if cfg.Inbound != nil {
		if err := validateAction(cfg.Inbound.Action); err != nil {
			return nil, err
		}
	}
	return &guardMiddleware{client: client, cfg: cfg}, nil
}

func (m *guardMiddleware) Run(next agent.RunFunc, ctx context.Context, messages []*message.Message, opts ...agent.Option) iter.Seq2[*agent.ResponseUpdate, error] {
	// Everything happens inside the returned sequence, as the framework's own
	// middleware does. Screening eagerly would spend a Guard decision when a
	// caller builds a stream and never reads it, and would move where the
	// call blocks depending on which middleware sit either side.
	return func(yield func(*agent.ResponseUpdate, error) bool) {
		ctx := withSessionCorrelation(ctx, opts)
		if m.cfg.Inbound != nil {
			if update, blocked := m.screenInbound(ctx, messages); blocked {
				yield(update, nil)
				return
			}
		}
		opts := opts
		if m.cfg.Tools != nil {
			guarded, err := guardToolOptions(m.client, opts, m.cfg.Tools)
			if err != nil {
				yield(nil, err)
				return
			}
			opts = guarded
		}
		for update, err := range next(ctx, messages, opts...) {
			if !yield(update, err) {
				return
			}
		}
	}
}

// screenInbound evaluates the inbound policy. It reports blocked=true with
// the update to return when the run must not continue.
func (m *guardMiddleware) screenInbound(ctx context.Context, messages []*message.Message) (*agent.ResponseUpdate, bool) {
	p := m.cfg.Inbound
	text := userText(messages)
	if !hasUserContent(messages) {
		// An approval turn carries only a person's answer to a call that was
		// already screened, so guarding it again spends a decision and lets
		// an outage block a call a person has approved. Any other turn is
		// screened even when text is empty: the policy still runs, and a turn
		// whose payload this cannot read as text must not pass unevaluated.
		return nil, false
	}
	policy := arcjet.GuardActionPolicy{
		Action:        p.Action,
		CorrelationID: p.CorrelationID,
		Metadata:      p.Metadata,
		OnGuardError:  p.OnGuardError,
		Resolve: func(ctx context.Context) (arcjet.GuardActionInputs, error) {
			var in arcjet.GuardActionInputs
			var err error
			if p.Actor != nil {
				if in.Actor, err = p.Actor(ctx, messages); err != nil {
					return in, err
				}
			}
			if p.Inputs != nil {
				if in.Inputs, err = p.Inputs(ctx, text); err != nil {
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
	// Unavailable is tested first: its Err may hold a *GuardDeniedError from a
	// nested guard on another action, and this action's policy never ran.
	if unavailable, ok := errors.AsType[*arcjet.GuardUnavailableError](err); ok && unavailable != nil {
		return assistantText(arcjet.NewGuardUnavailableResult().Message), true
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

// hasUserContent reports whether the run's user-role messages carry anything
// worth evaluating. A turn holding only tool-approval content is the
// framework relaying a person's answer, not a new user message.
//
// Content this cannot read as text, such as a document carried as
// message.DataContent, still counts: [userText] returns nothing for it, but
// the policy must run so the turn is not admitted unevaluated.
func hasUserContent(messages []*message.Message) bool {
	for _, msg := range messages {
		if msg == nil || msg.Role != message.RoleUser {
			continue
		}
		for _, content := range msg.Contents {
			switch content.(type) {
			case *message.ToolApprovalRequestContent, *message.ToolApprovalResponseContent:
				continue
			default:
				return true
			}
		}
	}
	return false
}

// userText joins the text of the run's user-role messages with newlines.
// Non-text
// content, such as a document carried as message.DataContent, has no text
// form and is not screened here.
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

// withSessionCorrelation puts the session's stored correlation ID on the
// context when the context carries none, so every guard and capture in the run
// joins one Sequence. It never generates an ID.
//
// The ID is read from the session's own state under [CorrelationIDStateKey],
// where the application put it. Session.ServiceID is deliberately not used: it
// belongs to the provider, and the OpenAI Responses, AG-UI, A2A and Copilot
// providers all rewrite it during a run.
func withSessionCorrelation(ctx context.Context, opts []agent.Option) context.Context {
	if _, ok := arcjet.CorrelationIDFromContext(ctx); ok {
		return ctx
	}
	session, ok := agent.GetOption(opts, agent.WithSession)
	if !ok || session == nil {
		return ctx
	}
	var id string
	found, err := session.Get(CorrelationIDStateKey, &id)
	if err != nil || !found || id == "" {
		return ctx
	}
	return arcjet.ContextWithCorrelationID(ctx, id)
}
