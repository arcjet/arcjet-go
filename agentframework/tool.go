package agentframework

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/microsoft/agent-framework-go/tool"

	"github.com/arcjet/arcjet-go"
)

// validateAction rejects an Action that Guard would reject as a label, so a
// misspelled slug fails at construction rather than disabling the guard for
// the life of the process.
func validateAction(action string) error {
	if action == "" {
		return errMissingAction
	}
	if err := arcjet.ValidateGuardLabel(action); err != nil {
		return fmt.Errorf("agentframework: policy Action %q: %w", action, err)
	}
	return nil
}

var (
	errNilClient     = fmt.Errorf("agentframework: guard client: %w", arcjet.ErrNilClient)
	errNilTool       = errors.New("agentframework: tool is nil")
	errMissingAction = errors.New("agentframework: policy Action is required")
	errNilPolicyFunc = errors.New("agentframework: policy function is nil")
)

// ToolPolicy describes how one tool is guarded. Action is required and must
// be a hardcoded label such as "order.looked-up". The three resolvers receive
// the tool call's raw JSON arguments; a resolver error counts as unevaluated
// policy and follows OnGuardError.
type ToolPolicy struct {
	Action string
	Actor  func(ctx context.Context, args json.RawMessage) (string, error)
	Inputs func(ctx context.Context, args json.RawMessage) (map[string]arcjet.GuardPolicyInput, error)
	Rules  func(ctx context.Context, args json.RawMessage) ([]arcjet.GuardRuleInput, error)
	// CorrelationID, when set, wins over the ID carried by the context and
	// over the session's stored ID.
	CorrelationID string
	Metadata      arcjet.Metadata
	OnGuardError  arcjet.OnGuardError
	// OnDeny, when set, replaces the arcjet.GuardDenialResult returned to the
	// model on a DENY decision. It is not called when the guard is
	// unavailable; that path always returns arcjet.NewGuardUnavailableResult.
	OnDeny func(arcjet.GuardDecision) any
}

// guardedMarker identifies a tool already wrapped by GuardTool so a later
// wrapping pass can tell it apart from a bare tool.
type guardedMarker interface{ arcjetGuarded() }

type guardedTool struct {
	tool.FuncTool
	client *arcjet.GuardClient
	policy ToolPolicy
}

func (g *guardedTool) arcjetGuarded() {}

// ApprovalRequired delegates to the wrapped tool so a human approval gate
// survives wrapping. A tool without one reports false.
func (g *guardedTool) ApprovalRequired() bool {
	if a, ok := g.FuncTool.(tool.ApprovalRequiredTool); ok {
		return a.ApprovalRequired()
	}
	return false
}

// The wrapper forwards Initialize, Close and ApprovalRequired to the wrapped
// tool, and [guardedTool.Unwrap] returns that tool. Any other method outside
// tool.FuncTool is not reachable through the wrapper; take it from Unwrap.
//
// Call evaluates the policy, then runs the wrapped tool if allowed. A denial
// or an unavailable guard is returned as a successful result, not an error,
// so the model reads it and the run is not aborted: NewGuardDenialResult for
// a denial, or NewGuardUnavailableResult for an unavailable guard, unless
// ToolPolicy.OnDeny is set, in which case a denial returns whatever OnDeny
// produces instead.
//
// An error from the wrapped tool passes through unchanged, including one of
// Arcjet's own error types, which a tool that calls arcjet.GuardAction in its
// own body can return. Only this wrapper's own decision is converted: once
// the tool has run, its effect has happened, and reporting a nested guard's
// denial as this call being blocked would tell the model to retry something
// that already took effect.
func (g *guardedTool) Call(ctx context.Context, args string) (any, error) {
	raw := json.RawMessage(args)
	p := g.policy
	policy := arcjet.GuardActionPolicy{
		Action:        p.Action,
		CorrelationID: p.CorrelationID,
		Metadata:      p.Metadata,
		OnGuardError:  p.OnGuardError,
		Resolve: func(ctx context.Context) (arcjet.GuardActionInputs, error) {
			var in arcjet.GuardActionInputs
			var err error
			if p.Actor != nil {
				if in.Actor, err = p.Actor(ctx, raw); err != nil {
					return in, err
				}
			}
			if p.Inputs != nil {
				if in.Inputs, err = p.Inputs(ctx, raw); err != nil {
					return in, err
				}
			}
			if p.Rules != nil {
				if in.Rules, err = p.Rules(ctx, raw); err != nil {
					return in, err
				}
			}
			return in, nil
		},
	}
	// Whether the wrapped tool was entered. Once it has run, its effect has
	// happened, so an Arcjet error coming back from it belongs to a nested
	// guard on some other action and must not be reported as this call being
	// blocked.
	ran := false
	out, err := arcjet.GuardAction(ctx, g.client, policy, func(ctx context.Context) (any, error) {
		ran = true
		return g.FuncTool.Call(ctx, args)
	})
	var denied *arcjet.GuardDeniedError
	var unavailable *arcjet.GuardUnavailableError
	switch {
	case ran:
		return out, err
	// Unavailable is tested first: its Err may hold a *GuardDeniedError from
	// a nested guard on another action, and this action's policy never ran.
	case errors.As(err, &unavailable):
		return arcjet.NewGuardUnavailableResult(), nil
	case errors.As(err, &denied):
		if p.OnDeny != nil {
			if out := p.OnDeny(denied.Decision); !isNilValue(out) {
				return out, nil
			}
		}
		return arcjet.NewGuardDenialResult(denied.Decision), nil
	}
	return out, err
}

// isNilValue reports whether v is nil or a nil pointer, map, slice, func or
// channel held in a non-nil interface. A typed nil is not equal to nil, so
// the plain comparison misses it, and letting one through turns a denial
// into a null result or a wrapper around nothing.
func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}

// Unwrap returns the tool GuardTool wrapped. A caller that needs a method
// outside tool.FuncTool, or wants to hand the original to something that
// type-asserts on its concrete type, reaches it here.
func (g *guardedTool) Unwrap() tool.FuncTool { return g.FuncTool }

// Initialize forwards to the wrapped tool when it has one, so a tool that
// sets up state before its first call still gets that call. It is a no-op
// otherwise: guardedTool cannot know at compile time whether the tool it
// wraps has this method, so it always offers it.
func (g *guardedTool) Initialize(ctx context.Context) error {
	if inner, ok := g.FuncTool.(interface {
		Initialize(context.Context) error
	}); ok {
		return inner.Initialize(ctx)
	}
	return nil
}

// Close forwards to the wrapped tool when it has one. shelltool.Local owns a
// shell subprocess, and dropping its Close would leak that process for the
// life of the program. A no-op when the wrapped tool has no Close.
func (g *guardedTool) Close() error {
	if inner, ok := g.FuncTool.(interface{ Close() error }); ok {
		return inner.Close()
	}
	return nil
}

// alreadyGuarded reports whether t was produced by GuardTool.
//
// A tool hidden inside a wrapper that embeds tool.FuncTool, such as
// tool.ApprovalRequiredFunc, cannot be recognised: Go promotes only the
// methods of the embedded field's own interface type, so no marker of any
// visibility reaches the outer value. Apply GuardTool outermost, as its own
// documentation says, or the tool is guarded twice.
func alreadyGuarded(t tool.Tool) bool {
	_, ok := t.(guardedMarker)
	return ok
}

// GuardTool wraps t so every call is evaluated by Arcjet first. The result
// keeps t's name, description, schemas, and approval-required status.
//
// If t also needs tool.ApprovalRequiredFunc, apply that first and pass its
// result to GuardTool, not the other way round: ApprovalRequiredFunc's
// wrapper does not forward the guarded marker a later guarding pass looks
// for, so wrapping an already-guarded tool with it would let that tool be
// guarded a second time.
func GuardTool(client *arcjet.GuardClient, t tool.FuncTool, policy ToolPolicy) (tool.FuncTool, error) {
	if client == nil {
		return nil, errNilClient
	}
	if isNilValue(t) {
		return nil, errNilTool
	}
	if err := validateAction(policy.Action); err != nil {
		return nil, err
	}
	return &guardedTool{FuncTool: t, client: client, policy: policy}, nil
}

// MustGuardTool is like GuardTool but panics on a configuration error. It is
// intended for package-level initialization.
func MustGuardTool(client *arcjet.GuardClient, t tool.FuncTool, policy ToolPolicy) tool.FuncTool {
	guarded, err := GuardTool(client, t, policy)
	if err != nil {
		panic(err)
	}
	return guarded
}

// Args adapts a typed rule resolver to the raw-JSON form ToolPolicy.Rules
// takes. In is decoded the way functool decodes it: a struct input is the
// arguments object itself; any other input type arrives wrapped in a
// single-property object. The wrapped form must carry exactly one property;
// zero or more than one fails the call closed.
//
// Decoding uses encoding/json, not the framework's own decoder, which is
// unexported. Schema defaults are therefore not applied: a field the tool's
// schema defaults arrives here as its zero value while the tool's handler
// sees the default. Key a policy on a value the caller supplies rather than
// one the schema fills in.
func Args[In any](fn func(context.Context, In) ([]arcjet.GuardRuleInput, error)) func(context.Context, json.RawMessage) ([]arcjet.GuardRuleInput, error) {
	return func(ctx context.Context, raw json.RawMessage) ([]arcjet.GuardRuleInput, error) {
		in, err := decodeArgs[In](raw)
		if err != nil {
			return nil, fmt.Errorf("agentframework: decoding tool arguments: %w", err)
		}
		return fn(ctx, in)
	}
}

func decodeArgs[In any](raw json.RawMessage) (In, error) {
	var in In
	// The framework decodes empty arguments as an empty object rather than
	// as null, so a tool that takes no arguments is called with "".
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	typ := reflect.TypeFor[In]()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Struct {
		err := json.Unmarshal(raw, &in)
		return in, err
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return in, err
	}
	if len(wrapper) != 1 {
		return in, fmt.Errorf("expected one wrapped argument, got %d", len(wrapper))
	}
	for _, v := range wrapper {
		err := json.Unmarshal(v, &in)
		return in, err
	}
	return in, nil
}
