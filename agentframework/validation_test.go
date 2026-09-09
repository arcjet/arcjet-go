package agentframework

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/microsoft/agent-framework-go/tool"
	"github.com/microsoft/agent-framework-go/tool/functool"

	"github.com/arcjet/arcjet-go"
)

// The framework decodes empty tool arguments as an empty object, so a
// zero-argument tool must reach Guard and then run.
func TestDecodeArgsTreatsEmptyArgumentsAsAnEmptyObject(t *testing.T) {
	type noArgs struct{}
	if _, err := decodeArgs[noArgs](nil); err != nil {
		t.Fatalf("decodeArgs(nil) = %v; want no error", err)
	}
	if _, err := decodeArgs[noArgs](json.RawMessage("")); err != nil {
		t.Fatalf("decodeArgs(\"\") = %v; want no error", err)
	}
}

func TestGuardToolCallsGuardForAToolWithNoArguments(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	ran := 0
	base := noArgTool(t, &ran)
	// A resolver is what puts decodeArgs on the path; without one the empty
	// arguments are never decoded and the test would not cover the defect.
	guarded := MustGuardTool(client, base, ToolPolicy{
		Action: "status.read",
		Rules: Args(func(context.Context, struct{}) ([]arcjet.GuardRuleInput, error) {
			return nil, nil
		}),
	})
	if _, err := guarded.Call(t.Context(), ""); err != nil {
		t.Fatalf("Call = %v; want no error", err)
	}
	if ran != 1 {
		t.Fatalf("tool ran %d times; want 1", ran)
	}
	if decide.guardCalls() != 1 {
		t.Fatalf("guard calls = %d; want 1", decide.guardCalls())
	}
}

// An Action that Guard would reject as a label must fail at construction,
// not silently disable the guard for the life of the process.
func TestGuardToolRejectsAnActionThatIsNotAValidLabel(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	base, _ := newLookupTool(t)
	for _, action := range []string{"issue_refund", "Refund.Issued", "-refund", "refund-"} {
		if _, err := GuardTool(client, base, ToolPolicy{Action: action}); err == nil {
			t.Fatalf("GuardTool accepted Action %q; want an error", action)
		} else if !errors.Is(err, arcjet.ErrInvalidLabel) {
			t.Fatalf("GuardTool(%q) error = %v; want it to wrap ErrInvalidLabel", action, err)
		}
	}
	if _, err := GuardTool(client, base, ToolPolicy{Action: "refund.issued"}); err != nil {
		t.Fatalf("GuardTool rejected a valid Action: %v", err)
	}
}

func TestGuardMiddlewareRejectsAnInboundActionThatIsNotAValidLabel(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	cfg := MiddlewareConfig{Inbound: &InboundPolicy{Action: "message_received"}}
	if _, err := GuardMiddleware(client, cfg); err == nil {
		t.Fatal("GuardMiddleware accepted an invalid inbound Action; want an error")
	} else if !errors.Is(err, arcjet.ErrInvalidLabel) {
		t.Fatalf("error = %v; want it to wrap ErrInvalidLabel", err)
	}
}

// An OnDeny hook that returns nil must not turn a denial into a successful
// empty result the model reads as "the tool worked".
func TestGuardToolOnDenyReturningNilFallsBackToTheDenialResult(t *testing.T) {
	decide := &fakeDecide{resp: denyRateLimitResponse()}
	client := newTestClient(t, decide)
	base, calls := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{
		Action: "order.looked-up",
		OnDeny: func(arcjet.GuardDecision) any { return nil },
	})
	out, err := guarded.Call(t.Context(), `{"orderNumber":"o-1"}`)
	if err != nil {
		t.Fatalf("Call = %v; want no error", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("tool ran %d times; want 0", calls.Load())
	}
	payload, ok := out.(arcjet.GuardDenialResult)
	if !ok {
		t.Fatalf("result = %T (%v); want GuardDenialResult", out, out)
	}
	if !payload.ArcjetDenied {
		t.Fatal("arcjetDenied = false; want true")
	}
}

func noArgTool(t *testing.T, ran *int) tool.FuncTool {
	t.Helper()
	tl, err := functool.New(functool.Config{Name: "read_status", Description: "Read the status"},
		func(context.Context, struct{}) (string, error) {
			*ran++
			return "ok", nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return tl
}
