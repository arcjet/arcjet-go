package agentframework

import (
	"testing"

	"github.com/microsoft/agent-framework-go/tool"

	"github.com/arcjet/arcjet-go"
)

type nilTool struct{ tool.FuncTool }

// A typed nil is not equal to nil, so GuardTool must look at the value.
func TestGuardToolRejectsATypedNilTool(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	var typed *nilTool
	if _, err := GuardTool(client, typed, ToolPolicy{Action: "a.b"}); err == nil {
		t.Fatal("GuardTool accepted a typed-nil tool")
	}
}

// GuardTools must reject it before the caller's policy function runs, since
// that function is documented as the place to switch on t.Name().
func TestGuardToolsRejectsATypedNilBeforeCallingThePolicy(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	var typed *nilTool
	called := false
	_, err := GuardTools(client, []tool.Tool{typed}, func(tool.Tool) (ToolPolicy, bool) {
		called = true
		return ToolPolicy{Action: "a.b"}, true
	})
	if err == nil {
		t.Fatal("GuardTools accepted a typed-nil tool")
	}
	if called {
		t.Fatal("the policy function ran on a typed-nil tool; it is documented to call t.Name()")
	}
}

// An OnDeny hook returning a typed nil must not become a null tool result.
func TestGuardToolOnDenyReturningATypedNilFallsBackToTheDenialResult(t *testing.T) {
	type reshaped struct{ Blocked bool }
	decide := &fakeDecide{resp: denyRateLimitResponse()}
	client := newTestClient(t, decide)
	base, calls := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{
		Action: "order.looked-up",
		OnDeny: func(arcjet.GuardDecision) any {
			var out *reshaped
			return out
		},
	})
	out, err := guarded.Call(t.Context(), `{"orderNumber":"o-1"}`)
	if err != nil {
		t.Fatalf("Call = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("tool ran %d times, want 0", calls.Load())
	}
	if _, ok := out.(arcjet.GuardDenialResult); !ok {
		t.Fatalf("result = %#v, want GuardDenialResult rather than a typed nil", out)
	}
}
