package arcjet

import (
	"context"
	"errors"
	"testing"
)

// A nil context is misconfiguration. A fail-closed helper must deny rather
// than panic on it, and must not invent a background context.
func TestGuardActionDeniesANilContext(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardTestClient(t, handler)

	ran := false
	//nolint:staticcheck // passing nil is the condition under test.
	_, err := GuardAction(nil, client, GuardActionPolicy{Action: "a.b"},
		func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) || !errors.Is(err, ErrGuardMisconfigured) {
		t.Fatalf("err = %v, want *GuardUnavailableError wrapping ErrGuardMisconfigured", err)
	}
	if ran {
		t.Fatal("fn ran with a nil context")
	}
}

// A caller passing through a header that was absent must not blank out an ID
// an outer layer already set.
func TestContextWithCorrelationIDIgnoresAnEmptyID(t *testing.T) {
	outer := ContextWithCorrelationID(context.Background(), "req_9")
	inner := ContextWithCorrelationID(outer, "")
	got, ok := CorrelationIDFromContext(inner)
	if !ok || got != "req_9" {
		t.Fatalf("id = %q ok = %v, want req_9: an empty ID must not shadow an outer one", got, ok)
	}
}

// The action runs under the ID the call resolved, so a nested guard or
// capture inside it joins the same Sequence.
func TestGuardActionPutsTheResolvedIDOnTheActionContext(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardTestClient(t, handler)

	var seen string
	_, err := GuardAction(context.Background(), client,
		GuardActionPolicy{Action: "a.b", CorrelationID: "policy_1"},
		func(ctx context.Context) (struct{}, error) {
			seen, _ = CorrelationIDFromContext(ctx)
			return struct{}{}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if seen != "policy_1" {
		t.Fatalf("id inside the action = %q, want policy_1", seen)
	}
}
