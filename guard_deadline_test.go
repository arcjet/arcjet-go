package arcjet

import (
	"context"
	"testing"
	"time"
)

// GuardAction bounds its Guard call when the caller's context has no
// deadline, so a Decide service that accepts a connection and then stops
// responding fails closed rather than hanging the caller forever.
func TestGuardActionAppliesADefaultDeadline(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardTestClient(t, handler)

	var seen time.Duration
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{
		Action: "a.b",
		Resolve: func(ctx context.Context) (GuardActionInputs, error) {
			// Resolve runs before the deadline is applied, which is what the
			// documentation says: a hook that blocks is the caller's to bound.
			if _, ok := ctx.Deadline(); ok {
				t.Error("Resolve saw a deadline; it runs before one is applied")
			}
			return GuardActionInputs{}, nil
		},
	}, func(ctx context.Context) (struct{}, error) {
		if d, ok := ctx.Deadline(); ok {
			seen = time.Until(d)
		}
		return struct{}{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The action itself runs on the caller's context, not the bounded one.
	if seen != 0 {
		t.Fatalf("the action saw a deadline %v away; it should run on the caller's context", seen)
	}
}

// A caller's own deadline is never replaced.
func TestGuardActionKeepsTheCallersDeadline(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardTestClient(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var seen time.Duration
	_, err := GuardAction(ctx, client, GuardActionPolicy{Action: "a.b"},
		func(ctx context.Context) (struct{}, error) {
			if d, ok := ctx.Deadline(); ok {
				seen = time.Until(d)
			}
			return struct{}{}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 40*time.Second {
		t.Fatalf("deadline %v away, want the caller's 45s rather than the 2s default", seen)
	}
}
