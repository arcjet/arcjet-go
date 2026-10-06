package arcjet

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
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

// Guard bounds its own RPC when the caller's context has no deadline, so
// every Guard caller is covered rather than only the ones going through
// GuardAction. ENG-1459.
func TestGuardAppliesADefaultDeadline(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardTestClient(t, handler)

	if _, err := client.Guard(context.Background(), GuardRequest{Label: "a.b"}); err != nil {
		t.Fatal(err)
	}

	handler.mu.Lock()
	saw, left := handler.sawDeadline, handler.deadlineLeft
	handler.mu.Unlock()
	if !saw {
		t.Fatal("Guard reached the Decide service with no deadline")
	}
	if left < 1500*time.Millisecond || left > defaultGuardTimeout {
		t.Errorf("deadline remaining = %s, want 1.5s–%s", left, defaultGuardTimeout)
	}
}

// A caller's own deadline is never replaced, in either direction. The short
// case is the one that matters: overriding it upwards would make Guard
// outlive a bound the caller chose.
func TestGuardKeepsTheCallersDeadline(t *testing.T) {
	cases := []struct {
		name             string
		timeout          time.Duration
		wantMin, wantMax time.Duration
	}{
		{name: "shorter than the default", timeout: 200 * time.Millisecond, wantMin: time.Millisecond, wantMax: 250 * time.Millisecond},
		{name: "longer than the default", timeout: 45 * time.Second, wantMin: 40 * time.Second, wantMax: 45100 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &testGuardHandler{resp: guardActionAllowResponse()}
			client := newGuardTestClient(t, handler)

			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			if _, err := client.Guard(ctx, GuardRequest{Label: "a.b"}); err != nil {
				t.Fatal(err)
			}

			handler.mu.Lock()
			saw, left := handler.sawDeadline, handler.deadlineLeft
			handler.mu.Unlock()
			if !saw {
				t.Fatal("Guard reached the Decide service with no deadline")
			}
			if left < tc.wantMin || left > tc.wantMax {
				t.Errorf("deadline remaining = %s, want %s–%s (the caller's, not the %s default)", left, tc.wantMin, tc.wantMax, defaultGuardTimeout)
			}
		})
	}
}

// A Decide service that accepts the connection and then stops responding
// returns within the default rather than blocking forever, and reports the
// expiry as the fail-open transport failure documented on Guard: a usable
// ALLOW plus a connect error coded deadline_exceeded.
func TestGuardReturnsWhenTheServerHangs(t *testing.T) {
	handler := &testGuardHandler{hangUntilDone: true}
	client := newGuardTestClient(t, handler)

	start := time.Now()
	decision, err := client.Guard(context.Background(), GuardRequest{Label: "a.b"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a deadline error from a hung server")
	}
	if elapsed < time.Second {
		t.Fatalf("returned after %s; expected to wait for the %s default", elapsed, defaultGuardTimeout)
	}
	if elapsed > 2*defaultGuardTimeout {
		t.Fatalf("returned after %s; the %s default should have bounded it", elapsed, defaultGuardTimeout)
	}
	// The error shape Guard documents, pinned so the doc comment cannot drift
	// from the behaviour. errors.Is(err, context.DeadlineExceeded) is
	// deliberately NOT asserted: whether the error unwraps to the sentinel
	// depends on which side of the RPC observes the expiry first. When connect
	// builds the error from the local context it wraps the sentinel; when it
	// decodes a deadline_exceeded status off the wire it carries a plain
	// string and the sentinel is lost. Both happen here, so a caller has to
	// test the code. Asserting the sentinel either way would be flaky.
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("err = %#v, want *connect.Error", err)
	}
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Errorf("connect.CodeOf(err) = %v, want %v (err = %v)", got, connect.CodeDeadlineExceeded, err)
	}
	if got, want := err.Error(), "deadline_exceeded: context deadline exceeded"; got != want {
		t.Errorf("err.Error() = %q, want %q", got, want)
	}
	// Fail-open, as for any other transport failure: the caller gets a usable
	// decision that still reports the degradation.
	if !decision.IsAllowed() {
		t.Error("expiry should fail open to a usable ALLOW")
	}
	if !decision.HasFailedOpen() {
		t.Error("expiry should be visible via HasFailedOpen")
	}
}

// GuardAction and a bare Guard call report the same expiry, so a caller that
// drops down to Guard keeps the error it already handles — wrapped, under the
// default fail-closed OnGuardError.
func TestGuardActionReportsTheSameExpiryAsGuard(t *testing.T) {
	handler := &testGuardHandler{hangUntilDone: true}
	client := newGuardTestClient(t, handler)

	ran := false
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "a.b"},
		func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })

	if ran {
		t.Error("the action ran despite an unevaluated policy")
	}
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %#v, want *GuardUnavailableError", err)
	}
	// The code survives the wrapper, so a caller moving between the two APIs
	// keeps the check it already has.
	if got := connect.CodeOf(unavailable.Err); got != connect.CodeDeadlineExceeded {
		t.Errorf("wrapped code = %v, want %v (err = %v)", got, connect.CodeDeadlineExceeded, unavailable.Err)
	}
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Errorf("code through the wrapper = %v, want %v (err = %v)", got, connect.CodeDeadlineExceeded, err)
	}
}
