package arcjet

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Guard marks every unusable request with ErrGuardMisconfigured while keeping
// the specific cause matchable, so a caller can ask either question.
func TestGuardMarksMisconfiguredRequests(t *testing.T) {
	limit, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 5, Interval: time.Hour, Capacity: 5, Bucket: "b",
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		req   GuardRequest
		cause error
		nilCl bool
	}{
		{name: "nil client", req: GuardRequest{Label: "a.b"}, cause: ErrNilClient, nilCl: true},
		{name: "invalid label", req: GuardRequest{Label: "Not A Label"}, cause: ErrInvalidLabel},
		{name: "nil rule", req: GuardRequest{Label: "a.b", Rules: []GuardRuleInput{nil}}, cause: ErrNilRule},
		{name: "unbindable rule", req: GuardRequest{Label: "a.b", Rules: []GuardRuleInput{limit.Key("", 1)}}, cause: ErrEmptyKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var client *GuardClient
			if !tc.nilCl {
				handler := &testGuardHandler{resp: guardActionAllowResponse()}
				client, _ = newGuardTestClient(t, handler)
			}
			decision, err := client.Guard(context.Background(), tc.req)
			if !errors.Is(err, ErrGuardMisconfigured) {
				t.Fatalf("err = %v, want it to wrap ErrGuardMisconfigured", err)
			}
			if !errors.Is(err, tc.cause) {
				t.Fatalf("err = %v, want it to still wrap %v", err, tc.cause)
			}
			if decision.ID != "" || decision.Conclusion != "" {
				t.Fatalf("decision = %+v, want the zero value", decision)
			}
		})
	}
}

// The whole point of the marker: OnGuardErrorAllow covers availability, so a
// misconfigured request denies whatever it is set to.
func TestGuardActionDeniesEveryMisconfiguredClassUnderAllow(t *testing.T) {
	limit, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 5, Interval: time.Hour, Capacity: 5, Bucket: "b",
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		policy GuardActionPolicy
		cause  error
	}{
		{
			name:   "invalid label",
			policy: GuardActionPolicy{Action: "Not A Label", OnGuardError: OnGuardErrorAllow},
			cause:  ErrInvalidLabel,
		},
		{
			name:   "nil rule",
			policy: GuardActionPolicy{Action: "a.b", Rules: []GuardRuleInput{nil}, OnGuardError: OnGuardErrorAllow},
			cause:  ErrNilRule,
		},
		{
			name:   "unbindable rule",
			policy: GuardActionPolicy{Action: "a.b", Rules: []GuardRuleInput{limit.Key("", 1)}, OnGuardError: OnGuardErrorAllow},
			cause:  ErrEmptyKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &testGuardHandler{resp: guardActionAllowResponse()}
			client, _ := newGuardTestClient(t, handler)
			ran := false
			_, err := GuardAction(context.Background(), client, tc.policy,
				func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
			var unavailable *GuardUnavailableError
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %v, want *GuardUnavailableError", err)
			}
			if !errors.Is(err, tc.cause) {
				t.Fatalf("err = %v, want it to wrap %v", err, tc.cause)
			}
			if ran {
				t.Fatal("fn ran under a misconfigured policy; allow covers availability only")
			}
		})
	}
}

// Degradation is the other class and must still honour OnGuardError, or the
// marker would have made the helper fail closed on every outage.
func TestGuardActionStillAllowsOnDegradation(t *testing.T) {
	handler := &testGuardHandler{errToReturn: errors.New("transport boom")}
	client, _ := newGuardTestClient(t, handler)
	ran := false
	_, err := GuardAction(context.Background(), client,
		GuardActionPolicy{Action: "a.b", OnGuardError: OnGuardErrorAllow},
		func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
	if err != nil {
		t.Fatalf("err = %v, want nil under allow on degradation", err)
	}
	if !ran {
		t.Fatal("fn did not run; degradation must still honour OnGuardErrorAllow")
	}
}
