package arcjet

import (
	"context"
	"errors"
	"testing"
	"time"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

func TestOnGuardErrorZeroValueIsDeny(t *testing.T) {
	var o OnGuardError
	if o != OnGuardErrorDeny {
		t.Fatalf("zero value = %v, want deny", o)
	}
	if got := OnGuardErrorDeny.String(); got != "deny" {
		t.Fatalf("String() = %q", got)
	}
	if got := OnGuardErrorAllow.String(); got != "allow" {
		t.Fatalf("String() = %q", got)
	}
}

func TestGuardDeniedErrorMessage(t *testing.T) {
	err := &GuardDeniedError{Action: "refund.issued", Decision: GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonRateLimit}}
	if got := err.Error(); got != `arcjet: denied action "refund.issued" (RATE_LIMIT)` {
		t.Fatalf("Error() = %q", got)
	}
}

func TestGuardUnavailableErrorUnwraps(t *testing.T) {
	err := &GuardUnavailableError{Action: "refund.issued", Err: ErrInvalidLabel}
	if !errors.Is(err, ErrInvalidLabel) {
		t.Fatal("expected errors.Is to see the wrapped programmer error")
	}
	if got := err.Error(); got != `arcjet: policy for action "refund.issued" could not be evaluated: invalid guard label` {
		t.Fatalf("Error() = %q", got)
	}
	bare := &GuardUnavailableError{Action: "refund.issued"}
	if got := bare.Error(); got != `arcjet: policy for action "refund.issued" could not be evaluated` {
		t.Fatalf("Error() = %q", got)
	}
}

func guardActionAllowResponse() *decidev2.GuardResponse {
	return &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{
		Id:         "gdec_allow",
		Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
	}}
}

func guardActionDenyResponse() *decidev2.GuardResponse {
	return &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{
		Id:         "gdec_deny",
		Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_DENY,
		Reason:     decidev2.GuardReason_GUARD_REASON_RATE_LIMIT,
		RuleResults: []*decidev2.GuardRuleResult{{
			ResultId: "gres_deny",
			Type:     decidev2.GuardRuleType_GUARD_RULE_TYPE_TOKEN_BUCKET,
			Result: &decidev2.GuardRuleResult_TokenBucket{TokenBucket: &decidev2.ResultTokenBucket{
				Conclusion:         decidev2.GuardConclusion_GUARD_CONCLUSION_DENY,
				ResetAtUnixSeconds: uint32(time.Now().Add(30 * time.Second).Unix()),
			}},
		}},
	}}
}

// flushedEvents drains the capture queue and returns every event the fake
// Decide service received.
func flushedEvents(client *GuardClient, handler *testGuardHandler) []*decidev2.CaptureEvent {
	client.Flush(context.Background())
	return handler.capturedEvents()
}

func newGuardActionTestClient(t *testing.T, handler *testGuardHandler) *GuardClient {
	t.Helper()
	client, _ := newGuardTestClient(t, handler)
	client.captureBatchDelay = time.Hour // hold events until Flush
	return client
}

func TestGuardActionAllowRunsAndCapturesSuccess(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardActionTestClient(t, handler)

	out, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "order.looked-up"},
		func(context.Context) (string, error) { return "shipped", nil })
	if err != nil || out != "shipped" {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	if handler.guardCalls != 1 {
		t.Fatalf("guard calls = %d, want 1 even with no rules", handler.guardCalls)
	}
	if len(handler.seen.GetRuleSubmissions()) != 0 {
		t.Fatalf("rule submissions = %d, want 0", len(handler.seen.GetRuleSubmissions()))
	}
	events := flushedEvents(client, handler)
	if len(events) != 1 {
		t.Fatalf("captured %d events, want 1", len(events))
	}
	if events[0].GetAction() != "order.looked-up" || events[0].GetDecisionId() != "gdec_allow" {
		t.Fatalf("event = %v", events[0])
	}
	if got := events[0].GetMetadataJson()["outcome"]; got != `"success"` {
		t.Fatalf("outcome = %s, want \"success\"", got)
	}
}

func TestGuardActionDenyReturnsDeniedErrorRegardlessOfPosture(t *testing.T) {
	for _, posture := range []OnGuardError{OnGuardErrorDeny, OnGuardErrorAllow} {
		handler := &testGuardHandler{resp: guardActionDenyResponse()}
		client := newGuardActionTestClient(t, handler)
		ran := false
		_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "refund.issued", OnGuardError: posture},
			func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
		var denied *GuardDeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("posture %v: err = %v, want *GuardDeniedError", posture, err)
		}
		if ran {
			t.Fatalf("posture %v: fn ran after a DENY", posture)
		}
		if denied.Action != "refund.issued" || denied.Decision.Reason != ReasonRateLimit || denied.Decision.ID != "gdec_deny" {
			t.Fatalf("posture %v: denied = %+v", posture, denied)
		}
		events := flushedEvents(client, handler)
		if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"denied"` || events[0].GetDecisionId() != "gdec_deny" {
			t.Fatalf("posture %v: events = %v", posture, events)
		}
	}
}

func TestGuardActionUnavailableFailsClosedByDefault(t *testing.T) {
	handler := &testGuardHandler{errToReturn: errors.New("decide unreachable")}
	client := newGuardActionTestClient(t, handler)
	ran := false
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "refund.issued"},
		func(context.Context) (int, error) { ran = true; return 1, nil })
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want *GuardUnavailableError", err)
	}
	if ran {
		t.Fatal("fn ran while the policy was unevaluated under the default posture")
	}
	if unavailable.Err == nil {
		t.Fatal("Err must carry the transport error")
	}
	if unavailable.Decision == nil || !unavailable.Decision.HasFailedOpen() {
		t.Fatalf("Decision = %+v, want the fail-open decision", unavailable.Decision)
	}
	events := flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"unavailable"` {
		t.Fatalf("events = %v", events)
	}
	if events[0].GetDecisionId() != "" {
		t.Fatalf("decision id = %q, want empty for a synthesized decision", events[0].GetDecisionId())
	}
}

func TestGuardActionOutOfRangePostureFailsClosed(t *testing.T) {
	// Only OnGuardErrorAllow opts into running fn on unevaluated policy. A
	// posture value outside the two named constants must still fail closed.
	handler := &testGuardHandler{errToReturn: errors.New("decide unreachable")}
	client := newGuardActionTestClient(t, handler)
	ran := false
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "refund.issued", OnGuardError: OnGuardError(2)},
		func(context.Context) (int, error) { ran = true; return 1, nil })
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want *GuardUnavailableError", err)
	}
	if ran {
		t.Fatal("fn ran while the policy was unevaluated under an out-of-range posture")
	}
}

func TestGuardActionUnavailableAllowRunsDegraded(t *testing.T) {
	handler := &testGuardHandler{errToReturn: errors.New("decide unreachable")}
	client := newGuardActionTestClient(t, handler)
	out, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "order.looked-up", OnGuardError: OnGuardErrorAllow},
		func(context.Context) (int, error) { return 42, nil })
	if err != nil || out != 42 {
		t.Fatalf("out = %d, err = %v", out, err)
	}
	events := flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"degraded"` {
		t.Fatalf("events = %v", events)
	}
}

func TestGuardActionFnErrorIsReturnedUnchangedAndCaptured(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardActionTestClient(t, handler)
	sentinel := errors.New("db down")
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "order.looked-up"},
		func(context.Context) (int, error) { return 0, sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the fn error unchanged", err)
	}
	events := flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"error"` {
		t.Fatalf("events = %v", events)
	}
}

func TestGuardActionOutcomeOverridesCallerMetadata(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardActionTestClient(t, handler)
	_, err := GuardAction(context.Background(), client,
		GuardActionPolicy{Action: "order.looked-up", Metadata: Metadata{"outcome": "spoofed", "user": "user_1"}},
		func(context.Context) (struct{}, error) { return struct{}{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	events := flushedEvents(client, handler)
	md := events[0].GetMetadataJson()
	if md["outcome"] != `"success"` || md["user"] != `"user_1"` {
		t.Fatalf("metadata = %v", md)
	}
}

func TestGuardActionCorrelationPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		ctx      context.Context
		explicit string
		want     string
	}{
		{"explicit wins over context", ContextWithCorrelationId(context.Background(), "ctx_1"), "explicit_1", "explicit_1"},
		{"context when no explicit", ContextWithCorrelationId(context.Background(), "ctx_1"), "", "ctx_1"},
		{"none", context.Background(), "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &testGuardHandler{resp: guardActionAllowResponse()}
			client := newGuardActionTestClient(t, handler)
			_, err := GuardAction(tc.ctx, client, GuardActionPolicy{Action: "order.looked-up", CorrelationId: tc.explicit},
				func(context.Context) (struct{}, error) { return struct{}{}, nil })
			if err != nil {
				t.Fatal(err)
			}
			if got := handler.seen.GetCorrelationId(); got != tc.want {
				t.Fatalf("guard correlation = %q, want %q", got, tc.want)
			}
			if got := flushedEvents(client, handler)[0].GetCorrelationId(); got != tc.want {
				t.Fatalf("capture correlation = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGuardActionProgrammerErrorIsWrappedAsUnavailable(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardActionTestClient(t, handler)
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "Not A Label"},
		func(context.Context) (struct{}, error) { return struct{}{}, nil })
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) || !errors.Is(err, ErrInvalidLabel) {
		t.Fatalf("err = %v, want *GuardUnavailableError wrapping ErrInvalidLabel", err)
	}
	if unavailable.Decision != nil {
		t.Fatalf("Decision = %+v, want nil for a zero decision", unavailable.Decision)
	}
	if handler.guardCalls != 0 {
		t.Fatalf("guard calls = %d, want 0", handler.guardCalls)
	}

	// Under allow the same programmer error lets fn run, degraded, still
	// without a Guard call: there was no valid request to send.
	handler = &testGuardHandler{resp: guardActionAllowResponse()}
	client = newGuardActionTestClient(t, handler)
	ran := false
	_, err = GuardAction(context.Background(), client, GuardActionPolicy{Action: "Not A Label", OnGuardError: OnGuardErrorAllow},
		func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
	if err != nil || !ran {
		t.Fatalf("err = %v, ran = %v; want fn to run under allow", err, ran)
	}
	if handler.guardCalls != 0 {
		t.Fatalf("guard calls = %d, want 0", handler.guardCalls)
	}
	if events := flushedEvents(client, handler); len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"degraded"` || events[0].GetDecisionId() != "" {
		t.Fatalf("events = %v", events)
	}
}

func TestGuardActionResolveReplacesStaticInputs(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardActionTestClient(t, handler)
	limit, err := GuardTokenBucket(GuardTokenBucketOptions{Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10})
	if err != nil {
		t.Fatal(err)
	}
	_, err = GuardAction(context.Background(), client, GuardActionPolicy{
		Action: "order.looked-up",
		Actor:  "static-actor",
		Inputs: map[string]GuardPolicyInput{"static": GuardPolicyServerString("x")},
		Resolve: func(context.Context) (GuardActionInputs, error) {
			return GuardActionInputs{
				Actor:  "resolved-actor",
				Inputs: map[string]GuardPolicyInput{"recipient": GuardPolicyServerString("a@example.com")},
				Rules:  []GuardRuleInput{limit.Key("user_1", 1)},
			}, nil
		},
	}, func(context.Context) (struct{}, error) { return struct{}{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := handler.seen.GetActor(); got != "resolved-actor" {
		t.Fatalf("actor = %q, want the resolved actor", got)
	}
	if got := len(handler.seen.GetRuleSubmissions()); got != 1 {
		t.Fatalf("rule submissions = %d, want 1", got)
	}
	inputs := handler.seen.GetPolicyInputs()
	if _, ok := inputs["recipient"]; !ok {
		t.Fatalf("resolved input missing from request: %v", inputs)
	}
	if _, ok := inputs["static"]; ok {
		t.Fatalf("static input must be replaced, not merged: %v", inputs)
	}
}

func TestGuardActionResolveErrorIsUnevaluated(t *testing.T) {
	boom := errors.New("cannot derive rules")
	resolve := func(context.Context) (GuardActionInputs, error) { return GuardActionInputs{}, boom }

	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardActionTestClient(t, handler)
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "order.looked-up", Resolve: resolve},
		func(context.Context) (struct{}, error) { return struct{}{}, nil })
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want unavailable wrapping the resolve error", err)
	}
	if handler.guardCalls != 0 {
		t.Fatalf("guard calls = %d, want 0 when Resolve fails", handler.guardCalls)
	}
	if events := flushedEvents(client, handler); len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"unavailable"` {
		t.Fatalf("events = %v", events)
	}

	handler = &testGuardHandler{resp: guardActionAllowResponse()}
	client = newGuardActionTestClient(t, handler)
	ran := false
	_, err = GuardAction(context.Background(), client, GuardActionPolicy{Action: "order.looked-up", Resolve: resolve, OnGuardError: OnGuardErrorAllow},
		func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
	if err != nil || !ran {
		t.Fatalf("err = %v, ran = %v; want fn to run under allow", err, ran)
	}
	if events := flushedEvents(client, handler); len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"degraded"` {
		t.Fatalf("events = %v", events)
	}
}

func TestGuardActionNilFn(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardActionTestClient(t, handler)
	_, err := GuardAction[int](context.Background(), client, GuardActionPolicy{Action: "order.looked-up"}, nil)
	if !errors.Is(err, ErrNilAction) {
		t.Fatalf("err = %v, want ErrNilAction", err)
	}
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want *GuardUnavailableError", err)
	}
	if handler.guardCalls != 0 {
		t.Fatal("Guard must not be called for a nil fn")
	}
}

func TestGuardActionNilClientFailsClosed(t *testing.T) {
	var client *GuardClient
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "order.looked-up"},
		func(context.Context) (struct{}, error) { return struct{}{}, nil })
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) || !errors.Is(err, ErrNilClient) {
		t.Fatalf("err = %v, want unavailable wrapping ErrNilClient", err)
	}
}

// partialAllowResponse is an ALLOW decision the server completed but in
// which one rule errored. Guard returns it with a nil error, so it is the
// case where HasFailedOpen() alone decides that policy was not evaluated.
func partialAllowResponse() *decidev2.GuardResponse {
	return &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{
		Id:         "gdec_partial",
		Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
		RuleResults: []*decidev2.GuardRuleResult{{
			ResultId: "gres_err",
			Type:     decidev2.GuardRuleType_GUARD_RULE_TYPE_PROMPT_INJECTION,
			Result:   &decidev2.GuardRuleResult_Error{Error: &decidev2.ResultError{Message: "classifier timed out"}},
		}},
	}}
}

func TestGuardActionFailedOpenDecisionWithoutErrorIsUnevaluated(t *testing.T) {
	// Under the default posture the action is blocked even though Guard
	// returned no error: the decision itself reports it failed open.
	handler := &testGuardHandler{resp: partialAllowResponse()}
	client := newGuardActionTestClient(t, handler)
	ran := false
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "refund.issued"},
		func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want *GuardUnavailableError", err)
	}
	if ran {
		t.Fatal("fn ran on a decision that failed open")
	}
	if unavailable.Err != nil {
		t.Fatalf("Err = %v, want nil: Guard returned no error, the decision failed open", unavailable.Err)
	}
	if unavailable.Decision == nil || unavailable.Decision.ID != "gdec_partial" || !unavailable.Decision.HasFailedOpen() {
		t.Fatalf("Decision = %+v", unavailable.Decision)
	}
	events := flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"unavailable"` || events[0].GetDecisionId() != "gdec_partial" {
		t.Fatalf("events = %v", events)
	}

	// Under allow the action runs, the outcome is degraded, and the decision
	// ID is kept: this is the record that says policy judged the action in
	// part, as opposed to not at all.
	handler = &testGuardHandler{resp: partialAllowResponse()}
	client = newGuardActionTestClient(t, handler)
	out, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "refund.issued", OnGuardError: OnGuardErrorAllow},
		func(context.Context) (string, error) { return "ran", nil })
	if err != nil || out != "ran" {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	events = flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"degraded"` {
		t.Fatalf("events = %v", events)
	}
	if events[0].GetDecisionId() != "gdec_partial" {
		t.Fatalf("decision id = %q, want gdec_partial kept on a degraded outcome", events[0].GetDecisionId())
	}
}

func TestGuardActionCaptureFailureDoesNotAffectResult(t *testing.T) {
	handler := &testGuardHandler{resp: guardActionAllowResponse(), captureErr: errors.New("capture down")}
	client := newGuardActionTestClient(t, handler)
	out, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "order.looked-up"},
		func(context.Context) (string, error) { return "shipped", nil })
	if err != nil || out != "shipped" {
		t.Fatalf("out = %q, err = %v; a capture failure must never reach the caller", out, err)
	}
	client.Flush(context.Background()) // the send fails here; nothing propagates
	if handler.guardCalls != 1 {
		t.Fatalf("guard calls = %d", handler.guardCalls)
	}
}

func TestGuardAndCaptureIgnoreContextCorrelation(t *testing.T) {
	// Only the helpers read the context. The core calls keep their documented
	// behaviour of never inheriting a correlation ID from ambient context.
	handler := &testGuardHandler{resp: guardActionAllowResponse()}
	client := newGuardActionTestClient(t, handler)
	ctx := ContextWithCorrelationId(context.Background(), "ctx_1")
	if _, err := client.Guard(ctx, GuardRequest{Label: "order.looked-up"}); err != nil {
		t.Fatal(err)
	}
	if got := handler.seen.GetCorrelationId(); got != "" {
		t.Fatalf("Guard inherited correlation %q from the context", got)
	}
	client.Capture(CaptureEvent{Action: "order.looked-up"})
	events := flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetCorrelationId() != "" {
		t.Fatalf("Capture inherited correlation: %v", events)
	}
}

// guardActionUnspecifiedConclusionResponse is a decision whose conclusion is
// the proto's unspecified zero value: neither ALLOW nor DENY, and Guard
// returns it with a nil error. It is distinct from guardActionAllowResponse
// so the decision ID can be told apart on the captured event.
func guardActionUnspecifiedConclusionResponse() *decidev2.GuardResponse {
	return &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{
		Id:         "gdec_unspecified",
		Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_UNSPECIFIED,
	}}
}

func TestGuardActionUnrecognisedConclusionFailsClosed(t *testing.T) {
	// A decision that is neither a clean ALLOW nor a DENY must not fall
	// through as evaluated. Guard returns this one with a nil error, so only
	// checking HasFailedOpen()/guardErr would let it run the action.
	handler := &testGuardHandler{resp: guardActionUnspecifiedConclusionResponse()}
	client := newGuardActionTestClient(t, handler)
	ran := false
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "refund.issued"},
		func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
	var unavailable *GuardUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want *GuardUnavailableError", err)
	}
	if ran {
		t.Fatal("fn ran on a decision that is neither allow nor deny")
	}
	// The guard call happened and returned a real decision: an empty
	// Conclusion must not be mistaken for no decision at all.
	if unavailable.Decision == nil || unavailable.Decision.ID != "gdec_unspecified" {
		t.Fatalf("Decision = %+v, want the fixture's decision kept", unavailable.Decision)
	}
	events := flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"unavailable"` || events[0].GetDecisionId() != "gdec_unspecified" {
		t.Fatalf("events = %v", events)
	}

	// Under allow the action runs, degraded, and the decision ID is kept.
	handler = &testGuardHandler{resp: guardActionUnspecifiedConclusionResponse()}
	client = newGuardActionTestClient(t, handler)
	out, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "refund.issued", OnGuardError: OnGuardErrorAllow},
		func(context.Context) (string, error) { return "ran", nil })
	if err != nil || out != "ran" {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	events = flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"degraded"` {
		t.Fatalf("events = %v", events)
	}
	if events[0].GetDecisionId() != "gdec_unspecified" {
		t.Fatalf("decision id = %q, want gdec_unspecified kept on a degraded outcome", events[0].GetDecisionId())
	}
}

func TestGuardActionDenyWinsOverCoOccurringError(t *testing.T) {
	// A locally enforced denial whose reporting failed comes back from
	// client.Guard as a DENY decision together with a non-nil error (see
	// reportLocalPolicyDenial in guard.go): the local sensitive-info
	// evaluator denies the call, then the best-effort RPC that reports the
	// denial to the server fails. The completed decision must win: the
	// caller gets a denial, not an unavailable policy.
	//
	// Setting both testGuardHandler.resp and errToReturn does not produce
	// this: errToReturn short-circuits before resp is ever read (see
	// testGuardHandler.Guard), so that combination instead exercises the
	// ordinary fail-open transport-error path, which TestGuardActionUnavailableFailsClosedByDefault
	// already covers.
	for _, posture := range []OnGuardError{OnGuardErrorDeny, OnGuardErrorAllow} {
		handler := &testGuardHandler{
			policyResponses: []*decidev2.GetGuardPolicyResponse{projectedSensitiveInfoPolicy("rev-1", decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE)},
			errToReturn:     errors.New("reporting failed"),
		}
		client := newGuardActionTestClient(t, handler)
		client.policy.backend = policySensitiveInfoBackend{}
		ran := false
		_, err := GuardAction(context.Background(), client, GuardActionPolicy{
			Action:       "message.send",
			OnGuardError: posture,
			Inputs:       map[string]GuardPolicyInput{"body": GuardPolicyLocalString("user@example.com")},
		}, func(context.Context) (struct{}, error) { ran = true; return struct{}{}, nil })
		var denied *GuardDeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("posture %v: err = %v, want *GuardDeniedError", posture, err)
		}
		if ran {
			t.Fatalf("posture %v: fn ran on a denial", posture)
		}
		events := flushedEvents(client, handler)
		if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"denied"` {
			t.Fatalf("posture %v: events = %v", posture, events)
		}
	}
}

func TestGuardActionDegradedThenFnErrorCapturesError(t *testing.T) {
	// An action that ran and then failed records "error", which takes
	// precedence over the degraded condition.
	handler := &testGuardHandler{errToReturn: errors.New("decide unreachable")}
	client := newGuardActionTestClient(t, handler)
	sentinel := errors.New("db down")
	_, err := GuardAction(context.Background(), client, GuardActionPolicy{Action: "refund.issued", OnGuardError: OnGuardErrorAllow},
		func(context.Context) (int, error) { return 0, sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the fn error unchanged", err)
	}
	events := flushedEvents(client, handler)
	if len(events) != 1 || events[0].GetMetadataJson()["outcome"] != `"error"` {
		t.Fatalf("events = %v, want outcome error taking precedence over degraded", events)
	}
}
