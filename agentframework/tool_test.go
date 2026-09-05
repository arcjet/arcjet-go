package agentframework

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/microsoft/agent-framework-go/agent"
	"github.com/microsoft/agent-framework-go/tool"

	"github.com/arcjet/arcjet-go"
)

func TestGuardToolValidation(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	base, _ := newLookupTool(t)
	if _, err := GuardTool(nil, base, ToolPolicy{Action: "order.looked-up"}); !errors.Is(err, errNilClient) {
		t.Fatalf("nil client: err = %v", err)
	}
	if _, err := GuardTool(client, nil, ToolPolicy{Action: "order.looked-up"}); !errors.Is(err, errNilTool) {
		t.Fatalf("nil tool: err = %v", err)
	}
	if _, err := GuardTool(client, base, ToolPolicy{}); !errors.Is(err, errMissingAction) {
		t.Fatalf("missing action: err = %v", err)
	}
}

func TestGuardToolPreservesIdentity(t *testing.T) {
	client := newTestClient(t, &fakeDecide{resp: allowResponse()})
	base, _ := newLookupTool(t)
	guarded, err := GuardTool(client, base, ToolPolicy{Action: "order.looked-up"})
	if err != nil {
		t.Fatal(err)
	}
	if guarded.Name() != base.Name() || guarded.Description() != base.Description() {
		t.Fatal("name or description changed")
	}
	if guarded.Schema() == nil || guarded.ReturnSchema() == nil {
		t.Fatal("schemas must pass through")
	}
	if _, ok := guarded.(guardedMarker); !ok {
		t.Fatal("wrapper must carry the guarded marker")
	}
}

func TestGuardToolForwardsApprovalRequired(t *testing.T) {
	client := newTestClient(t, &fakeDecide{resp: allowResponse()})
	base, _ := newLookupTool(t)
	plain, _ := GuardTool(client, base, ToolPolicy{Action: "order.looked-up"})
	if a, ok := plain.(tool.ApprovalRequiredTool); !ok || a.ApprovalRequired() {
		t.Fatal("a tool without approval must report ApprovalRequired() == false")
	}
	needsApproval, _ := GuardTool(client, tool.ApprovalRequiredFunc(base), ToolPolicy{Action: "order.looked-up"})
	if a, ok := needsApproval.(tool.ApprovalRequiredTool); !ok || !a.ApprovalRequired() {
		t.Fatal("approval-required status was lost by wrapping")
	}
}

func TestGuardToolDenialIsASuccessfulResultThroughTheLoop(t *testing.T) {
	decide := &fakeDecide{resp: denyRateLimitResponse()}
	client := newTestClient(t, decide)
	base, calls := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{Action: "order.looked-up"})
	runner := &scriptedRunner{turns: [][]*agent.ResponseUpdate{
		{functionCall("call_1", "lookup_order", `{"orderNumber":"o-1"}`)},
		{assistantTextUpdate("done")},
	}}
	a := newAgent(runner, agent.Config{Tools: []tool.Tool{guarded}})
	if _, err := a.RunText(t.Context(), "where is my order?").Collect(); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("tool ran %d times; want 0", *calls)
	}
	if runner.providerCalls() != 2 {
		t.Fatalf("provider calls = %d; want 2 (the run must not abort)", runner.providerCalls())
	}
	result := lastFunctionResult(t, runner.seen[1])
	if result.CallID != "call_1" {
		t.Fatalf("call id = %q", result.CallID)
	}
	if result.Error != nil {
		t.Fatalf("denial surfaced as an error: %v", result.Error)
	}
	payload, ok := result.Result.(arcjet.GuardDenialResult)
	if !ok {
		t.Fatalf("result = %T (%v), want GuardDenialResult", result.Result, result.Result)
	}
	if !payload.ArcjetDenied || payload.Reason != "RATE_LIMIT" || !payload.Retryable || payload.RetryAfterSeconds == nil {
		t.Fatalf("payload = %+v", payload)
	}
	if got := decide.request(0).GetLabel(); got != "order.looked-up" {
		t.Fatalf("label = %q", got)
	}
}

func TestGuardToolDenialWithNonRateLimitReasonIsNotRetryable(t *testing.T) {
	// Contrast with the rate-limit denial test: a reason that carries no
	// retry hint must not be marked retryable or given one.
	decide := &fakeDecide{resp: denyPromptInjectionResponse()}
	client := newTestClient(t, decide)
	base, calls := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{Action: "order.looked-up"})
	out, err := guarded.Call(t.Context(), `{"orderNumber":"o-1"}`)
	if err != nil {
		t.Fatalf("denial must not be an error: %v", err)
	}
	payload, ok := out.(arcjet.GuardDenialResult)
	if !ok || payload.Reason != "PROMPT_INJECTION" || payload.Retryable || payload.RetryAfterSeconds != nil {
		t.Fatalf("payload = %+v", payload)
	}
	if *calls != 0 {
		t.Fatal("tool ran on a denied call")
	}
}

func TestGuardToolUnavailableFailsClosedWithPayload(t *testing.T) {
	decide := &fakeDecide{err: errors.New("decide unreachable")}
	client := newTestClient(t, decide)
	base, calls := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{Action: "order.looked-up"})
	out, err := guarded.Call(t.Context(), `{"orderNumber":"o-1"}`)
	if err != nil {
		t.Fatalf("unavailable must not be an error: %v", err)
	}
	payload, ok := out.(arcjet.GuardDenialResult)
	if !ok || payload.Reason != "ERROR" || payload.RetryAfterSeconds == nil || *payload.RetryAfterSeconds != 5 {
		t.Fatalf("out = %#v", out)
	}
	if *calls != 0 {
		t.Fatal("tool ran while the guard was unavailable")
	}
}

func TestGuardToolUnavailableAllowRunsTool(t *testing.T) {
	client := newTestClient(t, &fakeDecide{err: errors.New("decide unreachable")})
	base, calls := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{Action: "order.looked-up", OnGuardError: arcjet.OnGuardErrorAllow})
	out, err := guarded.Call(t.Context(), `{"orderNumber":"o-1"}`)
	if err != nil || out != "o-1: shipped" || *calls != 1 {
		t.Fatalf("out = %v, err = %v, calls = %d", out, err, *calls)
	}
}

func TestGuardToolAllowRunsAndPassesToolErrorThrough(t *testing.T) {
	client := newTestClient(t, &fakeDecide{resp: allowResponse()})
	failing, err := functoolNew(t, "lookup_order", func(context.Context, lookupArgs) (string, error) { return "", errToolFailed })
	if err != nil {
		t.Fatal(err)
	}
	guarded := MustGuardTool(client, failing, ToolPolicy{Action: "order.looked-up"})
	_, callErr := guarded.Call(t.Context(), `{"orderNumber":"o-1"}`)
	if !errors.Is(callErr, errToolFailed) {
		t.Fatalf("err = %v, want the tool's own error unchanged", callErr)
	}
}

func TestGuardToolOnDenyReshapesPayload(t *testing.T) {
	client := newTestClient(t, &fakeDecide{resp: denyRateLimitResponse()})
	base, _ := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{
		Action: "order.looked-up",
		OnDeny: func(d arcjet.GuardDecision) any { return map[string]string{"blocked": string(d.Reason)} },
	})
	out, err := guarded.Call(t.Context(), `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.(map[string]string)["blocked"]; got != "RATE_LIMIT" {
		t.Fatalf("out = %#v", out)
	}
}

func TestGuardToolOnDenyIsNotInvokedWhenUnavailable(t *testing.T) {
	client := newTestClient(t, &fakeDecide{err: errors.New("decide unreachable")})
	base, _ := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{
		Action: "order.looked-up",
		OnDeny: func(arcjet.GuardDecision) any {
			t.Fatal("OnDeny must not run for an unavailable guard: it receives a DENY decision, and none exists")
			return nil
		},
	})
	out, err := guarded.Call(t.Context(), `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if payload, ok := out.(arcjet.GuardDenialResult); !ok || payload.Reason != "ERROR" {
		t.Fatalf("out = %#v, want the fixed unavailable payload", out)
	}
}

func TestGuardToolErrorReachesTheLoopAsAnError(t *testing.T) {
	// Contrast with the denial test: a real tool failure is still an error
	// to the framework, which then applies its own error handling.
	client := newTestClient(t, &fakeDecide{resp: allowResponse()})
	failing, err := functoolNew(t, "lookup_order", func(context.Context, lookupArgs) (string, error) { return "", errToolFailed })
	if err != nil {
		t.Fatal(err)
	}
	guarded := MustGuardTool(client, failing, ToolPolicy{Action: "order.looked-up"})
	runner := &scriptedRunner{turns: [][]*agent.ResponseUpdate{
		{functionCall("call_1", "lookup_order", `{"orderNumber":"o-1"}`)},
		{assistantTextUpdate("done")},
	}}
	a := newAgent(runner, agent.Config{Tools: []tool.Tool{guarded}})
	if _, err := a.RunText(t.Context(), "where is my order?").Collect(); err != nil {
		t.Fatal(err)
	}
	result := lastFunctionResult(t, runner.seen[1])
	if result.Error == nil {
		t.Fatalf("tool failure reached the loop as a success: %#v", result)
	}
	if !errors.Is(result.Error, errToolFailed) {
		t.Fatalf("loop saw %v, want the tool's own error", result.Error)
	}
}

func TestGuardToolResolversReachGuardAndTheirErrorsFailClosed(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	base, _ := newLookupTool(t)
	limit, err := arcjet.GuardTokenBucket(arcjet.GuardTokenBucketOptions{Mode: arcjet.ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10})
	if err != nil {
		t.Fatal(err)
	}
	guarded := MustGuardTool(client, base, ToolPolicy{
		Action: "order.looked-up",
		Actor:  func(context.Context, json.RawMessage) (string, error) { return "user_1", nil },
		Inputs: func(_ context.Context, raw json.RawMessage) (map[string]arcjet.GuardPolicyInput, error) {
			var in lookupArgs
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, err
			}
			return map[string]arcjet.GuardPolicyInput{"orderNumber": arcjet.GuardPolicyServerString(in.OrderNumber)}, nil
		},
		Rules: Args(func(_ context.Context, in lookupArgs) ([]arcjet.GuardRuleInput, error) {
			return []arcjet.GuardRuleInput{limit.Key(in.OrderNumber, 1)}, nil
		}),
	})
	if _, err := guarded.Call(t.Context(), `{"orderNumber":"o-1"}`); err != nil {
		t.Fatal(err)
	}
	req := decide.request(0)
	if req.GetActor() != "user_1" || len(req.GetRuleSubmissions()) != 1 {
		t.Fatalf("request = %v", req)
	}
	if _, ok := req.GetPolicyInputs()["orderNumber"]; !ok {
		t.Fatalf("Inputs resolver did not reach the request: %v", req.GetPolicyInputs())
	}

	failing := MustGuardTool(client, base, ToolPolicy{
		Action: "order.looked-up",
		Rules: func(context.Context, json.RawMessage) ([]arcjet.GuardRuleInput, error) {
			return nil, errors.New("no rules")
		},
	})
	out, err := failing.Call(t.Context(), `{"orderNumber":"o-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if payload, ok := out.(arcjet.GuardDenialResult); !ok || payload.Reason != "ERROR" {
		t.Fatalf("out = %#v, want the unavailable payload", out)
	}
	if decide.guardCalls() != 1 {
		t.Fatalf("guard calls = %d, want 1 (the failing resolver must not reach Guard)", decide.guardCalls())
	}
}
