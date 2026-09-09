package agentframework

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/microsoft/agent-framework-go/agent"
	"github.com/microsoft/agent-framework-go/message"

	"github.com/arcjet/arcjet-go"
)

// A turn whose payload carries no text still has to be evaluated. userText
// reads only *TextContent, so a document or an image yields an empty string;
// admitting such a turn unscreened would let an injection payload reach the
// model with no decision and no capture event.
func TestGuardMiddlewareScreensATurnWithNoText(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	mw, err := GuardMiddleware(client, MiddlewareConfig{Inbound: inboundPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	runner := &scriptedRunner{turns: [][]*agent.ResponseUpdate{{assistantTextUpdate("ok")}}}
	a := newAgent(runner, agent.Config{Middlewares: []agent.Middleware{mw}})

	doc := message.New(&message.DataContent{MediaType: "application/pdf", Data: "JVBERi0xLjc="})
	if _, err := a.Run(t.Context(), []*message.Message{doc}).Collect(); err != nil {
		t.Fatal(err)
	}
	if decide.guardCalls() != 1 {
		t.Fatalf("guard calls = %d, want 1: a turn with no text must still be evaluated", decide.guardCalls())
	}
}

// The one turn that is deliberately not screened: the framework relaying a
// person's answer to a call that was screened when it was made.
func TestGuardMiddlewareSkipsAnApprovalOnlyTurn(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	mw, err := GuardMiddleware(client, MiddlewareConfig{Inbound: inboundPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	runner := &scriptedRunner{turns: [][]*agent.ResponseUpdate{{assistantTextUpdate("ok")}}}
	a := newAgent(runner, agent.Config{Middlewares: []agent.Middleware{mw}})

	approval := message.New(&message.ToolApprovalResponseContent{RequestID: "call_1", Approved: true})
	if _, err := a.Run(t.Context(), []*message.Message{approval}).Collect(); err != nil {
		t.Fatal(err)
	}
	if decide.guardCalls() != 0 {
		t.Fatalf("guard calls = %d, want 0: an approval turn was already screened", decide.guardCalls())
	}
}

// GuardUnavailableError.Unwrap exposes its cause, so a denial raised by a
// nested guard on another action is reachable through errors.As on the outer
// error. The wrapper must report the outer class: this action's policy never
// ran, so it fails closed instead of telling the model this call was denied,
// with a reason and a retry hint belonging to a different action.
func TestGuardToolReportsUnavailableWhenItWrapsANestedDenial(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	base, calls := newLookupTool(t)

	// A resolver that fails is unevaluated policy. This one fails with a
	// denial from a guard on some other action, which is what a resolver
	// calling arcjet.GuardAction itself would return.
	nested := &arcjet.GuardDeniedError{
		Action:   "ledger.write",
		Decision: arcjet.GuardDecision{Conclusion: arcjet.ConclusionDeny, Reason: arcjet.ReasonRateLimit},
	}
	guarded := MustGuardTool(client, base, ToolPolicy{
		Action: "order.looked-up",
		Rules: func(context.Context, json.RawMessage) ([]arcjet.GuardRuleInput, error) {
			return nil, nested
		},
	})

	out, err := guarded.Call(t.Context(), `{"orderNumber":"o-1"}`)
	if err != nil {
		t.Fatalf("Call = %v, want no error", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("tool ran %d times, want 0", calls.Load())
	}
	payload, ok := out.(arcjet.GuardDenialResult)
	if !ok {
		t.Fatalf("result = %T (%v), want GuardDenialResult", out, out)
	}
	if payload.Reason != string(arcjet.ReasonError) {
		t.Fatalf("reason = %q, want %q: an unevaluated policy is not a denial of this action",
			payload.Reason, arcjet.ReasonError)
	}
}
