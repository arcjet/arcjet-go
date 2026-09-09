package agentframework

import (
	"testing"

	"github.com/microsoft/agent-framework-go/agent"
)

// Building a run must not spend a Guard decision. The framework's own
// middleware defer their work into the returned sequence, and a caller that
// abandons a stream should not be charged for it.
func TestGuardMiddlewareDoesNoWorkUntilTheStreamIsRead(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	mw, err := GuardMiddleware(client, MiddlewareConfig{Inbound: inboundPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	runner := &scriptedRunner{turns: [][]*agent.ResponseUpdate{{assistantTextUpdate("ok")}}}
	a := newAgent(runner, agent.Config{Middlewares: []agent.Middleware{mw}})

	stream := a.RunText(t.Context(), "hello")
	if decide.guardCalls() != 0 {
		t.Fatalf("guard calls = %d before reading the stream; want 0", decide.guardCalls())
	}
	if runner.providerCalls() != 0 {
		t.Fatalf("provider calls = %d before reading the stream; want 0", runner.providerCalls())
	}

	if _, err := stream.Collect(); err != nil {
		t.Fatal(err)
	}
	if decide.guardCalls() != 1 {
		t.Fatalf("guard calls = %d after reading; want 1", decide.guardCalls())
	}
}
