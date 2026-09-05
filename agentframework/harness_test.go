package agentframework

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/microsoft/agent-framework-go/agent"
	"github.com/microsoft/agent-framework-go/agent/harness/toolautocall"
	"github.com/microsoft/agent-framework-go/message"
	"github.com/microsoft/agent-framework-go/tool"
	"github.com/microsoft/agent-framework-go/tool/functool"
	"google.golang.org/protobuf/proto"

	"github.com/arcjet/arcjet-go"
	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

// fakeDecide is an in-process Decide service. Set resp or err before the
// run; read requests and captures after it.
type fakeDecide struct {
	mu       sync.Mutex
	resp     *decidev2.GuardResponse
	err      error
	requests []*decidev2.GuardRequest
	captures []*decidev2.CaptureEvent
}

func (f *fakeDecide) Guard(_ context.Context, req *connect.Request[decidev2.GuardRequest]) (*connect.Response[decidev2.GuardResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, proto.Clone(req.Msg).(*decidev2.GuardRequest))
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(f.resp), nil
}

func (f *fakeDecide) GetGuardPolicy(context.Context, *connect.Request[decidev2.GetGuardPolicyRequest]) (*connect.Response[decidev2.GetGuardPolicyResponse], error) {
	return connect.NewResponse(&decidev2.GetGuardPolicyResponse{
		Status: decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED,
	}), nil
}

func (f *fakeDecide) Capture(_ context.Context, req *connect.Request[decidev2.CaptureRequest]) (*connect.Response[decidev2.CaptureResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captures = append(f.captures, req.Msg.GetEvents()...)
	return connect.NewResponse(&decidev2.CaptureResponse{}), nil
}

func (f *fakeDecide) guardCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeDecide) request(i int) *decidev2.GuardRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[i]
}

// capturedEvents returns every capture event the fake service has received so
// far. Call client.Flush first: Capture enqueues events for asynchronous
// delivery, so reading captures without flushing races the delivery worker.
func (f *fakeDecide) capturedEvents() []*decidev2.CaptureEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.captures
}

func newTestClient(t *testing.T, f *fakeDecide) *arcjet.GuardClient {
	t.Helper()
	path, h := decidev2connect.NewDecideServiceHandler(f)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client, err := arcjet.NewGuardClient(arcjet.GuardConfig{
		Key:        "ajkey_test",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

func allowResponse() *decidev2.GuardResponse {
	return &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{
		Id:         "gdec_allow",
		Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
	}}
}

func denyRateLimitResponse() *decidev2.GuardResponse {
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

func denyPromptInjectionResponse() *decidev2.GuardResponse {
	return &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{
		Id:         "gdec_pi",
		Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_DENY,
		Reason:     decidev2.GuardReason_GUARD_REASON_PROMPT_INJECTION,
	}}
}

// scriptedRunner is a provider that replays one scripted turn per call and
// records the messages it was given, so a test can inspect the tool result
// message the framework built for the second turn.
type scriptedRunner struct {
	mu    sync.Mutex
	turns [][]*agent.ResponseUpdate
	calls int
	seen  [][]*message.Message
}

func (r *scriptedRunner) Run(_ context.Context, messages []*message.Message, _ ...agent.Option) iter.Seq2[*agent.ResponseUpdate, error] {
	return func(yield func(*agent.ResponseUpdate, error) bool) {
		r.mu.Lock()
		r.seen = append(r.seen, messages)
		turn := r.turns[min(r.calls, len(r.turns)-1)]
		r.calls++
		r.mu.Unlock()
		for _, u := range turn {
			if !yield(u, nil) {
				return
			}
		}
	}
}

func (r *scriptedRunner) providerCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func functionCall(callID, name, args string) *agent.ResponseUpdate {
	return &agent.ResponseUpdate{Role: message.RoleAssistant, Contents: message.Contents{
		&message.FunctionCallContent{CallID: callID, Name: name, Arguments: args},
	}}
}

func assistantTextUpdate(text string) *agent.ResponseUpdate {
	return &agent.ResponseUpdate{Role: message.RoleAssistant, Contents: message.Contents{&message.TextContent{Text: text}}}
}

// newAgent builds an agent around the scripted provider with the framework's
// own tool loop installed, the way every real provider does.
func newAgent(runner *scriptedRunner, cfg agent.Config) *agent.Agent {
	return agent.New(agent.ProviderConfig{
		Run:         runner.Run,
		Middlewares: []agent.Middleware{toolautocall.New(toolautocall.Config{})},
	}, cfg)
}

// lastFunctionResult finds the most recent tool result in a message slice.
func lastFunctionResult(t *testing.T, messages []*message.Message) *message.FunctionResultContent {
	t.Helper()
	for _, message0 := range slices.Backward(messages) {
		if message0 == nil {
			continue
		}
		for _, c := range message0.Contents {
			if frc, ok := c.(*message.FunctionResultContent); ok {
				return frc
			}
		}
	}
	t.Fatal("no FunctionResultContent found")
	return nil
}

type lookupArgs struct {
	OrderNumber string `json:"orderNumber"`
}

// newLookupTool returns a typed function tool and a counter of its calls.
func newLookupTool(t *testing.T) (tool.FuncTool, *int) {
	t.Helper()
	calls := 0
	tl, err := functool.New(functool.Config{Name: "lookup_order", Description: "Look up an order"},
		func(_ context.Context, in lookupArgs) (string, error) {
			calls++
			return in.OrderNumber + ": shipped", nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return tl, &calls
}

var errToolFailed = errors.New("db down")

// functoolNew builds a typed function tool for tests that need a handler
// other than newLookupTool's default.
func functoolNew[In, Out any](t *testing.T, name string, h func(context.Context, In) (Out, error)) (tool.FuncTool, error) {
	t.Helper()
	return functool.New(functool.Config{Name: name, Description: name}, h)
}
