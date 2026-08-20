package arcjet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

type testGuardHandler struct {
	seen            *decidev2.GuardRequest
	seenRequests    []*decidev2.GuardRequest
	header          http.Header
	resp            *decidev2.GuardResponse
	guardResponses  []*decidev2.GuardResponse
	guardErrors     []error
	policyResponses []*decidev2.GetGuardPolicyResponse
	guardCalls      int
	policyCalls     int
	// errToReturn, when non-nil, makes Guard return a transport error instead
	// of a response — used to exercise the fail-open-on-transport path.
	errToReturn error

	mu            sync.Mutex
	captureSeen   []*decidev2.CaptureRequest
	captureHeader http.Header
	captureErr    error
	captureBlock  chan struct{}
}

func (h *testGuardHandler) Guard(ctx context.Context, req *connect.Request[decidev2.GuardRequest]) (*connect.Response[decidev2.GuardResponse], error) {
	h.seen = req.Msg
	h.seenRequests = append(h.seenRequests, proto.Clone(req.Msg).(*decidev2.GuardRequest))
	h.header = req.Header()
	h.guardCalls++
	if len(h.guardErrors) >= h.guardCalls && h.guardErrors[h.guardCalls-1] != nil {
		return nil, h.guardErrors[h.guardCalls-1]
	}
	if h.errToReturn != nil {
		return nil, h.errToReturn
	}
	if len(h.guardResponses) >= h.guardCalls {
		return connect.NewResponse(h.guardResponses[h.guardCalls-1]), nil
	}
	if h.resp != nil {
		return connect.NewResponse(h.resp), nil
	}
	return connect.NewResponse(&decidev2.GuardResponse{
		Decision: &decidev2.GuardDecision{
			Id:         "gdec_test",
			Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
			RuleResults: []*decidev2.GuardRuleResult{
				{
					ResultId: "gres_test",
					ConfigId: req.Msg.GetRuleSubmissions()[0].GetConfigId(),
					InputId:  req.Msg.GetRuleSubmissions()[0].GetInputId(),
					Type:     decidev2.GuardRuleType_GUARD_RULE_TYPE_TOKEN_BUCKET,
					Result: &decidev2.GuardRuleResult_TokenBucket{
						TokenBucket: &decidev2.ResultTokenBucket{
							Conclusion:            decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
							RemainingTokens:       9,
							MaxTokens:             10,
							ResetAtUnixSeconds:    123,
							RefillRate:            1,
							RefillIntervalSeconds: 60,
						},
					},
				},
			},
		},
	}), nil
}

func (h *testGuardHandler) GetGuardPolicy(_ context.Context, _ *connect.Request[decidev2.GetGuardPolicyRequest]) (*connect.Response[decidev2.GetGuardPolicyResponse], error) {
	h.policyCalls++
	if len(h.policyResponses) >= h.policyCalls {
		return connect.NewResponse(h.policyResponses[h.policyCalls-1]), nil
	}
	return connect.NewResponse(&decidev2.GetGuardPolicyResponse{
		Status: decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED,
	}), nil
}

func (h *testGuardHandler) Capture(_ context.Context, req *connect.Request[decidev2.CaptureRequest]) (*connect.Response[decidev2.CaptureResponse], error) {
	if h.captureBlock != nil {
		<-h.captureBlock
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.captureSeen = append(h.captureSeen, req.Msg)
	h.captureHeader = req.Header().Clone()
	if h.captureErr != nil {
		return nil, h.captureErr
	}
	return connect.NewResponse(&decidev2.CaptureResponse{}), nil
}

func (h *testGuardHandler) capturedEvents() []*decidev2.CaptureEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var events []*decidev2.CaptureEvent
	for _, req := range h.captureSeen {
		events = append(events, req.GetEvents()...)
	}
	return events
}

func newGuardTestClient(t *testing.T, handler *testGuardHandler) (*GuardClient, func()) {
	t.Helper()
	path, h := decidev2connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	client, err := NewGuardClient(GuardConfig{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, func() {}
}

func TestGuardTokenBucketUsesConnectAndHashesKey(t *testing.T) {
	handler := &testGuardHandler{}
	client, closeServer := newGuardTestClient(t, handler)
	defer closeServer()

	limit, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode:       ModeLive,
		RefillRate: 1,
		Interval:   time.Minute,
		Capacity:   10,
		Bucket:     "tools.weather",
	})
	if err != nil {
		t.Fatal(err)
	}

	decision, err := client.Guard(context.Background(), GuardRequest{
		Label:         "tools.weather",
		Metadata:      Metadata{"env": "test", "user": map[string]any{"id": "u_1"}},
		CorrelationId: "wf_abcdef",
		Rules:         []GuardRuleInput{limit.Key("user_123", 2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsAllowed() {
		t.Fatalf("expected allow decision, got %#v", decision)
	}
	if got := decision.Results[0].TokenBucket.RemainingTokens; got != 9 {
		t.Fatalf("remaining tokens = %d", got)
	}

	if got := handler.header.Get("Authorization"); got != "Bearer ajkey_test" {
		t.Fatalf("authorization header = %q", got)
	}
	seen := handler.seen
	if seen.GetLabel() != "tools.weather" {
		t.Fatalf("label = %q", seen.GetLabel())
	}
	// Values go on the wire JSON-encoded per top-level key.
	if got := seen.GetMetadataJson()["env"]; got != `"test"` {
		t.Fatalf("metadata_json[env] = %q", got)
	}
	if got := seen.GetMetadataJson()["user"]; got != `{"id":"u_1"}` {
		t.Fatalf("metadata_json[user] = %q", got)
	}
	// The legacy plain-string map is not dual-written: the server prefers
	// metadata_json and falls back to `metadata` only for older SDKs.
	//nolint:staticcheck // asserting the deprecated field stays empty is the point
	if got := seen.GetMetadata(); len(got) != 0 {
		t.Fatalf("legacy metadata = %#v", got)
	}
	if got := seen.GetLocalWarnings(); len(got) != 0 {
		t.Fatalf("local_warnings = %#v", got)
	}
	if seen.GetCorrelationId() != "wf_abcdef" {
		t.Fatalf("correlation_id = %q", seen.GetCorrelationId())
	}
	sub := seen.GetRuleSubmissions()[0]
	tb := sub.GetRule().GetTokenBucket()
	if tb == nil {
		t.Fatal("missing token bucket rule")
	}
	if tb.GetInputKeyHash() != hashKey("user_123") {
		t.Fatalf("key hash = %q", tb.GetInputKeyHash())
	}
	if tb.GetInputRequested() != 2 {
		t.Fatalf("requested = %d", tb.GetInputRequested())
	}
	if sub.GetMode() != decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE {
		t.Fatalf("mode = %s", sub.GetMode())
	}
}

func TestGuardPolicyOnlyRequestCarriesActorInputsAndCapabilities(t *testing.T) {
	handler := &testGuardHandler{resp: &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{
		Id:         "gdec_policy_only",
		Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
	}}}
	client, closeServer := newGuardTestClient(t, handler)
	defer closeServer()

	actor := ""
	decision, err := client.Guard(context.Background(), GuardRequest{
		Label: "email.sent",
		Actor: &actor,
		Inputs: map[string]GuardPolicyInput{
			"recipient": GuardPolicyServerString("user@example.com"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.ID != "gdec_policy_only" {
		t.Fatalf("decision ID = %q", decision.ID)
	}
	seen := handler.seen
	if len(seen.GetRuleSubmissions()) != 0 {
		t.Fatalf("rule submissions = %#v", seen.GetRuleSubmissions())
	}
	if seen.Actor == nil || seen.GetActor() != "" {
		t.Fatalf("actor presence/value = %#v/%q", seen.Actor, seen.GetActor())
	}
	if got := seen.GetPolicyInputs()["recipient"].GetServer().GetStringValue(); got != "user@example.com" {
		t.Fatalf("recipient = %q", got)
	}
	if got := seen.GetPolicyCapabilities(); len(got) != 2 || got[0] != "guard-policy-v1" || got[1] != "local-sensitive-info-v1" {
		t.Fatalf("policy capabilities = %#v", got)
	}
}

func TestGuardRefreshesRemotePolicyAndRetriesExactlyOnce(t *testing.T) {
	handler := &testGuardHandler{
		policyResponses: []*decidev2.GetGuardPolicyResponse{
			{
				Status: decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
				Policy: &decidev2.GuardLocalPolicyProjection{PolicyId: "policy", Revision: "rev-1"},
			},
			{
				Status: decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
				Policy: &decidev2.GuardLocalPolicyProjection{PolicyId: "policy", Revision: "rev-2"},
			},
		},
		guardResponses: []*decidev2.GuardResponse{
			{Decision: &decidev2.GuardDecision{
				Id:         "first",
				Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
				PolicyEvaluation: &decidev2.GuardPolicyEvaluation{
					Revision:        "rev-2",
					Status:          decidev2.GuardPolicyStatus_GUARD_POLICY_STATUS_INCOMPLETE,
					RefreshRequired: true,
				},
			}},
			{Decision: &decidev2.GuardDecision{
				Id:         "second",
				Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
				PolicyEvaluation: &decidev2.GuardPolicyEvaluation{
					Revision:        "rev-2",
					Status:          decidev2.GuardPolicyStatus_GUARD_POLICY_STATUS_APPLIED,
					RefreshRequired: true,
				},
			}},
		},
	}
	client, closeServer := newGuardTestClient(t, handler)
	defer closeServer()

	decision, err := client.Guard(context.Background(), GuardRequest{
		Label:  "email.sent",
		Inputs: map[string]GuardPolicyInput{"body": GuardPolicyLocalString("private")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.ID != "second" || handler.guardCalls != 2 || handler.policyCalls != 2 {
		t.Fatalf("decision/calls = %q/%d/%d", decision.ID, handler.guardCalls, handler.policyCalls)
	}
	if len(handler.seenRequests) != 2 || handler.seenRequests[0].GetLocalPolicyRevision() != "rev-1" || handler.seenRequests[1].GetLocalPolicyRevision() != "rev-2" {
		t.Fatalf("request revisions = %#v", handler.seenRequests)
	}
}

func projectedSensitiveInfoPolicy(revision string, modes ...decidev2.GuardRuleMode) *decidev2.GetGuardPolicyResponse {
	rules := make([]*decidev2.GuardLocalSensitiveInfoRule, len(modes))
	for i, mode := range modes {
		rules[i] = &decidev2.GuardLocalSensitiveInfoRule{
			RuleId: fmt.Sprintf("rule-%d", i+1), InputName: "body", Mode: mode,
			EntityFilter: &decidev2.GuardLocalSensitiveInfoRule_EntitiesDeny{EntitiesDeny: &decidev2.EntityList{Entities: []string{"EMAIL"}}},
		}
	}
	return &decidev2.GetGuardPolicyResponse{
		Status: decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
		Policy: &decidev2.GuardLocalPolicyProjection{PolicyId: "policy", Revision: revision, SensitiveInfoRules: rules},
	}
}

func TestGuardLiveProjectedSensitiveInfoDenialUsesSanitizedGuardRPC(t *testing.T) {
	handler := &testGuardHandler{
		policyResponses: []*decidev2.GetGuardPolicyResponse{
			projectedSensitiveInfoPolicy("rev-1", decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE, decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE),
		},
		resp: &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{
			Id: "server-denial", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_DENY,
			Reason: decidev2.GuardReason_GUARD_REASON_SENSITIVE_INFO,
			PolicyRuleResults: []*decidev2.GuardPolicyRuleResult{
				{
					PolicyId: "policy", PolicyRevision: "rev-1", RuleId: "rule-1",
					Type: decidev2.GuardRuleType_GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO, Mode: decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE,
					Execution: decidev2.GuardRuleExecution_GUARD_RULE_EXECUTION_SDK, Source: decidev2.GuardRuleSource_GUARD_RULE_SOURCE_REMOTE,
					Result: &decidev2.GuardPolicyRuleResult_LocalSensitiveInfo{LocalSensitiveInfo: &decidev2.ResultLocalSensitiveInfo{
						Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_DENY, Detected: true, DetectedEntityTypes: []string{"EMAIL"},
					}},
				},
				{
					PolicyId: "policy", PolicyRevision: "rev-1", RuleId: "rule-2",
					Type: decidev2.GuardRuleType_GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO, Mode: decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE,
					Execution: decidev2.GuardRuleExecution_GUARD_RULE_EXECUTION_SDK, Source: decidev2.GuardRuleSource_GUARD_RULE_SOURCE_REMOTE,
					Result: &decidev2.GuardPolicyRuleResult_NotRun{NotRun: &decidev2.ResultNotRun{}},
				},
			},
		}},
	}
	client, _ := newGuardTestClient(t, handler)
	client.policy.backend = policySensitiveInfoBackend{}

	customCalls := 0
	custom, err := GuardCustom(GuardCustomOptions{
		Mode: ModeLive,
		Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
			customCalls++
			return GuardCustomResult{Conclusion: ConclusionAllow}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	actor := "sensitive-actor"
	decision, err := client.Guard(context.Background(), GuardRequest{
		Label:         "message.send",
		Actor:         &actor,
		CorrelationId: "sensitive-correlation",
		Inputs: map[string]GuardPolicyInput{
			"body":   GuardPolicyLocalString("secret user@example.com"),
			"server": GuardPolicyServerString("must not be transported"),
		},
		Metadata: Metadata{"retained": "metadata-marker", "invalid": make(chan int)},
		Rules:    []GuardRuleInput{custom.Input(map[string]string{"side_effect": "must not run"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsDenied() || decision.ID != "server-denial" || handler.guardCalls != 1 || customCalls != 0 {
		t.Fatalf("decision/Guard/custom calls = %#v/%d/%d", decision, handler.guardCalls, customCalls)
	}
	seen := handler.seen
	if len(seen.GetRuleSubmissions()) != 0 || seen.GetActor() != actor || seen.GetMetadataJson()["retained"] != `"metadata-marker"` || seen.GetCorrelationId() != "sensitive-correlation" || seen.GetUserAgent() == "" || seen.GetLabel() != "message.send" || seen.LocalEvalDurationMs == nil || seen.SentAtUnixMs == nil {
		t.Fatalf("normal denial envelope = %#v", seen)
	}
	if len(seen.GetPolicyInputs()) != 1 || seen.GetPolicyInputs()["body"].GetLocal() == nil || seen.GetPolicyInputs()["server"] != nil {
		t.Fatalf("sanitized policy inputs = %#v", seen.GetPolicyInputs())
	}
	if seen.GetLocalPolicyRevision() != "rev-1" || len(seen.GetLocalPolicyResults()) != 2 || len(seen.GetPolicyCapabilities()) != 2 {
		t.Fatalf("local policy evidence = %#v", seen)
	}
	if len(seen.GetLocalWarnings()) != 1 {
		t.Fatalf("reported metadata warnings = %#v", seen.GetLocalWarnings())
	}
	if len(decision.PolicyResults) != 2 || decision.PolicyResults[0].LocalSensitiveInfo == nil || !decision.PolicyResults[1].NotRun || decision.PolicyResults[0].Source != GuardRuleSourceRemote || decision.PolicyResults[1].Source != GuardRuleSourceRemote {
		t.Fatalf("sequential policy results = %#v", decision.PolicyResults)
	}
	if len(decision.Warnings) != 1 {
		t.Fatalf("envelope metadata warnings = %#v", decision.Warnings)
	}
}

func TestGuardRefreshLiveProjectedSensitiveInfoSanitizesRetry(t *testing.T) {
	handler := &testGuardHandler{
		policyResponses: []*decidev2.GetGuardPolicyResponse{
			projectedSensitiveInfoPolicy("rev-1"),
			projectedSensitiveInfoPolicy("rev-2", decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE),
		},
		guardResponses: []*decidev2.GuardResponse{
			{Decision: &decidev2.GuardDecision{
				Id: "first", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
				PolicyEvaluation: &decidev2.GuardPolicyEvaluation{Revision: "rev-2", Status: decidev2.GuardPolicyStatus_GUARD_POLICY_STATUS_INCOMPLETE, RefreshRequired: true},
			}},
			{Decision: &decidev2.GuardDecision{Id: "refresh-denial", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_DENY}},
		},
	}
	client, _ := newGuardTestClient(t, handler)
	client.policy.backend = policySensitiveInfoBackend{}

	custom, err := GuardCustom(GuardCustomOptions{Mode: ModeLive, Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
		return GuardCustomResult{Conclusion: ConclusionAllow}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	actor := "sensitive-actor"
	decision, err := client.Guard(context.Background(), GuardRequest{
		Label:         "message.send",
		Actor:         &actor,
		CorrelationId: "sensitive-correlation",
		Inputs: map[string]GuardPolicyInput{
			"body": GuardPolicyLocalString("secret user@example.com"), "server": GuardPolicyServerString("raw secret"),
		},
		Metadata: Metadata{"retained": "metadata-marker"},
		Rules:    []GuardRuleInput{custom.Input(nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsDenied() || decision.ID != "refresh-denial" || handler.guardCalls != 2 || handler.policyCalls != 2 {
		t.Fatalf("decision/Guard/policy calls = %#v/%d/%d", decision, handler.guardCalls, handler.policyCalls)
	}
	second := handler.seenRequests[1]
	if len(second.GetRuleSubmissions()) != 1 || second.GetMetadataJson()["retained"] != `"metadata-marker"` || second.GetActor() != actor || second.GetCorrelationId() != "sensitive-correlation" || second.GetPolicyInputs()["server"] != nil || second.GetPolicyInputs()["body"].GetLocal() == nil {
		t.Fatalf("sanitized refresh request = %#v", second)
	}
}

func TestGuardLiveProjectedSensitiveInfoReportingFailurePreservesDenial(t *testing.T) {
	handler := &testGuardHandler{
		policyResponses: []*decidev2.GetGuardPolicyResponse{projectedSensitiveInfoPolicy("rev-1", decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE)},
		errToReturn:     errors.New("offline"),
	}
	client, _ := newGuardTestClient(t, handler)
	client.policy.backend = policySensitiveInfoBackend{}
	decision, err := client.Guard(context.Background(), GuardRequest{Label: "message.send", Inputs: map[string]GuardPolicyInput{"body": GuardPolicyLocalString("user@example.com")}})
	if err == nil || !decision.IsDenied() || decision.ID != "" || handler.guardCalls != 1 {
		t.Fatalf("decision/error/calls = %#v/%v/%d", decision, err, handler.guardCalls)
	}
}

func TestGuardLiveProjectedSensitiveInfoRejectsIncompleteReportingResponse(t *testing.T) {
	for _, test := range []struct {
		name string
		resp *decidev2.GuardResponse
	}{
		{name: "missing decision", resp: &decidev2.GuardResponse{}},
		{name: "missing decision ID", resp: &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := &testGuardHandler{
				policyResponses: []*decidev2.GetGuardPolicyResponse{projectedSensitiveInfoPolicy("rev-1", decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE)},
				resp:            test.resp,
			}
			client, _ := newGuardTestClient(t, handler)
			client.policy.backend = policySensitiveInfoBackend{}
			decision, err := client.Guard(context.Background(), GuardRequest{Label: "message.send", Inputs: map[string]GuardPolicyInput{"body": GuardPolicyLocalString("user@example.com")}})
			if err != nil {
				t.Fatal(err)
			}
			if !decision.IsDenied() || decision.ID != "" {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestGuardRefreshLiveProjectedSensitiveInfoRejectsIncompleteReportingResponse(t *testing.T) {
	for _, test := range []struct {
		name string
		resp *decidev2.GuardResponse
	}{
		{name: "missing decision", resp: &decidev2.GuardResponse{}},
		{name: "missing decision ID", resp: &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := &testGuardHandler{
				policyResponses: []*decidev2.GetGuardPolicyResponse{
					projectedSensitiveInfoPolicy("rev-1"),
					projectedSensitiveInfoPolicy("rev-2", decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE),
				},
				guardResponses: []*decidev2.GuardResponse{
					{Decision: &decidev2.GuardDecision{Id: "first", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW, PolicyEvaluation: &decidev2.GuardPolicyEvaluation{RefreshRequired: true}}},
					test.resp,
				},
			}
			client, _ := newGuardTestClient(t, handler)
			client.policy.backend = policySensitiveInfoBackend{}
			decision, err := client.Guard(context.Background(), GuardRequest{Label: "message.send", Inputs: map[string]GuardPolicyInput{"body": GuardPolicyLocalString("user@example.com")}})
			if err != nil {
				t.Fatal(err)
			}
			if !decision.IsDenied() || decision.ID != "" || handler.guardCalls != 2 {
				t.Fatalf("decision/calls = %#v/%d", decision, handler.guardCalls)
			}
		})
	}
}

func TestGuardDryRunProjectedSensitiveInfoContinuesToGuardRPC(t *testing.T) {
	handler := &testGuardHandler{
		policyResponses: []*decidev2.GetGuardPolicyResponse{projectedSensitiveInfoPolicy("rev-1", decidev2.GuardRuleMode_GUARD_RULE_MODE_DRY_RUN, decidev2.GuardRuleMode_GUARD_RULE_MODE_DRY_RUN)},
		resp:            &decidev2.GuardResponse{Decision: &decidev2.GuardDecision{Id: "server", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW}},
	}
	client, _ := newGuardTestClient(t, handler)
	client.policy.backend = policySensitiveInfoBackend{}

	customCalls := 0
	custom, err := GuardCustom(GuardCustomOptions{Mode: ModeLive, Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
		customCalls++
		return GuardCustomResult{Conclusion: ConclusionAllow}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := client.Guard(context.Background(), GuardRequest{
		Label: "message.send", Inputs: map[string]GuardPolicyInput{
			"body": GuardPolicyLocalString("secret user@example.com"), "server": GuardPolicyServerString("server-policy-marker"),
		}, Metadata: Metadata{"retained": "metadata-marker"}, Rules: []GuardRuleInput{custom.Input(nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.ID != "server" || handler.guardCalls != 1 || customCalls != 1 {
		t.Fatalf("decision/Guard calls = %#v/%d", decision, handler.guardCalls)
	}
	if handler.seen.GetPolicyInputs()["server"] != nil || handler.seen.GetPolicyInputs()["body"].GetLocal() == nil || handler.seen.GetMetadataJson()["retained"] != `"metadata-marker"` || len(handler.seen.GetRuleSubmissions()) != 1 {
		t.Fatalf("dry-run request = %#v", handler.seen)
	}
	if got := handler.seen.GetLocalPolicyResults(); len(got) != 2 || got[0].GetLocalSensitiveInfo().GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_DENY || got[1].GetLocalSensitiveInfo().GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_DENY {
		t.Fatalf("dry-run local results = %#v", got)
	}
}

func TestGuardRefreshDryRunProjectedSensitiveInfoSanitizesRetry(t *testing.T) {
	handler := &testGuardHandler{
		policyResponses: []*decidev2.GetGuardPolicyResponse{
			projectedSensitiveInfoPolicy("rev-1"),
			projectedSensitiveInfoPolicy("rev-2", decidev2.GuardRuleMode_GUARD_RULE_MODE_DRY_RUN),
		},
		guardResponses: []*decidev2.GuardResponse{
			{Decision: &decidev2.GuardDecision{Id: "first", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW, PolicyEvaluation: &decidev2.GuardPolicyEvaluation{RefreshRequired: true}}},
			{Decision: &decidev2.GuardDecision{Id: "ordinary-retry", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW}},
		},
	}
	client, _ := newGuardTestClient(t, handler)
	client.policy.backend = policySensitiveInfoBackend{}
	decision, err := client.Guard(context.Background(), GuardRequest{Label: "message.send", Inputs: map[string]GuardPolicyInput{
		"body": GuardPolicyLocalString("user@example.com"), "server": GuardPolicyServerString("server-policy-marker"),
	}, Metadata: Metadata{"retained": "metadata-marker"}})
	if err != nil {
		t.Fatal(err)
	}
	second := handler.seenRequests[1]
	if decision.ID != "ordinary-retry" || second.GetPolicyInputs()["server"] != nil || second.GetPolicyInputs()["body"].GetLocal() == nil || second.GetMetadataJson()["retained"] != `"metadata-marker"` {
		t.Fatalf("decision/retry = %#v/%#v", decision, second)
	}
}

func TestGuardRefreshKeepsInitialDryRunSanitizationSticky(t *testing.T) {
	handler := &testGuardHandler{
		policyResponses: []*decidev2.GetGuardPolicyResponse{
			projectedSensitiveInfoPolicy("rev-1", decidev2.GuardRuleMode_GUARD_RULE_MODE_DRY_RUN),
			projectedSensitiveInfoPolicy("rev-2"),
		},
		guardResponses: []*decidev2.GuardResponse{
			{Decision: &decidev2.GuardDecision{Id: "first", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW, PolicyEvaluation: &decidev2.GuardPolicyEvaluation{RefreshRequired: true}}},
			{Decision: &decidev2.GuardDecision{Id: "ordinary-retry", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW}},
		},
	}
	client, _ := newGuardTestClient(t, handler)
	client.policy.backend = policySensitiveInfoBackend{}
	custom, err := GuardCustom(GuardCustomOptions{Mode: ModeLive, Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
		return GuardCustomResult{Conclusion: ConclusionAllow}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := client.Guard(context.Background(), GuardRequest{
		Label: "message.send",
		Inputs: map[string]GuardPolicyInput{
			"body": GuardPolicyLocalString("user@example.com"), "server": GuardPolicyServerString("server-policy-marker"),
		},
		Metadata: Metadata{"retained": "metadata-marker"},
		Rules:    []GuardRuleInput{custom.Input(nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.ID != "ordinary-retry" || decision.IsDenied() || handler.guardCalls != 2 {
		t.Fatalf("decision/calls = %#v/%d", decision, handler.guardCalls)
	}
	for i, seen := range handler.seenRequests {
		if seen.GetPolicyInputs()["server"] != nil || seen.GetPolicyInputs()["body"].GetLocal() == nil {
			t.Fatalf("request %d restored server input: %#v", i+1, seen.GetPolicyInputs())
		}
		if seen.GetMetadataJson()["retained"] != `"metadata-marker"` || len(seen.GetRuleSubmissions()) != 1 {
			t.Fatalf("request %d lost envelope/submissions: %#v", i+1, seen)
		}
	}
	if got := handler.seenRequests[0].GetLocalPolicyResults(); len(got) != 1 || got[0].GetLocalSensitiveInfo().GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_DENY {
		t.Fatalf("initial dry-run detection = %#v", got)
	}
	if got := handler.seenRequests[1].GetLocalPolicyResults(); len(got) != 0 {
		t.Fatalf("refreshed no-detection results = %#v", got)
	}
}

func TestGuardSensitiveInfoSubmitsLocalResultAndHashedText(t *testing.T) {
	// Sensitive-info detection runs locally via the bundled wasm analyzer.
	// The submission carries the locally-computed result plus a SHA-256
	// hash of the text — the raw text must never reach the server.
	handler := &testGuardHandler{resp: &decidev2.GuardResponse{
		Decision: &decidev2.GuardDecision{
			Id:         "gdec_sensitive",
			Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_DENY,
		},
	}}
	client, closeServer := newGuardTestClient(t, handler)
	defer closeServer()
	defer client.Close(context.Background())

	rule, err := GuardSensitiveInfo(GuardSensitiveInfoOptions{
		Mode: ModeLive,
		Deny: []EntityType{SensitiveInfoEmail},
	})
	if err != nil {
		t.Fatal(err)
	}
	const text = "email me at user@example.com"
	if _, err := client.Guard(context.Background(), GuardRequest{
		Label: "tools.email",
		Rules: []GuardRuleInput{rule.Text(text)},
	}); err != nil {
		t.Fatal(err)
	}
	subs := handler.seen.GetRuleSubmissions()
	if len(subs) != 1 {
		t.Fatalf("expected one submission, got %d", len(subs))
	}
	si := subs[0].GetRule().GetLocalSensitiveInfo()
	if si == nil {
		t.Fatal("expected localSensitiveInfo rule")
	}
	wantHash := sha256Hex(text)
	if got := si.GetInputTextHash(); got != wantHash {
		t.Errorf("inputTextHash = %q, want %q", got, wantHash)
	}
	deny := si.GetConfigEntitiesDeny()
	if deny == nil || len(deny.GetEntities()) != 1 || deny.GetEntities()[0] != string(SensitiveInfoEmail) {
		t.Errorf("configEntitiesDeny = %#v", deny)
	}
	result := si.GetResultComputed()
	if result == nil {
		t.Fatal("expected resultComputed on local sensitive-info submission")
	}
	if result.GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_DENY {
		t.Errorf("conclusion = %s, want DENY", result.GetConclusion())
	}
	if !result.GetDetected() {
		t.Error("expected detected=true")
	}
	if types := result.GetDetectedEntityTypes(); len(types) != 1 || types[0] != string(SensitiveInfoEmail) {
		t.Errorf("detectedEntityTypes = %v", types)
	}
	// Belt-and-braces: ensure the raw text isn't anywhere on the wire.
	wireBytes, err := jsonMarshal(subs[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wireBytes), "user@example.com") {
		t.Fatalf("raw text leaked onto guard submission: %s", wireBytes)
	}
}

func TestGuardSensitiveInfoAllowsWhenNoMatch(t *testing.T) {
	handler := &testGuardHandler{resp: &decidev2.GuardResponse{
		Decision: &decidev2.GuardDecision{
			Id:         "gdec_sensitive_allow",
			Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
		},
	}}
	client, closeServer := newGuardTestClient(t, handler)
	defer closeServer()
	defer client.Close(context.Background())

	rule, err := GuardSensitiveInfo(GuardSensitiveInfoOptions{
		Mode: ModeLive,
		Deny: []EntityType{SensitiveInfoEmail},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Guard(context.Background(), GuardRequest{
		Label: "tools.email",
		Rules: []GuardRuleInput{rule.Text("hello, world")},
	}); err != nil {
		t.Fatal(err)
	}
	result := handler.seen.GetRuleSubmissions()[0].GetRule().GetLocalSensitiveInfo().GetResultComputed()
	if result.GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW {
		t.Errorf("conclusion = %s, want ALLOW", result.GetConclusion())
	}
	if result.GetDetected() {
		t.Error("expected detected=false on clean text")
	}
	if len(result.GetDetectedEntityTypes()) != 0 {
		t.Errorf("detectedEntityTypes = %v, want empty", result.GetDetectedEntityTypes())
	}
}

func TestGuardSensitiveInfoAllowListSubmitsAllowEntities(t *testing.T) {
	handler := &testGuardHandler{resp: &decidev2.GuardResponse{
		Decision: &decidev2.GuardDecision{Id: "gdec_si_allow", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW},
	}}
	client, closeServer := newGuardTestClient(t, handler)
	defer closeServer()
	defer client.Close(context.Background())

	rule, err := GuardSensitiveInfo(GuardSensitiveInfoOptions{
		Mode:  ModeLive,
		Allow: []EntityType{SensitiveInfoCreditCardNumber},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Guard(context.Background(), GuardRequest{
		Label: "tools.payment",
		Rules: []GuardRuleInput{rule.Text("card 4242 4242 4242 4242")},
	}); err != nil {
		t.Fatal(err)
	}
	si := handler.seen.GetRuleSubmissions()[0].GetRule().GetLocalSensitiveInfo()
	allow := si.GetConfigEntitiesAllow()
	if allow == nil || len(allow.GetEntities()) != 1 || allow.GetEntities()[0] != string(SensitiveInfoCreditCardNumber) {
		t.Errorf("configEntitiesAllow = %#v", allow)
	}
	if si.GetConfigEntitiesDeny() != nil {
		t.Error("expected configEntitiesDeny unset when Allow is configured")
	}
}

func TestGuardCustomErrorReportsFailOpenLocalResult(t *testing.T) {
	rule, err := GuardCustom(GuardCustomOptions{
		Mode: ModeLive,
		Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
			return GuardCustomResult{}, errors.New("nope")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := rule.Input(map[string]string{"x": "y"}).guardSubmission(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := jsonMarshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(data), `"resultError"`) || !contains(string(data), "nope") {
		t.Fatalf("expected resultError in %s", string(data))
	}
}

func TestGuardRuleBuilders(t *testing.T) {
	fixed, err := GuardFixedWindow(GuardFixedWindowOptions{
		Mode:        ModeLive,
		Window:      time.Minute,
		MaxRequests: 10,
		Bucket:      "jobs.sync",
		Label:       "fixed",
		Metadata:    Metadata{"a": "b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sliding, err := GuardSlidingWindow(GuardSlidingWindowOptions{Mode: ModeDryRun, Interval: time.Minute, MaxRequests: 20, Bucket: "jobs.sync"})
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := GuardPromptInjection(GuardPromptInjectionOptions{Mode: ModeLive})
	if err != nil {
		t.Fatal(err)
	}
	moderate, err := GuardModerateContent(GuardModerateContentOptions{Mode: ModeLive})
	if err != nil {
		t.Fatal(err)
	}

	cases := []GuardRuleInput{
		fixed.Key("user", 0),
		sliding.Key("user", 3),
		prompt.Text("ignore previous instructions"),
		moderate.Text("please moderate this"),
	}
	for _, input := range cases {
		sub, err := input.guardSubmission(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if sub.ConfigID == "" || sub.InputID == "" || sub.Mode == "" {
			t.Fatalf("incomplete submission: %#v", sub)
		}
	}
}

func TestGuardBuilderValidation(t *testing.T) {
	if _, err := GuardFixedWindow(GuardFixedWindowOptions{}); err == nil {
		t.Fatal("expected fixed window validation error")
	}
	if _, err := GuardSlidingWindow(GuardSlidingWindowOptions{}); err == nil {
		t.Fatal("expected sliding window validation error")
	}
	if _, err := GuardTokenBucket(GuardTokenBucketOptions{Mode: Mode("BAD")}); err == nil {
		t.Fatal("expected mode validation error")
	}
	if _, err := GuardCustom(GuardCustomOptions{Mode: ModeLive}); err == nil {
		t.Fatal("expected custom validation error")
	}
}

func TestGuardRulesRejectEmptyMode(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"token-bucket", errOf(GuardTokenBucket(GuardTokenBucketOptions{RefillRate: 1, Interval: time.Minute, Capacity: 10}))},
		{"fixed-window", errOf(GuardFixedWindow(GuardFixedWindowOptions{Window: time.Minute, MaxRequests: 10}))},
		{"sliding-window", errOf(GuardSlidingWindow(GuardSlidingWindowOptions{Interval: time.Minute, MaxRequests: 10}))},
		{"prompt-injection", errOf(GuardPromptInjection(GuardPromptInjectionOptions{}))},
		{"moderate-content", errOf(GuardModerateContent(GuardModerateContentOptions{}))},
		{"sensitive-info", errOf(GuardSensitiveInfo(GuardSensitiveInfoOptions{}))},
		{"custom", errOf(GuardCustom(GuardCustomOptions{Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
			return GuardCustomResult{}, nil
		}}))},
	}
	for _, tc := range cases {
		if tc.err == nil {
			t.Errorf("%s: empty Mode should be rejected", tc.name)
			continue
		}
		if !errors.Is(tc.err, ErrInvalidMode) {
			t.Errorf("%s: errors.Is(_, ErrInvalidMode) = false; err=%v", tc.name, tc.err)
		}
	}
}

func errOf[T any](_ T, err error) error { return err }

func TestGuardRateLimitDefaultBuckets(t *testing.T) {
	tb, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	fw, err := GuardFixedWindow(GuardFixedWindowOptions{Mode: ModeLive, Window: time.Minute, MaxRequests: 10})
	if err != nil {
		t.Fatal(err)
	}
	sw, err := GuardSlidingWindow(GuardSlidingWindowOptions{Mode: ModeLive, Interval: time.Minute, MaxRequests: 10})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sub  GuardRuleInput
		key  string
		want string
	}{
		{"token-bucket", tb.Key("user", 1), "tokenBucket", defaultTokenBucketName},
		{"fixed-window", fw.Key("user", 1), "fixedWindow", defaultFixedWindowName},
		{"sliding-window", sw.Key("user", 1), "slidingWindow", defaultSlidingWindowName},
	}
	for _, tc := range cases {
		sub, err := tc.sub.guardSubmission(context.Background(), nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		rule, ok := sub.Rule[tc.key].(map[string]any)
		if !ok {
			t.Fatalf("%s: missing %s in %#v", tc.name, tc.key, sub.Rule)
		}
		if got := rule["configBucket"]; got != tc.want {
			t.Errorf("%s: configBucket = %v, want %q", tc.name, got, tc.want)
		}
	}
}

func TestNewGuardClientReadsARCJETKEY(t *testing.T) {
	t.Setenv("ARCJET_KEY", "ajkey_from_env")
	path, h := decidev2connect.NewDecideServiceHandler(&testGuardHandler{})
	mux := http.NewServeMux()
	mux.Handle(path, h)
	client, err := NewGuardClient(GuardConfig{
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.key != "ajkey_from_env" {
		t.Errorf("key = %q, want ajkey_from_env", client.key)
	}

	explicit, err := NewGuardClient(GuardConfig{
		Key:        "ajkey_explicit",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if explicit.key != "ajkey_explicit" {
		t.Errorf("explicit key = %q, want ajkey_explicit", explicit.key)
	}
}

func TestGuardLabelValidation(t *testing.T) {
	client, closeServer := newGuardTestClient(t, &testGuardHandler{})
	defer closeServer()
	_, err := client.Guard(context.Background(), GuardRequest{Label: "Tools.Bad"})
	if !errors.Is(err, ErrInvalidLabel) {
		t.Fatalf("expected ErrInvalidLabel, got %v", err)
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestGuardClientNilReceiver(t *testing.T) {
	var c *GuardClient
	_, err := c.Guard(context.Background(), GuardRequest{Label: "tools.test"})
	if !errors.Is(err, ErrNilClient) {
		t.Errorf("expected ErrNilClient, got %v", err)
	}
}

func TestGuardClientRejectsNilRuleInput(t *testing.T) {
	client, _ := newGuardTestClient(t, &testGuardHandler{})
	_, err := client.Guard(context.Background(), GuardRequest{
		Label: "tools.test",
		Rules: []GuardRuleInput{nil},
	})
	if !errors.Is(err, ErrNilRule) {
		t.Errorf("expected ErrNilRule, got %v", err)
	}
}

func TestGuardRateLimitKeyValidation(t *testing.T) {
	tb, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tb.Key("", 1).guardSubmission(context.Background(), nil); !errors.Is(err, ErrEmptyKey) {
		t.Errorf("token bucket: expected ErrEmptyKey, got %v", err)
	}

	fw, err := GuardFixedWindow(GuardFixedWindowOptions{Mode: ModeLive, Window: time.Minute, MaxRequests: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Key("", 1).guardSubmission(context.Background(), nil); !errors.Is(err, ErrEmptyKey) {
		t.Errorf("fixed window: expected ErrEmptyKey, got %v", err)
	}

	sw, err := GuardSlidingWindow(GuardSlidingWindowOptions{Mode: ModeLive, Interval: time.Minute, MaxRequests: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Key("", 1).guardSubmission(context.Background(), nil); !errors.Is(err, ErrEmptyKey) {
		t.Errorf("sliding window: expected ErrEmptyKey, got %v", err)
	}
}

func TestGuardRateLimitDefaultsRequestedToOne(t *testing.T) {
	tb, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := tb.Key("user_1", 0).guardSubmission(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	bucket := sub.Rule["tokenBucket"].(map[string]any)
	if bucket["inputRequested"].(uint32) != 1 {
		t.Errorf("requested = %v want 1", bucket["inputRequested"])
	}
}

func TestValidateGuardLabelEdges(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
	}{
		{"", false},
		{"Tools.Test", false},
		{"-bad", false},
		{"bad-", false},
		{".bad", false},
		{"bad.", false},
		{"bad!", false},
		{"ok", true},
		{"a", true},
		{"9", true},
		{"tools.foo-bar.42", true},
		{strings.Repeat("a", 257), false},
		{strings.Repeat("a", 256), true},
	}
	for _, tc := range cases {
		err := validateGuardLabel(tc.in)
		if (err == nil) != tc.valid {
			t.Errorf("validateGuardLabel(%q) err=%v want valid=%v", tc.in, err, tc.valid)
		}
	}
}

func TestHashKeyDeterministicAndPositional(t *testing.T) {
	// Determinism across separate invocations of hashKey with the same input.
	first := hashKey("user_1")
	second := hashKey("user_1")
	if first != second {
		t.Errorf("hashKey should be deterministic: %q != %q", first, second)
	}
	if hashKey("a", "b") == hashKey("ab") {
		t.Error("expected separator to differentiate parts from concatenation")
	}
	if hashKey("a", "b") == hashKey("b", "a") {
		t.Error("part order should affect hash")
	}
}

func TestGuardCustomSuccessProducesComputedResult(t *testing.T) {
	rule, err := GuardCustom(GuardCustomOptions{
		Mode:   ModeLive,
		Config: map[string]string{"plan": "free"},
		Func: func(_ context.Context, in map[string]string) (GuardCustomResult, error) {
			return GuardCustomResult{Conclusion: ConclusionDeny, Data: map[string]string{"why": "limit"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := rule.Input(map[string]string{"x": "y"}).guardSubmission(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := jsonMarshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, `"resultComputed"`) ||
		!strings.Contains(body, `"GUARD_CONCLUSION_DENY"`) ||
		!strings.Contains(body, `"why":"limit"`) {
		t.Errorf("unexpected payload: %s", body)
	}
	if strings.Contains(body, `"resultError"`) {
		t.Errorf("did not expect resultError on success: %s", body)
	}
}

func TestGuardCustomDefaultsToAllowConclusion(t *testing.T) {
	rule, err := GuardCustom(GuardCustomOptions{
		Mode: ModeLive,
		Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
			return GuardCustomResult{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := rule.Input(nil).guardSubmission(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := jsonMarshal(sub)
	if !strings.Contains(string(data), `"GUARD_CONCLUSION_ALLOW"`) {
		t.Errorf("expected default allow conclusion in %s", data)
	}
}

func TestGuardConclusionStringMapping(t *testing.T) {
	if got := guardConclusion(ConclusionDeny); got != "GUARD_CONCLUSION_DENY" {
		t.Errorf("deny = %q", got)
	}
	if got := guardConclusion(ConclusionAllow); got != "GUARD_CONCLUSION_ALLOW" {
		t.Errorf("allow = %q", got)
	}
	if got := guardConclusion(ConclusionChallenge); got != "GUARD_CONCLUSION_ALLOW" {
		t.Errorf("non-deny defaults to allow, got %q", got)
	}
}

func TestGuardTokenBucketResultAccessors(t *testing.T) {
	rule, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	tb := &GuardTokenBucketResult{RemainingTokens: 3, MaxTokens: 10}
	deniedTB := &GuardTokenBucketResult{RemainingTokens: 0, MaxTokens: 10}
	d := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: "other", TokenBucket: &GuardTokenBucketResult{RemainingTokens: 9}},
		{ConfigID: rule.base.configID, Conclusion: ConclusionAllow, TokenBucket: tb},
	}}
	if got := rule.Result(d); got != tb {
		t.Errorf("Result should match by configID, got %#v", got)
	}
	if rule.DeniedResult(d) != nil {
		t.Error("DeniedResult should be nil when allow")
	}
	d.Results[1] = GuardRuleResult{ConfigID: rule.base.configID, Conclusion: ConclusionDeny, TokenBucket: deniedTB}
	if got := rule.DeniedResult(d); got != deniedTB {
		t.Errorf("DeniedResult = %#v", got)
	}
	if rule.Result(GuardDecision{}) != nil {
		t.Error("Result on empty decision should be nil")
	}
}

func TestGuardFixedWindowResultAccessors(t *testing.T) {
	rule, err := GuardFixedWindow(GuardFixedWindowOptions{Mode: ModeLive, Window: time.Minute, MaxRequests: 10})
	if err != nil {
		t.Fatal(err)
	}
	fw := &GuardFixedWindowResult{RemainingRequests: 4}
	d := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionDeny, FixedWindow: fw},
	}}
	if rule.Result(d) != fw || rule.DeniedResult(d) != fw {
		t.Error("fixed window accessors did not return result")
	}
}

func TestGuardSlidingWindowResultAccessors(t *testing.T) {
	rule, err := GuardSlidingWindow(GuardSlidingWindowOptions{Mode: ModeLive, Interval: time.Minute, MaxRequests: 10})
	if err != nil {
		t.Fatal(err)
	}
	sw := &GuardSlidingWindowResult{RemainingRequests: 2}
	d := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionDeny, SlidingWindow: sw},
	}}
	if rule.Result(d) != sw || rule.DeniedResult(d) != sw {
		t.Error("sliding window accessors did not return result")
	}
}

func TestGuardPromptInjectionResultAccessors(t *testing.T) {
	rule, err := GuardPromptInjection(GuardPromptInjectionOptions{Mode: ModeLive})
	if err != nil {
		t.Fatal(err)
	}
	pr := &GuardPromptResult{Detected: true}
	d := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionDeny, PromptInjection: pr},
	}}
	if rule.Result(d) != pr || rule.DeniedResult(d) != pr {
		t.Error("prompt injection accessors did not return result")
	}
}

func TestGuardModerateContentResultAccessors(t *testing.T) {
	rule, err := GuardModerateContent(GuardModerateContentOptions{Mode: ModeLive})
	if err != nil {
		t.Fatal(err)
	}
	mc := &GuardModerateContentResult{Detected: true}
	d := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionDeny, ModerateContent: mc},
	}}
	if rule.Result(d) != mc || rule.DeniedResult(d) != mc {
		t.Error("moderate content accessors did not return result")
	}
}

func TestExperimentalGuardModerateContentDeprecatedAlias(t *testing.T) {
	rule, err := ExperimentalGuardModerateContent(ExperimentalGuardModerateContentOptions{Mode: ModeLive})
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil {
		t.Fatal("deprecated alias must return a GuardModerateContentRule")
	}
}

func TestGuardSensitiveInfoResultAccessors(t *testing.T) {
	rule, err := GuardSensitiveInfo(GuardSensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}})
	if err != nil {
		t.Fatal(err)
	}
	sr := &GuardSensitiveInfoResult{Detected: true, DetectedEntityTypes: []EntityType{SensitiveInfoEmail}}
	d := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionDeny, LocalSensitiveInfo: sr},
	}}
	if rule.Result(d) != sr || rule.DeniedResult(d) != sr {
		t.Error("sensitive info accessors did not return result")
	}
}

func TestGuardCustomResultAccessors(t *testing.T) {
	rule, err := GuardCustom(GuardCustomOptions{
		Mode: ModeLive,
		Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
			return GuardCustomResult{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cr := &GuardLocalCustomResult{Conclusion: ConclusionDeny}
	d := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionDeny, LocalCustom: cr},
	}}
	if rule.Result(d) != cr || rule.DeniedResult(d) != cr {
		t.Error("custom result accessors did not return result")
	}
}

// TestGuardErrorResultAccessor verifies the error/non-error split: ErrorResult
// surfaces an errored rule result, while Result/DeniedResult never do.
func TestGuardErrorResultAccessor(t *testing.T) {
	rule, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A rule that errored: fail-open ALLOW carrying an *ArcjetError, matched by
	// ConfigID. The error must surface via ErrorResult, never via Result.
	errored := &ArcjetError{Code: "AJ1100", Message: "boom"}
	d := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionAllow, Reason: ReasonError, Error: errored},
	}}
	if got := rule.ErrorResult(d); got != errored {
		t.Errorf("ErrorResult should return the rule's error, got %#v", got)
	}
	if rule.Result(d) != nil {
		t.Error("Result must not return an errored result")
	}
	if rule.DeniedResult(d) != nil {
		t.Error("DeniedResult must not return an errored result")
	}

	// No error present: ErrorResult is nil and a normal result resolves cleanly.
	tb := &GuardTokenBucketResult{RemainingTokens: 5, MaxTokens: 10}
	ok := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionAllow, TokenBucket: tb},
	}}
	if rule.ErrorResult(ok) != nil {
		t.Error("ErrorResult should be nil when nothing errored")
	}
	if rule.Result(ok) != tb {
		t.Error("Result should return the non-error result")
	}

	// A DENY is a trustworthy non-error result: it must NOT be dropped, and it
	// is not an error.
	deniedTB := &GuardTokenBucketResult{RemainingTokens: 0, MaxTokens: 10}
	denied := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionDeny, TokenBucket: deniedTB},
	}}
	if rule.DeniedResult(denied) != deniedTB {
		t.Error("a DENY result must still be returned by DeniedResult")
	}
	if rule.ErrorResult(denied) != nil {
		t.Error("a DENY is not an error")
	}

	// Defensive: a malformed result carrying BOTH an error and a rule field
	// must be treated as errored, never surfaced as a normal result.
	both := GuardDecision{Results: []GuardRuleResult{
		{ConfigID: rule.base.configID, Conclusion: ConclusionAllow, Error: errored, TokenBucket: tb},
	}}
	if rule.Result(both) != nil {
		t.Error("Result must exclude a result that also carries an error")
	}
	if rule.ErrorResult(both) != errored {
		t.Error("ErrorResult should surface the error even if a rule field is set")
	}

	if rule.ErrorResult(GuardDecision{}) != nil {
		t.Error("ErrorResult on empty decision should be nil")
	}
}

// TestGuardErrorResultAcrossRuleTypes verifies every rule type exposes a
// rule-level ErrorResult matched by ConfigID.
func TestGuardErrorResultAcrossRuleTypes(t *testing.T) {
	errored := &ArcjetError{Code: "AJ1200", Message: "x"}
	fw, _ := GuardFixedWindow(GuardFixedWindowOptions{Mode: ModeLive, Window: time.Minute, MaxRequests: 10})
	sw, _ := GuardSlidingWindow(GuardSlidingWindowOptions{Mode: ModeLive, Interval: time.Minute, MaxRequests: 10})
	pi, _ := GuardPromptInjection(GuardPromptInjectionOptions{Mode: ModeLive})
	mc, _ := GuardModerateContent(GuardModerateContentOptions{Mode: ModeLive})
	si, _ := GuardSensitiveInfo(GuardSensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}})
	cr, _ := GuardCustom(GuardCustomOptions{
		Mode: ModeLive,
		Func: func(context.Context, map[string]string) (GuardCustomResult, error) {
			return GuardCustomResult{}, nil
		},
	})

	type errorAccessor interface {
		ErrorResult(GuardDecision) *ArcjetError
	}
	// token_bucket is covered by TestGuardErrorResultAccessor above.
	cases := []struct {
		name     string
		configID string
		rule     errorAccessor
	}{
		{"fixed_window", fw.base.configID, fw},
		{"sliding_window", sw.base.configID, sw},
		{"prompt_injection", pi.base.configID, pi},
		{"moderate_content", mc.base.configID, mc},
		{"sensitive_info", si.base.configID, si},
		{"custom", cr.base.configID, cr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := GuardDecision{Results: []GuardRuleResult{
				{ConfigID: tc.configID, Conclusion: ConclusionAllow, Reason: ReasonError, Error: errored},
			}}
			if tc.rule.ErrorResult(d) != errored {
				t.Errorf("%s: ErrorResult did not return the error", tc.name)
			}
		})
	}
}

func TestGuardSensitiveInfoRejectsConflictingAllowDeny(t *testing.T) {
	if _, err := GuardSensitiveInfo(GuardSensitiveInfoOptions{
		Mode:  ModeLive,
		Allow: []EntityType{SensitiveInfoEmail},
		Deny:  []EntityType{SensitiveInfoIPAddress},
	}); err == nil {
		t.Error("expected allow+deny conflict to error")
	}
}

// TestGuardTransportFailureFailsOpenDecision verifies the Option C contract: a
// transport failure (runtime degradation) returns BOTH a non-nil error AND a
// usable fail-open ALLOW decision carrying a synthetic TRANSPORT_ERROR result,
// so a caller that ignores err still has HasFailedOpen() report true.
func TestGuardTransportFailureFailsOpenDecision(t *testing.T) {
	client, _ := newGuardTestClient(t, &testGuardHandler{
		errToReturn: connect.NewError(connect.CodeUnavailable, errors.New("upstream down")),
	})
	tb, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := client.Guard(context.Background(), GuardRequest{
		Label: "tools.test",
		Rules: []GuardRuleInput{tb.Key("user_1", 1)},
	})
	if err == nil {
		t.Fatal("expected a transport error alongside the fail-open decision")
	}
	// The decision is still usable and fail-open.
	if !d.IsAllowed() {
		t.Errorf("expected ALLOW (fail open), got %s", d.Conclusion)
	}
	if !d.HasFailedOpen() {
		t.Error("transport failure should be marked failed-open")
	}
	errs := d.ErrorResults()
	if len(errs) != 1 {
		t.Fatalf("expected one synthetic errored result, got %d", len(errs))
	}
	if errs[0].Error.Code != "TRANSPORT_ERROR" {
		t.Errorf("expected TRANSPORT_ERROR code, got %q", errs[0].Error.Code)
	}
	// No server response, so no decision-level warnings.
	if len(d.Warnings) != 0 {
		t.Errorf("expected no warnings, got %+v", d.Warnings)
	}
}

// TestGuardProgrammerErrorsReturnZeroDecision verifies that programmer errors
// (nil rule) return the zero-value decision plus a non-nil error — they do
// NOT fail open, so HasFailedOpen() on the returned (zero) decision is false
// and the caller must handle err.
func TestGuardProgrammerErrorsReturnZeroDecision(t *testing.T) {
	client, _ := newGuardTestClient(t, &testGuardHandler{})
	d, err := client.Guard(context.Background(), GuardRequest{
		Label: "tools.test",
		Rules: []GuardRuleInput{nil},
	})
	if !errors.Is(err, ErrNilRule) {
		t.Errorf("expected ErrNilRule, got %v", err)
	}
	// Zero-value decision: no results, so not failed-open. Caller must handle
	// err rather than trust the decision.
	if d.HasFailedOpen() {
		t.Error("programmer error should not produce a failed-open decision")
	}
	if len(d.Results) != 0 {
		t.Errorf("expected zero results on programmer error, got %d", len(d.Results))
	}
}
