package arcjet

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

type testGuardHandler struct {
	seen   *decidev2.GuardRequest
	header http.Header
	resp   *decidev2.GuardResponse
	// errToReturn, when non-nil, makes Guard return a transport error instead
	// of a response — used to exercise the fail-open-on-transport path.
	errToReturn error
}

func (h *testGuardHandler) Guard(ctx context.Context, req *connect.Request[decidev2.GuardRequest]) (*connect.Response[decidev2.GuardResponse], error) {
	h.seen = req.Msg
	h.header = req.Header()
	if h.errToReturn != nil {
		return nil, h.errToReturn
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
		Label:    "tools.weather",
		Metadata: map[string]string{"env": "test"},
		Rules:    []GuardRuleInput{limit.Key("user_123", 2)},
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
	if seen.GetMetadata()["env"] != "test" {
		t.Fatalf("metadata = %#v", seen.GetMetadata())
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
		Metadata:    map[string]string{"a": "b"},
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
	moderate, err := ExperimentalGuardModerateContent(ExperimentalGuardModerateContentOptions{Mode: ModeLive})
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

func TestExperimentalGuardModerateContentResultAccessors(t *testing.T) {
	rule, err := ExperimentalGuardModerateContent(ExperimentalGuardModerateContentOptions{Mode: ModeLive})
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
