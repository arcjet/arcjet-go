package arcjet

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1/decidev1alpha1connect"
	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

// mockBackend is a test SensitiveInfoBackend that returns a canned result (or
// error) and records the entities it was called with.
type mockBackend struct {
	result   SensitiveInfoResult
	err      error
	gotDeny  bool
	gotList  []EntityType
	gotValue string
	called   bool
}

func (m *mockBackend) Detect(_ context.Context, _ SensitiveInfoBackendContext, value string, entities SensitiveInfoEntities, _ *SensitiveInfoBackendOptions) (SensitiveInfoResult, error) {
	m.called = true
	m.gotDeny = entities.Deny
	m.gotList = entities.Entities
	m.gotValue = value
	return m.result, m.err
}

// declaringBackend is a mockBackend that also declares the entity types it
// supports via the optional SensitiveInfoBackendEntitySupporter interface.
type declaringBackend struct {
	mockBackend
	supported []EntityType
}

func (d *declaringBackend) SupportedEntities() []EntityType { return d.supported }

func TestValidateSensitiveInfoEntities(t *testing.T) {
	// A backend that does not declare its entities (trusted for any type).
	opaque := &mockBackend{}
	// A backend that declares support only for GIVEN_NAME.
	declaresGivenName := &declaringBackend{supported: []EntityType{SensitiveInfoGivenName}}

	tests := []struct {
		name      string
		allow     []EntityType
		deny      []EntityType
		backend   SensitiveInfoBackend
		hasDetect bool
		wantErr   bool
	}{
		{name: "native deny, no backend", deny: []EntityType{SensitiveInfoEmail}},
		{name: "all native", deny: []EntityType{SensitiveInfoEmail, SensitiveInfoPhoneNumber, SensitiveInfoIPAddress, SensitiveInfoCreditCardNumber}},
		{name: "non-native deny, no backend", deny: []EntityType{SensitiveInfoGivenName}, wantErr: true},
		{name: "non-native allow, no backend", allow: []EntityType{SensitiveInfoCity}, wantErr: true},
		{name: "non-native deny, with opaque backend", deny: []EntityType{SensitiveInfoGivenName}, backend: opaque},
		{name: "non-native deny, with detect", deny: []EntityType{SensitiveInfoSSN}, hasDetect: true},
		{name: "custom label, no backend", deny: []EntityType{"MY_CUSTOM"}, wantErr: true},
		{name: "declared type, declaring backend", deny: []EntityType{SensitiveInfoGivenName}, backend: declaresGivenName},
		{name: "undeclared type, declaring backend", deny: []EntityType{SensitiveInfoSurname}, backend: declaresGivenName, wantErr: true},
		{name: "custom label, declaring backend", deny: []EntityType{"MY_CUSTOM"}, backend: declaresGivenName, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSensitiveInfoEntities(tt.allow, tt.deny, tt.backend, tt.hasDetect)
			if tt.wantErr {
				if !errors.Is(err, ErrUnsupportedEntityType) {
					t.Fatalf("want ErrUnsupportedEntityType, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want nil error, got %v", err)
			}
		})
	}
}

func TestSensitiveInfoRuleErrorsOnUnsupportedEntity(t *testing.T) {
	rule := SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoGivenName}})
	eval := newLazyLocalEvaluator(nil)
	defer eval.close(context.Background())

	_, err := rule.evaluateLocal(context.Background(), ProtectDetails{},
		ProtectOptions{SensitiveInfoValue: "My name is Sarah"}, eval)
	if !errors.Is(err, ErrUnsupportedEntityType) {
		t.Fatalf("want ErrUnsupportedEntityType, got %v", err)
	}
}

func TestGuardSensitiveInfoErrorsOnUnsupportedEntity(t *testing.T) {
	rule, err := GuardSensitiveInfo(GuardSensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoCity}})
	if err != nil {
		t.Fatal(err)
	}
	eval := newLazyLocalEvaluator(nil)
	defer eval.close(context.Background())

	_, err = rule.Text("some text").guardSubmission(context.Background(), eval)
	if !errors.Is(err, ErrUnsupportedEntityType) {
		t.Fatalf("want ErrUnsupportedEntityType, got %v", err)
	}
}

func TestSensitiveInfoDispatchesToBackend(t *testing.T) {
	backend := &mockBackend{result: SensitiveInfoResult{
		Denied: []DetectedSensitiveInfoEntity{{Start: 11, End: 16, Type: SensitiveInfoGivenName}},
	}}
	rule := SensitiveInfo(SensitiveInfoOptions{
		Mode:    ModeLive,
		Deny:    []EntityType{SensitiveInfoGivenName},
		Backend: backend,
	})
	eval := newLazyLocalEvaluator(nil)
	defer eval.close(context.Background())

	decision, err := rule.evaluateLocal(context.Background(), ProtectDetails{},
		ProtectOptions{SensitiveInfoValue: "My name is Sarah"}, eval)
	if err != nil {
		t.Fatal(err)
	}
	if !backend.called {
		t.Fatal("backend was not called")
	}
	if !backend.gotDeny || len(backend.gotList) != 1 || backend.gotList[0] != SensitiveInfoGivenName {
		t.Fatalf("backend got unexpected entities: deny=%v list=%v", backend.gotDeny, backend.gotList)
	}
	if backend.gotValue != "My name is Sarah" {
		t.Fatalf("backend got unexpected value %q", backend.gotValue)
	}
	if !decision.liveDeny() {
		t.Fatalf("expected live deny, got %#v", decision)
	}
	denied := decision.decision.GetReason().GetSensitiveInfo().GetDenied()
	if len(denied) != 1 || denied[0].GetIdentifiedType() != string(SensitiveInfoGivenName) {
		t.Fatalf("expected GIVEN_NAME denied entity, got %#v", denied)
	}
}

func TestSensitiveInfoBackendAllowedProducesNoDeny(t *testing.T) {
	backend := &mockBackend{result: SensitiveInfoResult{
		Allowed: []DetectedSensitiveInfoEntity{{Start: 0, End: 5, Type: SensitiveInfoGivenName}},
	}}
	rule := SensitiveInfo(SensitiveInfoOptions{
		Mode:    ModeLive,
		Allow:   []EntityType{SensitiveInfoGivenName},
		Backend: backend,
	})
	eval := newLazyLocalEvaluator(nil)
	defer eval.close(context.Background())

	decision, err := rule.evaluateLocal(context.Background(), ProtectDetails{},
		ProtectOptions{SensitiveInfoValue: "Sarah"}, eval)
	if err != nil {
		t.Fatal(err)
	}
	if backend.gotDeny {
		t.Fatal("expected allow-list dispatch (Deny=false)")
	}
	if decision != nil && decision.liveDeny() {
		t.Fatalf("expected no deny, got %#v", decision)
	}
}

func TestSensitiveInfoBackendErrorPropagates(t *testing.T) {
	sentinel := errors.New("backend boom")
	backend := &mockBackend{err: sentinel}
	rule := SensitiveInfo(SensitiveInfoOptions{
		Mode:    ModeLive,
		Deny:    []EntityType{SensitiveInfoGivenName},
		Backend: backend,
	})
	eval := newLazyLocalEvaluator(nil)
	defer eval.close(context.Background())

	_, err := rule.evaluateLocal(context.Background(), ProtectDetails{},
		ProtectOptions{SensitiveInfoValue: "Sarah"}, eval)
	if !errors.Is(err, sentinel) {
		t.Fatalf("want backend error, got %v", err)
	}
}

// limitedBackend is a mockBackend that declares a scan limit via the optional
// SensitiveInfoBackendLimiter interface.
type limitedBackend struct {
	mockBackend
	limit int
}

func (l *limitedBackend) MaxInputChars() int { return l.limit }

// The SensitiveInfo rule denies input over a backend's declared limit without
// running the backend, rather than letting the backend scan a prefix.
func TestSensitiveInfoBackendLimit(t *testing.T) {
	// "é" is two bytes and one code point, so these strings are twice as long
	// in bytes as in characters.
	tests := []struct {
		name       string
		backend    func() *mockBackend
		limiter    bool
		mode       Mode
		text       string
		wantCalled bool
		wantDeny   bool
		wantState  decidev1.RuleState
		wantOuter  decidev1.Conclusion
		wantMsg    string
	}{
		{
			name: "live over limit", limiter: true, mode: ModeLive, text: "abcde",
			wantDeny: true, wantState: decidev1.RuleState_RULE_STATE_RUN, wantOuter: decidev1.Conclusion_CONCLUSION_DENY,
			wantMsg: "sensitive info input of 5 characters exceeds the backend limit of 4",
		},
		{
			name: "dry run over limit", limiter: true, mode: ModeDryRun, text: "abcde",
			wantDeny: true, wantState: decidev1.RuleState_RULE_STATE_DRY_RUN, wantOuter: decidev1.Conclusion_CONCLUSION_ALLOW,
			wantMsg: "sensitive info input of 5 characters exceeds the backend limit of 4",
		},
		{name: "exactly at limit", limiter: true, mode: ModeLive, text: "abcd", wantCalled: true},
		{name: "multi-byte at limit", limiter: true, mode: ModeLive, text: "éééé", wantCalled: true},
		{
			name: "multi-byte over limit", limiter: true, mode: ModeLive, text: "ééééé",
			wantDeny: true, wantState: decidev1.RuleState_RULE_STATE_RUN, wantOuter: decidev1.Conclusion_CONCLUSION_DENY,
			wantMsg: "sensitive info input of 5 characters exceeds the backend limit of 4",
		},
		{name: "backend without a limit", mode: ModeLive, text: strings.Repeat("a", 100_000), wantCalled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var backend SensitiveInfoBackend
			var mock *mockBackend
			if tt.limiter {
				lb := &limitedBackend{limit: 4}
				backend, mock = lb, &lb.mockBackend
			} else {
				mock = &mockBackend{}
				backend = mock
			}
			rule := SensitiveInfo(SensitiveInfoOptions{
				Mode:    tt.mode,
				Deny:    []EntityType{SensitiveInfoGivenName},
				Backend: backend,
			})
			var logs bytes.Buffer
			eval := newLazyLocalEvaluator(nil)
			eval.log = slog.New(slog.NewTextHandler(&logs, nil))
			defer eval.close(context.Background())

			decision, err := rule.evaluateLocal(context.Background(), ProtectDetails{},
				ProtectOptions{SensitiveInfoValue: tt.text}, eval)
			if err != nil {
				t.Fatal(err)
			}
			if mock.called != tt.wantCalled {
				t.Fatalf("backend called = %v, want %v", mock.called, tt.wantCalled)
			}
			if !tt.wantDeny {
				if decision != nil {
					t.Fatalf("expected no decision, got %#v", decision)
				}
				if logs.Len() != 0 {
					t.Fatalf("expected no warning, got %q", logs.String())
				}
				return
			}
			if decision == nil {
				t.Fatal("expected a decision")
			}
			if got := decision.decision.GetConclusion(); got != tt.wantOuter {
				t.Fatalf("outer conclusion = %s, want %s", got, tt.wantOuter)
			}
			results := decision.decision.GetRuleResults()
			if len(results) != 1 {
				t.Fatalf("rule results = %#v", results)
			}
			result := results[0]
			if result.GetConclusion() != decidev1.Conclusion_CONCLUSION_DENY || result.GetState() != tt.wantState {
				t.Fatalf("rule result = %s/%s", result.GetConclusion(), result.GetState())
			}
			if got := result.GetReason().GetError().GetMessage(); got != tt.wantMsg {
				t.Fatalf("error reason = %q, want %q", got, tt.wantMsg)
			}
			if result.GetTtl() != 0 {
				t.Fatalf("ttl = %d, want 0 so the denial is never cached", result.GetTtl())
			}
			if strings.Contains(result.GetReason().GetError().GetMessage(), tt.text) {
				t.Fatal("error reason contains the input text")
			}
			if n := strings.Count(logs.String(), "exceeds the backend limit"); n != 1 {
				t.Fatalf("warnings = %d, want 1: %q", n, logs.String())
			}
			if !strings.Contains(logs.String(), "characters=5") || !strings.Contains(logs.String(), "limit=4") {
				t.Fatalf("warning lacks counts: %q", logs.String())
			}
			if strings.Contains(logs.String(), tt.text) {
				t.Fatalf("warning contains the input text: %q", logs.String())
			}

			public := decisionFromProto(decision.decision)
			if tt.mode == ModeLive {
				if !public.IsDenied() || !public.IsErrored() || !public.Reason.IsError() || public.Reason.IsSensitiveInfo() {
					t.Fatalf("live decision = %#v", public)
				}
			} else if !public.IsAllowed() || public.IsDenied() {
				t.Fatalf("dry-run decision = %#v", public)
			}
			if len(public.Results) != 1 || public.Results[0].Reason.Message != tt.wantMsg {
				t.Fatalf("public results = %#v", public.Results)
			}
		})
	}
}

// A live oversize denial short-circuits Decide and is reported like any other
// local denial, without the scanned text.
func TestProtectReportsSensitiveInfoOverLimit(t *testing.T) {
	handler := &testDecideHandler{reportCh: make(chan struct{}, 1)}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	backend := &limitedBackend{limit: 8}
	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Log:        slog.New(slog.DiscardHandler),
		Rules: []Rule{
			SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}, Backend: backend}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())

	const text = "padding filler: user@example.com"
	decision, err := client.ProtectDetails(context.Background(), ProtectDetails{}, WithSensitiveInfoValue(text))
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsDenied() {
		t.Fatalf("expected deny, got %#v", decision)
	}
	if backend.called {
		t.Fatal("backend ran on oversize input")
	}
	handler.waitReport(t)
	snap := handler.snapshot()
	if snap.decideCalls != 0 || snap.reportCalls != 1 {
		t.Fatalf("expected report-only path, decide=%d report=%d", snap.decideCalls, snap.reportCalls)
	}
	reported := snap.reportSeen.GetDecision()
	if reported.GetConclusion() != decidev1.Conclusion_CONCLUSION_DENY ||
		reported.GetReason().GetError().GetMessage() != "sensitive info input of 32 characters exceeds the backend limit of 8" {
		t.Fatalf("reported decision = %#v", reported)
	}
	wire, err := jsonMarshal(snap.reportSeen)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "user@example.com") {
		t.Fatalf("report contains the scanned text: %s", wire)
	}
}

// The Guard sensitive-info rule sends a computed DENY for input over the
// backend's limit, which the server enforces for a live rule, and never a
// resultError, which the server treats as fail-open.
func TestGuardSensitiveInfoBackendLimit(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		text       string
		wantCalled bool
		wantDeny   bool
	}{
		{name: "live over limit", mode: ModeLive, text: "abcde", wantDeny: true},
		{name: "dry run over limit", mode: ModeDryRun, text: "abcde", wantDeny: true},
		{name: "exactly at limit", mode: ModeLive, text: "abcd", wantCalled: true},
		{name: "multi-byte at limit", mode: ModeLive, text: "éééé", wantCalled: true},
		{name: "multi-byte over limit", mode: ModeLive, text: "ééééé", wantDeny: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &limitedBackend{limit: 4}
			rule, err := GuardSensitiveInfo(GuardSensitiveInfoOptions{
				Mode:    tt.mode,
				Deny:    []EntityType{SensitiveInfoEmail},
				Backend: backend,
			})
			if err != nil {
				t.Fatal(err)
			}
			handler := &testGuardHandler{resp: &decidev2.GuardResponse{
				Decision: &decidev2.GuardDecision{Id: "gdec_limit", Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW},
			}}
			client := newGuardTestClient(t, handler)
			var logs bytes.Buffer
			client.local.log = slog.New(slog.NewTextHandler(&logs, nil))

			if _, err := client.Guard(context.Background(), GuardRequest{
				Label: "tools.limit",
				Rules: []GuardRuleInput{rule.Text(tt.text)},
			}); err != nil {
				t.Fatal(err)
			}
			subs := handler.seen.GetRuleSubmissions()
			if len(subs) != 1 {
				t.Fatalf("submissions = %d, want 1", len(subs))
			}
			sub := subs[0]
			if backend.called != tt.wantCalled {
				t.Fatalf("backend called = %v, want %v", backend.called, tt.wantCalled)
			}
			si := sub.GetRule().GetLocalSensitiveInfo()
			if si.GetResultError() != nil {
				t.Fatalf("unexpected resultError: %#v", si.GetResultError())
			}
			computed := si.GetResultComputed()
			if computed == nil {
				t.Fatal("expected resultComputed")
			}
			if si.GetInputTextHash() != sha256Hex(tt.text) {
				t.Fatalf("inputTextHash = %q", si.GetInputTextHash())
			}
			if !tt.wantDeny {
				if computed.GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW {
					t.Fatalf("conclusion = %s, want ALLOW", computed.GetConclusion())
				}
				if logs.Len() != 0 {
					t.Fatalf("expected no warning, got %q", logs.String())
				}
				return
			}
			if computed.GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_DENY {
				t.Fatalf("conclusion = %s, want DENY", computed.GetConclusion())
			}
			if computed.GetDetected() || len(computed.GetDetectedEntityTypes()) != 0 {
				t.Fatalf("expected no detected entities, got %#v", computed)
			}
			if n := strings.Count(logs.String(), "exceeds the backend limit"); n != 1 {
				t.Fatalf("warnings = %d, want 1: %q", n, logs.String())
			}
			wantMode := decidev2.GuardRuleMode_GUARD_RULE_MODE_LIVE
			if tt.mode == ModeDryRun {
				wantMode = decidev2.GuardRuleMode_GUARD_RULE_MODE_DRY_RUN
			}
			if sub.GetMode() != wantMode {
				t.Fatalf("mode = %s, want %s", sub.GetMode(), wantMode)
			}
			wire, err := jsonMarshal(sub)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(wire), tt.text) {
				t.Fatalf("submission contains the input text: %s", wire)
			}
		})
	}
}
