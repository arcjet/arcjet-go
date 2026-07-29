package arcjet

import (
	"context"
	"errors"
	"testing"
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
