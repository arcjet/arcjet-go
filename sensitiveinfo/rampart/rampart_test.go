package rampart

import (
	"context"
	"strings"
	"sync"
	"testing"

	arcjet "github.com/arcjet/arcjet-go"
)

var (
	sharedOnce    sync.Once
	sharedBackend arcjet.SensitiveInfoBackend
)

// testBackend returns a shared backend so the (relatively expensive) model load
// happens once across the behavioral tests.
func testBackend(t *testing.T) arcjet.SensitiveInfoBackend {
	t.Helper()
	sharedOnce.Do(func() {
		b, err := New(Options{})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		sharedBackend = b
	})
	return sharedBackend
}

func detect(t *testing.T, b arcjet.SensitiveInfoBackend, value string, ents arcjet.SensitiveInfoEntities) arcjet.SensitiveInfoResult {
	t.Helper()
	res, err := b.Detect(context.Background(), arcjet.SensitiveInfoBackendContext{}, value, ents, nil)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return res
}

// hasEntity reports whether entities contains one of type typ whose spanned
// text (case-insensitively) contains want.
func hasEntity(entities []arcjet.DetectedSensitiveInfoEntity, value string, typ arcjet.EntityType, want string) bool {
	for _, e := range entities {
		if e.Type == typ && e.Start >= 0 && e.End <= len(value) &&
			strings.Contains(strings.ToLower(value[e.Start:e.End]), strings.ToLower(want)) {
			return true
		}
	}
	return false
}

func joinedEntityText(entities []arcjet.DetectedSensitiveInfoEntity, value string, typ arcjet.EntityType) string {
	var result strings.Builder
	for _, entity := range entities {
		if entity.Type == typ && entity.Start >= 0 && entity.End <= len(value) {
			result.WriteString(value[entity.Start:entity.End])
		}
	}
	return result.String()
}

func TestDetectNamesAndPlaces(t *testing.T) {
	b := testBackend(t)
	value := "My name is Sarah and I live in London"
	res := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()})
	if !hasEntity(res.Denied, value, arcjet.SensitiveInfoGivenName, "Sarah") {
		t.Errorf("expected GIVEN_NAME Sarah in %+v", res.Denied)
	}
	if !hasEntity(res.Denied, value, arcjet.SensitiveInfoCity, "London") {
		t.Errorf("expected CITY London in %+v", res.Denied)
	}
}

func TestDetectStructuredViaRecognizers(t *testing.T) {
	b := testBackend(t)
	value := "Reach me at john.doe@example.com or (555) 234-5678. SSN 123-45-6789. See https://example.com/x."
	res := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()})
	checks := []struct {
		typ  arcjet.EntityType
		want string
	}{
		{arcjet.SensitiveInfoEmail, "john.doe@example.com"},
		{arcjet.SensitiveInfoPhoneNumber, "234-5678"},
		{arcjet.SensitiveInfoSSN, "123-45-6789"},
		{arcjet.SensitiveInfoURL, "example.com"},
	}
	for _, c := range checks {
		if !hasEntity(res.Denied, value, c.typ, c.want) {
			t.Errorf("expected %s (%q) in denied %+v", c.typ, c.want, res.Denied)
		}
	}
}

func TestModelDistinguishesBankAccountsAndRoutingNumbersFromPhones(t *testing.T) {
	b := testBackend(t)
	value := "Details on file: name: Alex Morgan; email: alex.morgan@client-corp.example; ssn: 431-55-9928; bank_account: 0123456789; routing_number: 022000020"
	res := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()})

	if got := joinedEntityText(res.Denied, value, arcjet.SensitiveInfoBankAccount); got != "0123456789" {
		t.Errorf("BANK_ACCOUNT text = %q, want %q; denied=%+v", got, "0123456789", res.Denied)
	}
	if got := joinedEntityText(res.Denied, value, arcjet.SensitiveInfoRoutingNumber); got != "022000020" {
		t.Errorf("ROUTING_NUMBER text = %q, want %q; denied=%+v", got, "022000020", res.Denied)
	}
	if got := joinedEntityText(res.Denied, value, arcjet.SensitiveInfoPhoneNumber); got != "" {
		t.Errorf("unexpected PHONE_NUMBER text %q; denied=%+v", got, res.Denied)
	}
}

func TestDetectAllowMode(t *testing.T) {
	b := testBackend(t)
	value := "Email jane@example.com, name Robert."
	// Allow only EMAIL: the email is allowed, the name is denied.
	res := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: false, Entities: []arcjet.EntityType{arcjet.SensitiveInfoEmail}})
	if !hasEntity(res.Allowed, value, arcjet.SensitiveInfoEmail, "jane@example.com") {
		t.Errorf("expected EMAIL allowed, got allowed=%+v", res.Allowed)
	}
	if hasEntity(res.Denied, value, arcjet.SensitiveInfoEmail, "jane@example.com") {
		t.Errorf("EMAIL should not be denied in allow=[EMAIL] mode")
	}
	if !hasEntity(res.Denied, value, arcjet.SensitiveInfoGivenName, "Robert") {
		t.Errorf("expected GIVEN_NAME denied in allow=[EMAIL] mode, got denied=%+v", res.Denied)
	}
}

func TestDetectDenyModeOnlyListed(t *testing.T) {
	b := testBackend(t)
	value := "Email jane@example.com, name Robert."
	// Deny only EMAIL: email denied, name allowed.
	res := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: true, Entities: []arcjet.EntityType{arcjet.SensitiveInfoEmail}})
	if !hasEntity(res.Denied, value, arcjet.SensitiveInfoEmail, "jane@example.com") {
		t.Errorf("expected EMAIL denied, got denied=%+v", res.Denied)
	}
	if hasEntity(res.Denied, value, arcjet.SensitiveInfoGivenName, "Robert") {
		t.Errorf("GIVEN_NAME should not be denied in deny=[EMAIL] mode")
	}
}

func TestDetectCleanTextNoDetections(t *testing.T) {
	b := testBackend(t)
	value := "The quick brown fox jumps over the lazy dog."
	res := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()})
	if len(res.Denied) != 0 {
		t.Errorf("expected no detections in clean text, got %+v", res.Denied)
	}
}

func TestDetectModelOnly(t *testing.T) {
	// Empty (non-nil) recognizers disables the deterministic recognizers.
	b, err := New(Options{Recognizers: []Recognizer{}})
	if err != nil {
		t.Fatal(err)
	}
	value := "Contact Sarah at 123-45-6789."
	res := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()})
	// The name is still found by the model; the SSN recognizer is off, so no
	// recognizer-only SSN span (the model may or may not tag it).
	if !hasEntity(res.Denied, value, arcjet.SensitiveInfoGivenName, "Sarah") {
		t.Errorf("expected model to still detect the name, got %+v", res.Denied)
	}
}

func TestDetectTruncatesLongInput(t *testing.T) {
	b, err := New(Options{MaxInputChars: 20})
	if err != nil {
		t.Fatal(err)
	}
	value := "Sarah lives here. " + strings.Repeat("x", 1000)
	res := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()})
	for _, e := range append(res.Denied, res.Allowed...) {
		if e.End > 20 {
			t.Errorf("detection past truncation limit: %+v", e)
		}
	}
}

func TestDetectRespectsContextCancellation(t *testing.T) {
	b := testBackend(t)
	// Long enough to require many windows; an already-cancelled context must
	// stop the scan before the first window rather than run to completion.
	value := strings.Repeat("Contact Sarah Smith in London. ", 400) // ~12k chars
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.Detect(ctx, arcjet.SensitiveInfoBackendContext{}, value,
		arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}, nil)
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
}

func TestEntitiesCount(t *testing.T) {
	if got := len(Entities()); got != 20 {
		t.Fatalf("Entities() = %d, want 20", got)
	}
}

func TestBackendImplementsInterface(t *testing.T) {
	var _ arcjet.SensitiveInfoBackend = (*backend)(nil)
}

func TestNewDefaults(t *testing.T) {
	b, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	impl := b.(*backend)
	if impl.runner.threshold != DefaultThreshold {
		t.Errorf("threshold = %v, want %v", impl.runner.threshold, DefaultThreshold)
	}
	if impl.maxInputChars != DefaultMaxInputChars {
		t.Errorf("maxInputChars = %d, want %d", impl.maxInputChars, DefaultMaxInputChars)
	}
	if len(impl.recognizers) != len(DefaultRecognizers) {
		t.Errorf("recognizers = %d, want %d", len(impl.recognizers), len(DefaultRecognizers))
	}
}
