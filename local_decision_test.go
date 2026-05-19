package arcjet

import (
	"context"
	"fmt"
	"sync"
	"testing"

	localbot "github.com/arcjet/arcjet-go/internal/local/bot"
)

func TestLocalEvaluatorAllowsNonMatchingWasmRules(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		ValidateEmail(EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}}),
		Filter(FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "bad.example"`}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	emailDecision, err := evaluator.validateEmail(
		context.Background(),
		EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}},
		ProtectDetails{Email: "user@example.com"},
		ProtectOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if emailDecision != nil {
		t.Fatalf("expected valid email to allow, got %#v", emailDecision)
	}

	filterDecision, err := evaluator.matchFilter(
		context.Background(),
		FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "bad.example"`}},
		ProtectDetails{Host: "example.com"},
		ProtectOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if filterDecision != nil {
		t.Fatalf("expected non-matching filter to allow, got %#v", filterDecision)
	}
}

func TestLocalBotEmptyAllowBlocksDetectedBots(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Allow: []string{}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	decision, err := evaluator.detectBot(
		context.Background(),
		BotOptions{Mode: ModeLive, Allow: []string{}},
		ProtectDetails{Headers: map[string]string{"user-agent": "curl/8.7.1"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.liveDeny() {
		t.Fatalf("expected detected bot to be denied by empty allow list, got %#v", decision)
	}
}

func TestLocalFilterMatchesFilterLocalFields(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		Filter(FilterOptions{Mode: ModeLive, Deny: []string{`local["plan"] == "free"`}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	decision, err := evaluator.matchFilter(
		context.Background(),
		FilterOptions{Mode: ModeLive, Deny: []string{`local["plan"] == "free"`}},
		ProtectDetails{},
		ProtectOptions{FilterLocal: map[string]string{"plan": "free"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.liveDeny() {
		t.Fatalf("expected filter local fields to deny, got %#v", decision)
	}
}

func TestLocalEvaluatorWarmsConfiguredWasmFactories(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
		ValidateEmail(EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}}),
		Filter(FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "example.com"`}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())
	if evaluator.botFactory == nil || evaluator.emailFactory == nil || evaluator.filterFactory == nil {
		t.Fatalf("expected all configured Wasm factories to be warmed, got bot=%v email=%v filter=%v", evaluator.botFactory != nil, evaluator.emailFactory != nil, evaluator.filterFactory != nil)
	}
}

func TestLocalEvaluatorSupportsConcurrentWasmEvaluations(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
		ValidateEmail(EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}}),
		Filter(FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "example.com"`}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	var wg sync.WaitGroup
	errs := make(chan error, 90)
	for range 30 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			decision, err := evaluator.validateEmail(context.Background(), EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}}, ProtectDetails{Email: "invalid-email@//example-com"}, ProtectOptions{})
			if err != nil {
				errs <- err
				return
			}
			if !decision.liveDeny() {
				errs <- errExpectedLocalDeny("email")
			}
		}()
		go func() {
			defer wg.Done()
			decision, err := evaluator.detectBot(context.Background(), BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}, ProtectDetails{Headers: map[string]string{"user-agent": "curl/8.7.1"}})
			if err != nil {
				errs <- err
				return
			}
			if !decision.liveDeny() {
				errs <- errExpectedLocalDeny("bot")
			}
		}()
		go func() {
			defer wg.Done()
			decision, err := evaluator.matchFilter(context.Background(), FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "example.com"`}}, ProtectDetails{Host: "example.com"}, ProtectOptions{})
			if err != nil {
				errs <- err
				return
			}
			if !decision.liveDeny() {
				errs <- errExpectedLocalDeny("filter")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestLocalDryRunDecisionDoesNotShortCircuit(t *testing.T) {
	reason := localDeny("local_test", ModeDryRun, 60, nil)
	if reason.liveDeny() {
		t.Fatal("dry-run local decision must not short-circuit")
	}
	if got := reason.decision.GetRuleResults()[0].GetState(); got.String() != "RULE_STATE_DRY_RUN" {
		t.Fatalf("state = %s", got)
	}
}

func TestLocalFailOpenOverrides(t *testing.T) {
	email := failOpenEmailOverrides{}
	if email.IsFreeEmail(context.Background(), "example.com") {
		t.Fatal("free email override should default false")
	}
	if email.IsDisposableEmail(context.Background(), "example.com") {
		t.Fatal("disposable email override should default false")
	}
	if !email.HasMxRecords(context.Background(), "example.com") {
		t.Fatal("MX override should fail open")
	}
	if email.HasGravatar(context.Background(), "user@example.com") {
		t.Fatal("gravatar override should default false")
	}
	if detected, ok := (noopBotIdentifier{}).Detect(context.Background(), "{}"); ok || detected != "" {
		t.Fatalf("bot identifier = %q, %v", detected, ok)
	}
	if got := (noopBotVerifier{}).Verify(context.Background(), "CURL", "192.0.2.1"); got != localbot.Unverifiable {
		t.Fatalf("bot verifier = %#v", got)
	}
}

func errExpectedLocalDeny(kind string) error {
	return fmt.Errorf("expected local %s deny", kind)
}

func TestCleanMapAnyDropsEmptyStringsAndMaps(t *testing.T) {
	out := cleanMapAny(map[string]any{
		"ip":    "1.2.3.4",
		"host":  "",
		"extra": map[string]string{},
		"kept":  map[string]string{"a": "b"},
	})
	if _, ok := out["host"]; ok {
		t.Error("empty string not dropped")
	}
	if _, ok := out["extra"]; ok {
		t.Error("empty map not dropped")
	}
	if out["ip"] != "1.2.3.4" || out["kept"] == nil {
		t.Errorf("expected entries kept, got %#v", out)
	}
}
