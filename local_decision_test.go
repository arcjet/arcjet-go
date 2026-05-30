package arcjet

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/arcjet/arcjet-go/internal/local/jsreq"
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
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())
	if evaluator.factory == nil {
		t.Fatal("expected the jsreq factory to be warmed when any local rule is configured")
	}
}

func TestLocalEvaluatorSkipsFactoryWhenNoLocalRules(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		// PromptInjection has no local kind, so the factory should not warm.
		DetectPromptInjection(PromptInjectionOptions{Mode: ModeLive}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())
	if evaluator.factory != nil {
		t.Fatal("expected factory to stay nil when no local rules are configured")
	}
}

func TestLocalEvaluatorSupportsConcurrentWasmEvaluations(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
		ValidateEmail(EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}}),
		Filter(FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "example.com"`}}),
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	var wg sync.WaitGroup
	errs := make(chan error, 120)
	for range 30 {
		wg.Add(4)
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
		go func() {
			defer wg.Done()
			decision, err := evaluator.detectSensitiveInfo(
				context.Background(),
				SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}},
				ProtectDetails{},
				ProtectOptions{SensitiveInfoValue: "Reach me at customer@example.com please."},
			)
			if err != nil {
				errs <- err
				return
			}
			if !decision.liveDeny() {
				errs <- errExpectedLocalDeny("sensitive_info")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestLocalSensitiveInfoDeniesConfiguredEntityType(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	decision, err := evaluator.detectSensitiveInfo(
		context.Background(),
		SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}},
		ProtectDetails{},
		ProtectOptions{SensitiveInfoValue: "Please contact alice@example.com."},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.liveDeny() {
		t.Fatalf("expected sensitive-info deny for email entity, got %#v", decision)
	}
	reason := decision.decision.GetReason().GetSensitiveInfo()
	if reason == nil {
		t.Fatal("expected SensitiveInfoReason on decision")
	}
	if len(reason.Denied) == 0 || reason.Denied[0].IdentifiedType != string(SensitiveInfoEmail) {
		t.Fatalf("expected denied EMAIL entity, got %#v", reason.Denied)
	}
}

func TestLocalSensitiveInfoAllowsWhenNoMatch(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	decision, err := evaluator.detectSensitiveInfo(
		context.Background(),
		SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}},
		ProtectDetails{},
		ProtectOptions{SensitiveInfoValue: "Hello world."},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision != nil {
		t.Fatalf("expected nil decision when no sensitive info matched, got %#v", decision)
	}
}

func TestLocalSensitiveInfoAllowListDeniesUnlistedTypes(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Allow: []EntityType{SensitiveInfoCreditCardNumber}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	decision, err := evaluator.detectSensitiveInfo(
		context.Background(),
		SensitiveInfoOptions{Mode: ModeLive, Allow: []EntityType{SensitiveInfoCreditCardNumber}},
		ProtectDetails{},
		ProtectOptions{SensitiveInfoValue: "Reach me at alice@example.com please."},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.liveDeny() {
		t.Fatalf("expected sensitive-info deny when EMAIL is outside the allow list, got %#v", decision)
	}
}

func TestLocalSensitiveInfoSkipsWhenValueEmpty(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	decision, err := evaluator.detectSensitiveInfo(
		context.Background(),
		SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}},
		ProtectDetails{},
		ProtectOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision != nil {
		t.Fatalf("expected nil decision when WithSensitiveInfoValue is unset, got %#v", decision)
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

func TestSensitiveInfoEntityWireRoundtrip(t *testing.T) {
	cases := []struct {
		in   EntityType
		want jsreq.SensitiveInfoEntity
	}{
		{SensitiveInfoEmail, jsreq.SensitiveInfoEntityEmail{}},
		{SensitiveInfoPhoneNumber, jsreq.SensitiveInfoEntityPhoneNumber{}},
		{SensitiveInfoIPAddress, jsreq.SensitiveInfoEntityIpAddress{}},
		{SensitiveInfoCreditCardNumber, jsreq.SensitiveInfoEntityCreditCardNumber{}},
		{EntityType("MY_LABEL"), jsreq.SensitiveInfoEntityCustom{Value: "MY_LABEL"}},
	}
	for _, c := range cases {
		got := sensitiveInfoEntityWire(c.in)
		if got != c.want {
			t.Errorf("sensitiveInfoEntityWire(%q) = %#v, want %#v", c.in, got, c.want)
		}
		if back := identifiedEntityType(got); back != string(c.in) {
			t.Errorf("identifiedEntityType(%#v) = %q, want %q", got, back, c.in)
		}
	}
}
