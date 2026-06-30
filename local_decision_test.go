package arcjet

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/arcjet/arcjet-go/internal/local/jsreq"
)

func TestLocalEvaluatorAllowsNonMatchingWasmRules(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		ValidateEmail(EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}}),
		Filter(FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "bad.example"`}}),
	}, nil)
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
	}, nil)
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
	}, nil)
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
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())
	if evaluator.factory == nil {
		t.Fatal("expected the jsreq factory to be warmed when any local rule is configured")
	}
}

func TestLocalEvaluatorWarmsFactoryForFingerprintOnlyRules(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		// PromptInjection has no local kind, but the per-rule cache still
		// fingerprints it via WASM (see Client.ruleFingerprints), so the
		// factory must warm at construction to keep the cold compile off
		// the first Protect's hot path.
		DetectPromptInjection(PromptInjectionOptions{Mode: ModeLive}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())
	if evaluator.factory == nil {
		t.Fatal("expected the jsreq factory to warm for any configured rule")
	}
}

func TestLocalEvaluatorSkipsFactoryWhenNoRules(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())
	if evaluator.factory != nil {
		t.Fatal("expected factory to stay nil when no rules are configured")
	}
}

func TestLocalEvaluatorSupportsConcurrentWasmEvaluations(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
		ValidateEmail(EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}}),
		Filter(FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "example.com"`}}),
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	}, nil)
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
	}, nil)
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
	if len(reason.GetDenied()) == 0 || reason.GetDenied()[0].GetIdentifiedType() != string(SensitiveInfoEmail) {
		t.Fatalf("expected denied EMAIL entity, got %#v", reason.GetDenied())
	}
}

func TestLocalSensitiveInfoAllowsWhenNoMatch(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	}, nil)
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
	}, nil)
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
	}, nil)
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

func TestSensitiveInfoDetectCallbackClassifiesCustomTokens(t *testing.T) {
	// The user callback should fire for tokens the bundled analyzer
	// didn't classify. We pick a deliberately uncommon label ("API_KEY")
	// so the analyzer's built-in detectors stay out of the way.
	const customLabel EntityType = "API_KEY"
	const text = "service token sk_test_internal_key_12345 in the request body"

	detect := func(_ context.Context, tokens []string) []EntityType {
		out := make([]EntityType, len(tokens))
		for i, tok := range tokens {
			if strings.HasPrefix(tok, "sk_test_") {
				out[i] = customLabel
			}
		}
		return out
	}
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{customLabel}}),
	}, detect)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())

	decision, err := evaluator.detectSensitiveInfo(
		context.Background(),
		SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{customLabel}},
		ProtectDetails{},
		ProtectOptions{SensitiveInfoValue: text},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.liveDeny() {
		t.Fatalf("expected deny for custom-label match, got %#v", decision)
	}
	denied := decision.decision.GetReason().GetSensitiveInfo().GetDenied()
	if len(denied) == 0 || denied[0].GetIdentifiedType() != string(customLabel) {
		t.Fatalf("expected custom-label denied entity, got %#v", denied)
	}
}

func TestSensitiveInfoDetectCallbackAbsentSkipsCustomDetect(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())
	if evaluator.hasCustomDetect() {
		t.Fatal("expected no custom detect when callback unset")
	}
	cfg := sensitiveInfoConfig(nil, []EntityType{SensitiveInfoEmail}, evaluator.hasCustomDetect())
	if !cfg.SkipCustomDetect {
		t.Fatal("SkipCustomDetect should be true with no callback")
	}
}

func TestSensitiveInfoDetectCallbackPresentRunsCustomDetect(t *testing.T) {
	evaluator, err := newLocalEvaluator(context.Background(), []Rule{
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive, Deny: []EntityType{SensitiveInfoEmail}}),
	}, func(context.Context, []string) []EntityType { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close(context.Background())
	if !evaluator.hasCustomDetect() {
		t.Fatal("expected custom detect to be reported when callback set")
	}
	cfg := sensitiveInfoConfig(nil, nil, evaluator.hasCustomDetect())
	if cfg.SkipCustomDetect {
		t.Fatal("SkipCustomDetect should be false when callback is configured")
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
