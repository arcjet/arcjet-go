package arcjet

import (
	"errors"
	"testing"
	"time"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

func TestRequestRuleBuilders(t *testing.T) {
	trueValue := true
	// SensitiveInfo is intentionally a noop (no analyzer yet) and is
	// covered separately by TestSensitiveInfoRuleProducesNoWirePayload.
	rules := []Rule{
		FixedWindow(FixedWindowOptions{Mode: ModeLive, Window: time.Minute, MaxRequests: 10}),
		SlidingWindow(SlidingWindowOptions{Mode: ModeLive, Interval: time.Minute, MaxRequests: 10}),
		DetectBot(BotOptions{Mode: ModeDryRun, Deny: []string{"CURL"}}),
		ValidateEmail(EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeDisposable}, RequireTopLevelDomain: &trueValue}),
		DetectPromptInjection(PromptInjectionOptions{Mode: ModeLive}),
		Filter(FilterOptions{Mode: ModeLive, Deny: []string{`ip.src.country == "KP"`}}),
	}
	client, err := NewClient(Config{Key: "ajkey_test", Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	protoRules := client.builtRules
	if len(protoRules) != len(rules) {
		t.Fatalf("rule count = %d", len(protoRules))
	}
	// NewClient sorts by JS priority, so look up each family rather than
	// asserting declaration order.
	var (
		fixed, sliding *decidev1.RateLimitRule
		bot            *decidev1.BotV2Rule
		email          *decidev1.EmailRule
		prompt         *decidev1.PromptInjectionRule
		filter         *decidev1.FilterRule
	)
	for _, r := range protoRules {
		switch {
		case r.GetRateLimit() != nil && r.GetRateLimit().GetWindowInSeconds() > 0:
			fixed = r.GetRateLimit()
		case r.GetRateLimit() != nil && r.GetRateLimit().GetInterval() > 0:
			sliding = r.GetRateLimit()
		case r.GetBotV2() != nil:
			bot = r.GetBotV2()
		case r.GetEmail() != nil:
			email = r.GetEmail()
		case r.GetPromptInjectionDetection() != nil:
			prompt = r.GetPromptInjectionDetection()
		case r.GetFilter() != nil:
			filter = r.GetFilter()
		}
	}
	if fixed == nil || fixed.GetWindowInSeconds() != 60 {
		t.Fatalf("fixed window = %#v", fixed)
	}
	if sliding == nil || sliding.GetInterval() != 60 {
		t.Fatalf("sliding interval = %#v", sliding)
	}
	if bot == nil || bot.GetDeny()[0] != "CURL" {
		t.Fatalf("bot deny = %#v", bot)
	}
	if email == nil || email.GetDeny()[0].String() != "EMAIL_TYPE_DISPOSABLE" {
		t.Fatalf("email deny = %#v", email)
	}
	if prompt == nil {
		t.Fatal("missing prompt injection rule")
	}
	if filter == nil || filter.GetDeny()[0] == "" {
		t.Fatal("missing filter deny")
	}
}

func TestSortRulesByPriorityIsStable(t *testing.T) {
	first := TokenBucket(TokenBucketOptions{Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 1})
	second := FixedWindow(FixedWindowOptions{Mode: ModeLive, Window: time.Minute, MaxRequests: 1})
	sorted := sortRulesByPriority([]Rule{
		DetectBot(BotOptions{Mode: ModeLive}),
		first,
		SensitiveInfo(SensitiveInfoOptions{Mode: ModeLive}),
		second,
	})
	if sorted[0].evalPriority() != evalPrioritySensitiveInfo {
		t.Errorf("first = %d, want sensitive-info", sorted[0].evalPriority())
	}
	if sorted[1].ruleID() != first.ruleID() || sorted[2].ruleID() != second.ruleID() {
		t.Error("same-priority rate limits should keep declaration order")
	}
	if sorted[3].evalPriority() != evalPriorityBot {
		t.Errorf("last = %d, want bot", sorted[3].evalPriority())
	}
}

func TestContextWindowSizeDefault(t *testing.T) {
	if got := contextWindowSize(0); got != 1 {
		t.Errorf("zero = %d", got)
	}
	if got := contextWindowSize(-3); got != 1 {
		t.Errorf("negative = %d", got)
	}
	if got := contextWindowSize(4); got != 4 {
		t.Errorf("positive = %d", got)
	}
}

func TestProtectSignupComposesRules(t *testing.T) {
	rules := ProtectSignup(ProtectSignupOptions{
		RateLimit: SlidingWindowOptions{Mode: ModeLive, Interval: time.Minute, MaxRequests: 5},
		Bots:      BotOptions{Mode: ModeLive, Deny: []string{"CURL"}},
		Email:     EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeDisposable}},
	})
	if len(rules) != 3 {
		t.Fatalf("ProtectSignup returned %d rules, want 3", len(rules))
	}
	client, err := NewClient(Config{Key: "ajkey_test", Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	built := client.builtRules
	if built[0].GetRateLimit().GetInterval() != 60 {
		t.Fatalf("sliding window not first: %#v", built[0])
	}
	if built[1].GetBotV2().GetDeny()[0] != "CURL" {
		t.Fatalf("bot rule not second: %#v", built[1])
	}
	if built[2].GetEmail().GetDeny()[0].String() != "EMAIL_TYPE_DISPOSABLE" {
		t.Fatalf("email rule not third: %#v", built[2])
	}
}

func TestRequestRuleBuilderRejectsConflicts(t *testing.T) {
	rules := []Rule{
		DetectBot(BotOptions{Allow: []string{"A"}, Deny: []string{"B"}}),
		ValidateEmail(EmailOptions{Allow: []EmailType{EmailTypeFree}, Deny: []EmailType{EmailTypeInvalid}}),
		SensitiveInfo(SensitiveInfoOptions{Allow: []EntityType{SensitiveInfoEmail}, Deny: []EntityType{SensitiveInfoIPAddress}}),
		Filter(FilterOptions{Allow: []string{"true"}, Deny: []string{"false"}}),
	}
	for _, rule := range rules {
		if _, err := rule.requestRule(); err == nil {
			t.Fatalf("expected conflict error for %#v", rule)
		}
	}
}

func TestDecisionAndErrorHelpers(t *testing.T) {
	if !(Decision{Conclusion: ConclusionAllow}).IsAllowed() {
		t.Fatal("allow helper failed")
	}
	if !(Decision{Conclusion: ConclusionError}).IsAllowed() {
		t.Fatal("error conclusion should fail open (IsAllowed)")
	}
	if !(Decision{Conclusion: ConclusionChallenge}).IsChallenged() {
		t.Fatal("challenge helper failed")
	}
	if !(Decision{Conclusion: ConclusionError}).IsErrored() {
		t.Fatal("error helper failed")
	}
	if !(Decision{Reason: Reason{Type: ReasonError}}).IsErrored() {
		t.Fatal("reason error helper failed")
	}
	if !(Decision{Reason: Reason{Bot: &BotReason{Spoofed: true}}}).IsSpoofedBot() {
		t.Fatal("spoofed bot helper (top-level reason) failed")
	}
	if !(Decision{Results: []RuleResult{{State: RuleStateRun, Reason: Reason{Bot: &BotReason{Spoofed: true}}}}}).IsSpoofedBot() {
		t.Fatal("spoofed bot helper (rule result) failed")
	}
	if (Decision{Results: []RuleResult{{State: RuleStateDryRun, Reason: Reason{Bot: &BotReason{Spoofed: true}}}}}).IsSpoofedBot() {
		t.Fatal("spoofed bot helper should ignore dry-run results")
	}
	if !(Decision{Reason: Reason{Bot: &BotReason{Verified: true}}}).IsVerifiedBot() {
		t.Fatal("verified bot helper (top-level reason) failed")
	}
	if !(Decision{Results: []RuleResult{{State: RuleStateRun, Reason: Reason{Bot: &BotReason{Verified: true}}}}}).IsVerifiedBot() {
		t.Fatal("verified bot helper (rule result) failed")
	}
	if (Decision{Results: []RuleResult{{State: RuleStateDryRun, Reason: Reason{Bot: &BotReason{Verified: true}}}}}).IsVerifiedBot() {
		t.Fatal("verified bot helper should ignore dry-run results")
	}
	// A dry-run rule still populates the top-level reason (see localDeny), so the
	// helpers must not leak a dry-run-only detection through it.
	dryRunLeak := Decision{
		Reason:  Reason{Bot: &BotReason{Spoofed: true, Verified: true}},
		Results: []RuleResult{{State: RuleStateDryRun, Reason: Reason{Bot: &BotReason{Spoofed: true, Verified: true}}}},
	}
	if dryRunLeak.IsSpoofedBot() {
		t.Fatal("spoofed bot helper leaked a dry-run detection via the top-level reason")
	}
	if dryRunLeak.IsVerifiedBot() {
		t.Fatal("verified bot helper leaked a dry-run detection via the top-level reason")
	}
	if !(Decision{Reason: Reason{Type: ReasonError, Message: "bot detection requires user-agent header"}}).IsMissingUserAgent() {
		t.Fatal("missing user agent helper (local message) failed")
	}
	if !(Decision{Results: []RuleResult{{State: RuleStateRun, Reason: Reason{Type: ReasonError, Message: "the request was missing User-Agent header"}}}}).IsMissingUserAgent() {
		t.Fatal("missing user agent helper (server message) failed")
	}
	if (Decision{Reason: Reason{Type: ReasonError, Message: "some other error"}}).IsMissingUserAgent() {
		t.Fatal("missing user agent helper should not match unrelated errors")
	}
	if (ArcjetError{Code: "AJ1", Message: "bad"}).Error() != "AJ1: bad" {
		t.Fatal("unexpected error formatting")
	}
	ip := IPDetails{IsVPN: true, IsProxy: true, IsTor: true}
	if !ip.IsVPN || !ip.IsProxy || !ip.IsTor {
		t.Fatal("ip fields failed")
	}
}

func TestReasonTypeHelpers(t *testing.T) {
	cases := []struct {
		name  string
		r     Reason
		check func(Reason) bool
	}{
		{"rate-limit", Reason{Type: ReasonRateLimit}, Reason.IsRateLimit},
		{"bot", Reason{Type: ReasonBot}, Reason.IsBot},
		{"shield", Reason{Type: ReasonShield}, Reason.IsShield},
		{"email", Reason{Type: ReasonEmail}, Reason.IsEmail},
		{"sensitive-info", Reason{Type: ReasonSensitiveInfo}, Reason.IsSensitiveInfo},
		{"prompt-injection", Reason{Type: ReasonPromptInjection}, Reason.IsPromptInjection},
		{"filter", Reason{Type: ReasonFilter}, Reason.IsFilter},
		{"error", Reason{Type: ReasonError}, Reason.IsError},
	}
	for _, tc := range cases {
		if !tc.check(tc.r) {
			t.Errorf("expected %s helper to return true", tc.name)
		}
	}
	empty := Reason{}
	if empty.IsRateLimit() || empty.IsBot() || empty.IsShield() || empty.IsEmail() ||
		empty.IsSensitiveInfo() || empty.IsPromptInjection() || empty.IsFilter() || empty.IsError() {
		t.Error("empty reason should not match any type")
	}
}

func TestArcjetErrorFormatting(t *testing.T) {
	if got := (ArcjetError{Code: "AJ1", Message: "bad"}).Error(); got != "AJ1: bad" {
		t.Errorf("both fields = %q", got)
	}
	if got := (ArcjetError{Message: "bad"}).Error(); got != "bad" {
		t.Errorf("message-only = %q", got)
	}
	if got := (ArcjetError{Code: "AJ1"}).Error(); got != "AJ1" {
		t.Errorf("code-only = %q", got)
	}
	if got := (ArcjetError{}).Error(); got != "" {
		t.Errorf("empty = %q", got)
	}
}

func TestNormalizeAndValidateMode(t *testing.T) {
	if normalizeMode("") != ModeDryRun {
		t.Error("empty mode should normalize to dry-run")
	}
	if err := validateMode(Mode("LIVE")); err != nil {
		t.Errorf("LIVE should validate, got %v", err)
	}
	if err := validateMode(Mode("BAD")); err == nil {
		t.Error("unknown mode should fail")
	}
	if got := requestMode(ModeLive); got != "MODE_LIVE" {
		t.Errorf("requestMode(LIVE) = %q", got)
	}
	if got := requestMode(""); got != "MODE_DRY_RUN" {
		t.Errorf("requestMode(default) = %q", got)
	}
	if got := guardMode(ModeLive); got != "GUARD_RULE_MODE_LIVE" {
		t.Errorf("guardMode(LIVE) = %q", got)
	}
	if got := guardMode(""); got != "GUARD_RULE_MODE_DRY_RUN" {
		t.Errorf("guardMode(default) = %q", got)
	}
	if err := validateGuardMode(""); err == nil || !errors.Is(err, ErrInvalidMode) {
		t.Errorf("validateGuardMode(\"\") = %v, want ErrInvalidMode", err)
	}
	if err := validateGuardMode(ModeLive); err != nil {
		t.Errorf("validateGuardMode(LIVE) = %v", err)
	}
	if err := validateGuardMode(ModeDryRun); err != nil {
		t.Errorf("validateGuardMode(DRY_RUN) = %v", err)
	}
}

func TestSecondsRoundingBoundaries(t *testing.T) {
	if got := seconds(0); got != 1 {
		t.Errorf("zero = %d", got)
	}
	if got := seconds(time.Millisecond); got != 1 {
		t.Errorf("sub-second = %d", got)
	}
	if got := seconds(time.Second); got != 1 {
		t.Errorf("one second = %d", got)
	}
	if got := seconds(time.Minute + 400*time.Millisecond); got != 60 {
		t.Errorf("rounded down = %d", got)
	}
	if got := seconds(time.Minute + 600*time.Millisecond); got != 61 {
		t.Errorf("rounded up = %d", got)
	}
}

func TestCleanMapDropsNilsEmptiesAndUnwrapsBoolPtr(t *testing.T) {
	trueVal := true
	out := cleanMap(map[string]any{
		"keep":      "x",
		"nilValue":  nil,
		"emptyList": []string{},
		"list":      []string{"a"},
		"ptrNil":    (*bool)(nil),
		"ptrTrue":   &trueVal,
	})
	if _, ok := out["nilValue"]; ok {
		t.Error("nil value not dropped")
	}
	if _, ok := out["emptyList"]; ok {
		t.Error("empty []string not dropped")
	}
	if _, ok := out["ptrNil"]; ok {
		t.Error("nil *bool not dropped")
	}
	if v, ok := out["ptrTrue"].(bool); !ok || !v {
		t.Errorf("*bool not unwrapped: got %v ok=%v", v, ok)
	}
	if out["keep"] != "x" || out["list"] == nil {
		t.Errorf("expected entries kept, got %#v", out)
	}
}

func TestEmailEnumsHandlesEmpty(t *testing.T) {
	if emailEnums(nil) != nil {
		t.Error("nil input should return nil")
	}
	if got := emailEnums([]EmailType{EmailTypeInvalid, EmailTypeDisposable}); len(got) != 2 ||
		got[0] != "EMAIL_TYPE_INVALID" || got[1] != "EMAIL_TYPE_DISPOSABLE" {
		t.Errorf("got = %#v", got)
	}
}

func TestSentinelErrorsAreWrappedAtValidationSites(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "rate-limit-token-bucket",
			err:  buildErr(TokenBucket(TokenBucketOptions{Mode: ModeLive})),
			want: ErrInvalidRateLimit,
		},
		{
			name: "rate-limit-fixed-window",
			err:  buildErr(FixedWindow(FixedWindowOptions{Mode: ModeLive})),
			want: ErrInvalidRateLimit,
		},
		{
			name: "rate-limit-sliding-window",
			err:  buildErr(SlidingWindow(SlidingWindowOptions{Mode: ModeLive})),
			want: ErrInvalidRateLimit,
		},
		{
			name: "invalid-mode",
			err:  buildErr(Shield(ShieldOptions{Mode: Mode("BAD")})),
			want: ErrInvalidMode,
		},
		{
			name: "bot-conflict",
			err:  buildErr(DetectBot(BotOptions{Allow: []string{"A"}, Deny: []string{"B"}})),
			want: ErrAllowDenyConflict,
		},
		{
			name: "email-conflict",
			err:  buildErr(ValidateEmail(EmailOptions{Allow: []EmailType{EmailTypeFree}, Deny: []EmailType{EmailTypeInvalid}})),
			want: ErrAllowDenyConflict,
		},
		{
			name: "sensitive-info-conflict",
			err:  buildErr(SensitiveInfo(SensitiveInfoOptions{Allow: []EntityType{SensitiveInfoEmail}, Deny: []EntityType{SensitiveInfoIPAddress}})),
			want: ErrAllowDenyConflict,
		},
		{
			name: "filter-conflict",
			err:  buildErr(Filter(FilterOptions{Allow: []string{"true"}, Deny: []string{"false"}})),
			want: ErrAllowDenyConflict,
		},
	}
	for _, tc := range cases {
		if tc.err == nil {
			t.Errorf("%s: expected an error", tc.name)
			continue
		}
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s: errors.Is(_, %v) = false; err=%v", tc.name, tc.want, tc.err)
		}
	}
}

func buildErr(rule Rule) error {
	_, err := rule.requestRule()
	return err
}

func TestDecisionErrReturnsAtErroredDecision(t *testing.T) {
	if (Decision{}).Err() != nil {
		t.Error("zero decision should not error")
	}
	err := (Decision{Conclusion: ConclusionError, Reason: Reason{Message: "boom"}}).Err()
	if err == nil || err.Error() != "boom" {
		t.Errorf("error decision = %v", err)
	}
	err = (Decision{Reason: Reason{Type: ReasonError}}).Err()
	if err == nil {
		t.Error("reason-error decision should produce an error")
	}
}

func TestArcjetErrorIsByCode(t *testing.T) {
	err := ArcjetError{Code: "AJ1100", Message: "boom"}
	if !errors.Is(err, ArcjetError{Code: "AJ1100"}) {
		t.Error("errors.Is should match by code")
	}
	if errors.Is(err, ArcjetError{Code: "AJ_OTHER"}) {
		t.Error("errors.Is should not match a different code")
	}
	if errors.Is(err, errors.New("not an arcjet error")) {
		t.Error("errors.Is should not match non-ArcjetError")
	}
	// An empty-Code target must not act as a wildcard for any ArcjetError.
	if errors.Is(err, ArcjetError{}) {
		t.Error("errors.Is should not match a code-less target")
	}
	// Decision.Err returns a code-less ArcjetError; matching it against a bare
	// ArcjetError{} must be false, not a spurious wildcard hit.
	decErr := (Decision{Conclusion: ConclusionError, Reason: Reason{Message: "boom"}}).Err()
	if errors.Is(decErr, ArcjetError{}) {
		t.Error("errors.Is(Decision.Err(), ArcjetError{}) should be false")
	}
}
