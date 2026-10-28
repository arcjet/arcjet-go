package arcjet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

func TestSignedBotDirectoryConfiguration(t *testing.T) {
	const directory = "SIGNED_BOT:https://bot.example.com/.well-known/http-message-signatures-directory"
	for _, entity := range []string{
		"CHATGPT_AGENT",
		"BROWSERBASE",
		"MANUS_BOT",
		directory,
		// The SDK validates syntax. Arcjet Cloud decides whether a directory
		// may be fetched, so even these locations pass SDK validation.
		"SIGNED_BOT:https://localhost/.well-known/http-message-signatures-directory",
		"SIGNED_BOT:https://Bot.Example.com:8443/.well-known/http-message-signatures-directory",
	} {
		for _, opts := range []BotOptions{
			{Mode: ModeLive, Allow: []string{entity}},
			{Mode: ModeLive, Deny: []string{entity}},
		} {
			if _, err := buildRequestRule(DetectBot(opts)); err != nil {
				t.Errorf("%q: %v", entity, err)
			}
		}
	}
	for _, entity := range []string{
		"SIGNED_BOT",
		"SIGNED_BOT:http://bot.example.com/.well-known/http-message-signatures-directory",
		"SIGNED_BOT:https://bot.example.com/keys.json",
		"SIGNED_BOT:https://bot.example.com/.well-known/http-message-signatures-directory?x=1",
		"SIGNED_BOT:https://bot.example.com/.well-known/http-message-signatures-directory#fragment",
		"SIGNED_BOT:https://bot.example.com/.well-known/http-message-signatures-director%79",
	} {
		for _, opts := range []BotOptions{
			{Mode: ModeLive, Allow: []string{entity}},
			{Mode: ModeLive, Deny: []string{entity}},
		} {
			_, err := buildRequestRule(DetectBot(opts))
			if err == nil || !strings.Contains(err.Error(), "invalid signed bot directory") {
				t.Errorf("%q: expected signed directory error, got %v", entity, err)
			}
		}
	}
}

func TestSignedBotPolicies(t *testing.T) {
	for _, entity := range []string{
		"GOOGLE_AGENT", "CHATGPT_AGENT", "DUCKASSIST_BOT", "BROWSERBASE", "MANUS_BOT",
		"YOU_CRAWLER", "EXA_SEARCHBOT", "CONTEXT7_CRAWLER", "SHOPIFY_CLOUDSURF",
		"KERNEL_AGENT", "KERNEL_SEARCH", "OSANO_BOT", "CLOUDFLARE_BROWSER_RUN",
		"LANE_AGENT", "ISONSEARCH_CRAWLER", "ISONAI_USER", "LINER_BOT", "LINER_USER",
		BotCategoryAI, BotCategoryGoogle, BotCategorySearchEngine, BotCategoryTool,
		BotCategoryMonitor,
		"SIGNED_BOT:https://bot.example.com/.well-known/http-message-signatures-directory",
	} {
		if !mayBeSignedBot(entity) {
			t.Errorf("%q should be signer-relevant", entity)
		}
	}
	for _, entity := range []string{"CURL", "OPENAI_CRAWLER_USER", "SIGNED_BOT"} {
		if mayBeSignedBot(entity) {
			t.Errorf("%q should not be signer-relevant", entity)
		}
	}
	for _, opts := range []BotOptions{
		{Mode: ModeLive, Allow: []string{"CHATGPT_AGENT"}},
		{Mode: ModeLive, Deny: []string{BotCategoryTool}},
		{Mode: ModeLive, Allow: []string{"OSANO_BOT"}},
		{Mode: ModeLive, Deny: []string{BotCategoryMonitor}},
		{Mode: ModeLive, Allow: []string{"LINER_USER"}},
		{Mode: ModeLive, Deny: []string{"ISONSEARCH_CRAWLER"}},
		{Mode: ModeLive, Allow: []string{"ISONAI_USER", "LINER_BOT"}},
	} {
		rule, err := buildRequestRule(DetectBot(opts))
		if err != nil {
			t.Fatal(err)
		}
		if !botRulesMayVerifySignature([]*decidev1.Rule{rule}) {
			t.Errorf("rule %#v should be signer-relevant", opts)
		}
	}
}

func TestSignedBotAttemptReachesDecidePastLocalAndCachedBotDenial(t *testing.T) {
	handler := &testDecideHandler{
		reportCh: make(chan struct{}, 2),
		decision: &decidev1.Decision{Id: "req_signed", Conclusion: decidev1.Conclusion_CONCLUSION_ALLOW},
	}
	client := newProtectTestClient(t, handler, []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
		DetectBot(BotOptions{Mode: ModeLive, Allow: []string{"CHATGPT_AGENT"}}),
	})
	defer client.Close(context.Background())

	unsigned := ProtectDetails{
		IP:      "203.0.113.10",
		Method:  http.MethodGet,
		Path:    "/signed",
		Headers: map[string]string{"user-agent": "curl/8.7.1"},
	}
	decision, err := client.ProtectDetails(context.Background(), unsigned)
	if err != nil || !decision.IsDenied() {
		t.Fatalf("unsigned request should be denied locally: %#v, %v", decision, err)
	}
	if got := handler.snapshot().decideCalls; got != 0 {
		t.Fatalf("unsigned request made %d Decide calls", got)
	}
	fingerprint := client.ruleFingerprints(context.Background(), unsigned)[0]
	if client.cache.get(client.ruleIDs[0], fingerprint) == nil {
		t.Fatal("expected an unsigned local bot denial in the cache")
	}

	signed := unsigned
	signed.Headers = map[string]string{
		"user-agent":      "curl/8.7.1",
		"Signature-Input": `sig1=("@method" "@path");keyid="example"`,
	}
	signed.RawPath = "/signed"
	decision, err = client.ProtectDetails(context.Background(), signed)
	if err != nil || !decision.IsAllowed() {
		t.Fatalf("signed request should use Arcjet Cloud decision: %#v, %v", decision, err)
	}
	snap := handler.snapshot()
	if snap.decideCalls != 1 {
		t.Fatalf("signed request made %d Decide calls, want 1", snap.decideCalls)
	}
	if got := snap.seen.GetDetails().GetRawPath(); got != "/signed" {
		t.Errorf("Decide raw path = %q, want /signed", got)
	}
	if got := snap.seen.GetDetails().GetHeaders()["Signature-Input"]; got == "" {
		t.Error("Decide lost Signature-Input header")
	}
}

func TestUnrelatedSignedHeaderKeepsLocalBotDenial(t *testing.T) {
	handler := &testDecideHandler{reportCh: make(chan struct{}, 1)}
	client := newProtectTestClient(t, handler, []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
	})
	defer client.Close(context.Background())

	decision, err := client.ProtectDetails(context.Background(), ProtectDetails{
		RawPath: "/signed/%2F",
		Headers: map[string]string{
			"user-agent":      "curl/8.7.1",
			"signature-input": `sig1=()`,
		},
	})
	if err != nil || !decision.IsDenied() {
		t.Fatalf("unrelated policy should deny locally: %#v, %v", decision, err)
	}
	handler.waitReport(t)
	snap := handler.snapshot()
	if got := snap.decideCalls; got != 0 {
		t.Fatalf("unrelated signed request made %d Decide calls", got)
	}
	if got := snap.reportSeen.GetDetails().GetRawPath(); got != "" {
		t.Errorf("Report included raw path %q", got)
	}
}

func TestSignedBotDenialDoesNotPoisonUnsignedCache(t *testing.T) {
	botReason := &decidev1.Reason{Reason: &decidev1.Reason_BotV2{
		BotV2: &decidev1.BotV2Reason{Denied: []string{"CHATGPT_AGENT"}},
	}}
	handler := &testDecideHandler{decision: &decidev1.Decision{
		Id:         "req_signed_deny",
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Reason:     botReason,
		RuleResults: []*decidev1.RuleResult{{
			RuleId:     "rule_signed_bot",
			State:      decidev1.RuleState_RULE_STATE_RUN,
			Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
			Reason:     botReason,
			Ttl:        60,
		}},
	}}
	client := newProtectTestClient(t, handler, []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CHATGPT_AGENT"}}),
	})
	defer client.Close(context.Background())
	unsigned := ProtectDetails{
		IP:      "203.0.113.10",
		Path:    "/signed",
		Headers: map[string]string{"user-agent": "curl/8.7.1"},
	}
	signed := unsigned
	signed.Headers = map[string]string{"user-agent": "curl/8.7.1", "signature-input": "sig1=()"}
	fingerprints := client.ruleFingerprints(context.Background(), signed)
	if got := client.ruleFingerprints(context.Background(), unsigned)[0]; got != fingerprints[0] {
		t.Fatalf("signed and unsigned request fingerprints differ: %q, %q", fingerprints[0], got)
	}
	decision, err := client.ProtectDetails(context.Background(), signed)
	if err != nil || !decision.IsDenied() || handler.snapshot().decideCalls != 1 {
		t.Fatalf("signed bot denial should come from Decide: %#v, %v", decision, err)
	}
	if got := client.cache.get(client.ruleIDs[0], fingerprints[0]); got != nil {
		t.Fatal("signed bot denial populated the unsigned cache")
	}
	handler.mu.Lock()
	handler.decision = &decidev1.Decision{Id: "req_unsigned_allow", Conclusion: decidev1.Conclusion_CONCLUSION_ALLOW}
	handler.mu.Unlock()
	decision, err = client.ProtectDetails(context.Background(), unsigned)
	if err != nil || !decision.IsAllowed() || handler.snapshot().decideCalls != 2 {
		t.Fatalf("unsigned request should reach Decide: %#v, %v", decision, err)
	}
}

func TestSignedBotAttemptStillCachesOtherRuleResults(t *testing.T) {
	client, err := NewClient(Config{Key: "ajkey_test", Rules: []Rule{
		Shield(ShieldOptions{Mode: ModeLive}),
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CHATGPT_AGENT"}}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())
	fingerprints := []string{"same-fingerprint", "same-fingerprint"}
	denied := &decidev1.RuleResult{
		State:      decidev1.RuleState_RULE_STATE_RUN,
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Ttl:        60,
	}
	client.cacheDecideResults(&decidev1.Decision{
		RuleResults: []*decidev1.RuleResult{denied, denied},
	}, fingerprints, true)
	if got := client.cache.get(client.ruleIDs[0], fingerprints[0]); got == nil {
		t.Fatal("signed request did not cache unrelated Shield result")
	}
	if got := client.cache.get(client.ruleIDs[1], fingerprints[1]); got != nil {
		t.Fatal("signed request cached bot result")
	}
}

func TestWithRuleAddsSignedBotPolicy(t *testing.T) {
	handler := &testDecideHandler{
		decision: &decidev1.Decision{Id: "req_signed", Conclusion: decidev1.Conclusion_CONCLUSION_ALLOW},
	}
	base := newProtectTestClient(t, handler, []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
	})
	defer base.Close(context.Background())
	withSigner, err := base.WithRule(DetectBot(BotOptions{Mode: ModeLive, Allow: []string{"CHATGPT_AGENT"}}))
	if err != nil {
		t.Fatal(err)
	}
	if base.hasSignedBotRule || !withSigner.hasSignedBotRule {
		t.Fatal("WithRule did not update signed-bot policy metadata")
	}
	decision, err := withSigner.ProtectDetails(context.Background(), ProtectDetails{
		Headers: map[string]string{"user-agent": "curl/8.7.1", "signature-input": "sig1=()"},
	})
	if err != nil || !decision.IsAllowed() || handler.snapshot().decideCalls != 1 {
		t.Fatalf("WithRule signed request should reach Decide: %#v, %v", decision, err)
	}
}

func TestProtectForwardsOriginalOriginFormPath(t *testing.T) {
	handler := &testDecideHandler{
		decision: &decidev1.Decision{Id: "req_signed", Conclusion: decidev1.Conclusion_CONCLUSION_ALLOW},
	}
	client := newProtectTestClient(t, handler, []Rule{
		DetectBot(BotOptions{Mode: ModeLive, Allow: []string{"CHATGPT_AGENT"}}),
	})
	defer client.Close(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/a/%2E%2e/../b?x=1", http.NoBody)
	req.Header.Set("Signature-Input", "sig1=()")
	if _, err := client.Protect(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	details := handler.snapshot().seen.GetDetails()
	if details.GetPath() != req.URL.Path || details.GetRawPath() != "/a/%2E%2e/../b" {
		t.Fatalf("Decide path = %q, raw path = %q", details.GetPath(), details.GetRawPath())
	}
}
