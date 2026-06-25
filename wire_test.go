package arcjet

import (
	"encoding/json"
	"testing"
)

func TestParseReasonVariants(t *testing.T) {
	cases := []struct {
		raw  string
		want ReasonType
	}{
		{`{"botV2":{"allowed":["CATEGORY:SEARCH_ENGINE"],"verified":true}}`, ReasonBot},
		{`{"bot":{"verified":false}}`, ReasonBot},
		{`{"shield":{"shieldTriggered":true}}`, ReasonShield},
		{`{"email":{"types":["EMAIL_TYPE_INVALID"]}}`, ReasonEmail},
		{`{"sensitiveInfo":{"denied":[{"identifiedType":"EMAIL"}]}}`, ReasonSensitiveInfo},
		{`{"promptInjection":{"injectionDetected":true}}`, ReasonPromptInjection},
		{`{"filter":{"matchedExpressions":["true"]}}`, ReasonFilter},
		{`{"error":{"message":"bad"}}`, ReasonError},
	}
	for _, tc := range cases {
		got := parseReason(json.RawMessage(tc.raw))
		if got.Type != tc.want {
			t.Fatalf("parseReason(%s) = %q, want %q", tc.raw, got.Type, tc.want)
		}
	}
}

func TestGuardRuleResultVariants(t *testing.T) {
	cases := []guardRuleResultWire{
		{Type: "GUARD_RULE_TYPE_FIXED_WINDOW", FixedWindow: &GuardFixedWindowResult{Conclusion: "GUARD_CONCLUSION_DENY"}},
		{Type: "GUARD_RULE_TYPE_SLIDING_WINDOW", SlidingWindow: &GuardSlidingWindowResult{Conclusion: "GUARD_CONCLUSION_ALLOW"}},
		{Type: "GUARD_RULE_TYPE_PROMPT_INJECTION", PromptInjection: &GuardPromptResult{Conclusion: "GUARD_CONCLUSION_DENY"}},
		{Type: "GUARD_RULE_TYPE_MODERATE_CONTENT", ModerateContent: &GuardModerateContentResult{Conclusion: "GUARD_CONCLUSION_DENY"}},
		{Type: "GUARD_RULE_TYPE_LOCAL_CUSTOM", LocalCustom: &GuardLocalCustomResult{Conclusion: "GUARD_CONCLUSION_ALLOW"}},
		{Type: "GUARD_RULE_TYPE_TOKEN_BUCKET", Error: &ArcjetError{Message: "bad"}},
		{Type: "GUARD_RULE_TYPE_TOKEN_BUCKET", NotRun: map[string]any{}},
	}
	for _, tc := range cases {
		got := tc.toGuardRuleResult()
		if got.Type == "" {
			t.Fatalf("missing type for %#v", tc)
		}
		if got.Error != nil && !got.IsErrored() {
			t.Fatal("expected errored helper")
		}
	}
	if parseGuardReason("GUARD_REASON_RATE_LIMIT") != ReasonRateLimit ||
		parseGuardReason("GUARD_REASON_PROMPT_INJECTION") != ReasonPromptInjection ||
		parseGuardReason("GUARD_REASON_MODERATE_CONTENT") != ReasonModerateContent ||
		parseGuardReason("GUARD_REASON_CUSTOM") != ReasonCustom {
		t.Fatal("guard reason parsing failed")
	}

	// Content moderation results map to the moderate-content reason.
	mc := guardRuleResultWire{
		Type:            "GUARD_RULE_TYPE_MODERATE_CONTENT",
		ModerateContent: &GuardModerateContentResult{Conclusion: "GUARD_CONCLUSION_DENY"},
	}.toGuardRuleResult()
	if mc.Reason != ReasonModerateContent || mc.ModerateContent == nil {
		t.Fatalf("moderate content result mapped incorrectly: %#v", mc)
	}
}

func TestParseConclusionAllVariants(t *testing.T) {
	cases := []struct {
		in   string
		want Conclusion
	}{
		{"CONCLUSION_ALLOW", ConclusionAllow},
		{"ALLOW", ConclusionAllow},
		{"CONCLUSION_DENY", ConclusionDeny},
		{"DENY", ConclusionDeny},
		{"CONCLUSION_CHALLENGE", ConclusionChallenge},
		{"CHALLENGE", ConclusionChallenge},
		{"CONCLUSION_ERROR", ConclusionError},
		{"ERROR", ConclusionError},
		{"WHATEVER", Conclusion("WHATEVER")},
		{"", Conclusion("")},
	}
	for _, tc := range cases {
		if got := parseConclusion(tc.in); got != tc.want {
			t.Errorf("parseConclusion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseReasonEdges(t *testing.T) {
	if got := parseReason(nil); got.Type != "" {
		t.Errorf("nil raw = %#v", got)
	}
	if got := parseReason(json.RawMessage("null")); got.Type != "" {
		t.Errorf("null raw = %#v", got)
	}
	if got := parseReason(json.RawMessage("not json")); got.Type != ReasonError {
		t.Errorf("invalid raw should be error, got %#v", got)
	}
	if got := parseReason(json.RawMessage(`{}`)); got.Type != "" {
		t.Errorf("empty envelope should be unknown, got %#v", got)
	}
	got := parseReason(json.RawMessage(`{"rateLimit":{"max":5,"remaining":2,"resetInSeconds":10,"windowInSeconds":60}}`))
	if got.Type != ReasonRateLimit || got.RateLimit == nil || got.RateLimit.Max != 5 {
		t.Fatalf("rate limit reason = %#v", got)
	}
}

func TestParseReasonMalformedInnerEnvelopeSurfacesError(t *testing.T) {
	// Outer envelope parses, but the inner reason body is broken JSON.
	// Previously this was silently swallowed; now it should surface as ReasonError.
	cases := []struct {
		name string
		raw  string
		tag  string
	}{
		{"rateLimit", `{"rateLimit":"not-an-object"}`, "rateLimit"},
		{"botV2", `{"botV2":42}`, "botV2"},
		{"shield", `{"shield":[]}`, "shield"},
		{"filter", `{"filter":"oops"}`, "filter"},
	}
	for _, tc := range cases {
		got := parseReason(json.RawMessage(tc.raw))
		if got.Type != ReasonError {
			t.Errorf("%s: expected ReasonError, got %q (%#v)", tc.name, got.Type, got)
			continue
		}
		if got.Message == "" || !contains(got.Message, tc.tag) {
			t.Errorf("%s: expected error message tagged with %q, got %q", tc.name, tc.tag, got.Message)
		}
	}
}

func TestDecisionFromProtoNilFailsToError(t *testing.T) {
	d := decisionFromProto(nil)
	if !d.IsErrored() {
		t.Error("nil proto should produce an error decision")
	}
}

func TestParseGuardRuleType(t *testing.T) {
	cases := map[string]GuardRuleType{
		"GUARD_RULE_TYPE_TOKEN_BUCKET":         GuardRuleTypeTokenBucket,
		"GUARD_RULE_TYPE_FIXED_WINDOW":         GuardRuleTypeFixedWindow,
		"GUARD_RULE_TYPE_SLIDING_WINDOW":       GuardRuleTypeSlidingWindow,
		"GUARD_RULE_TYPE_PROMPT_INJECTION":     GuardRuleTypePromptInjection,
		"GUARD_RULE_TYPE_MODERATE_CONTENT":     GuardRuleTypeModerateContent,
		"GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO": GuardRuleTypeLocalSensitiveInfo,
		"GUARD_RULE_TYPE_LOCAL_CUSTOM":         GuardRuleTypeLocalCustom,
		"UNRECOGNISED":                         GuardRuleType("UNRECOGNISED"),
	}
	for in, want := range cases {
		if got := parseGuardRuleType(in); got != want {
			t.Errorf("parseGuardRuleType(%q) = %q want %q", in, got, want)
		}
	}
}

func TestParseGuardReasonEdges(t *testing.T) {
	for _, in := range []string{"", "WHATEVER", "GUARD_REASON_UNSPECIFIED"} {
		if got := parseGuardReason(in); got != ReasonUnknown {
			t.Errorf("parseGuardReason(%q) = %q want %q", in, got, ReasonUnknown)
		}
	}
	if got := parseGuardReason("GUARD_REASON_SENSITIVE_INFO"); got != ReasonSensitiveInfo {
		t.Errorf("sensitive-info = %q", got)
	}
	if got := parseGuardReason("GUARD_REASON_ERROR"); got != ReasonError {
		t.Errorf("error = %q", got)
	}
	if got := parseGuardReason("GUARD_REASON_NOT_RUN"); got != ReasonNotRun {
		t.Errorf("not-run = %q", got)
	}
}

func TestGuardDecisionFromProtoNilFailsOpen(t *testing.T) {
	d := guardDecisionFromProto(nil)
	if !d.IsAllowed() {
		t.Error("nil response should fail open (allow)")
	}
	if !d.HasFailedOpen() {
		t.Error("nil response should be marked failed-open")
	}
	if len(d.ErrorResults()) != 1 {
		t.Error("nil response should surface one errored result")
	}
}

func TestGuardDecisionErroredFromRuleResult(t *testing.T) {
	d := GuardDecision{Results: []GuardRuleResult{{Error: &ArcjetError{Message: "boom"}}}}
	if len(d.ErrorResults()) != 1 {
		t.Error("rule-level error not surfaced on decision")
	}
	if !(GuardRuleResult{Error: &ArcjetError{Message: "x"}}).IsErrored() {
		t.Error("rule errored helper failed")
	}
	if !(GuardRuleResult{Conclusion: ConclusionDeny}).IsDenied() {
		t.Error("rule denied helper failed")
	}
	if (GuardDecision{}).HasFailedOpen() {
		t.Error("empty decision should not be failed-open")
	}
}

func TestGuardDecisionWarningsSurfaceFromResponseErrors(t *testing.T) {
	resp := guardResponseWire{
		Decision: guardDecisionWire{
			ID:          "gdec_test",
			Conclusion:  "GUARD_CONCLUSION_ALLOW",
			Reason:      "GUARD_REASON_UNSPECIFIED",
			RuleResults: nil,
		},
		Warnings: []Warning{
			{Code: "AJ1001", Message: "invalid metadata key"},
			{Code: "AJ1002", Message: "invalid label"},
		},
	}
	d := resp.toGuardDecision()
	if len(d.Warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(d.Warnings))
	}
	if d.Warnings[0].Code != "AJ1001" || d.Warnings[0].Message != "invalid metadata key" {
		t.Errorf("unexpected first warning: %+v", d.Warnings[0])
	}
	// A warning alone never makes a decision fail open.
	if d.HasFailedOpen() {
		t.Error("warnings should not make a decision fail open")
	}
	if len(d.ErrorResults()) != 0 {
		t.Error("warnings should not produce errored results")
	}
}

func TestGuardDecisionAllowWithErrorIsFailedOpen(t *testing.T) {
	resp := guardResponseWire{
		Decision: guardDecisionWire{
			ID:         "gdec_test",
			Conclusion: "GUARD_CONCLUSION_ALLOW",
			Reason:     "GUARD_REASON_UNSPECIFIED",
			RuleResults: []guardRuleResultWire{{
				ConfigID: "cfg_1",
				InputID:  "in_1",
				Type:     "GUARD_RULE_TYPE_TOKEN_BUCKET",
				Error:    &ArcjetError{Message: "boom", Code: "INTERNAL"},
			}},
		},
	}
	d := resp.toGuardDecision()
	if d.Conclusion != ConclusionAllow {
		t.Errorf("expected ALLOW, got %s", d.Conclusion)
	}
	if !d.HasFailedOpen() {
		t.Error("ALLOW with an errored rule should be failed-open")
	}
	errs := d.ErrorResults()
	if len(errs) != 1 || errs[0].Error.Code != "INTERNAL" {
		t.Errorf("expected one INTERNAL errored result, got %+v", errs)
	}
}

func TestGuardDecisionDenyWithErrorIsNotFailedOpen(t *testing.T) {
	// A DENY conclusion was reached despite an errored rule — the decision did
	// not fail open (it denied on purpose), but the errored rule is still
	// surfaced via ErrorResults().
	resp := guardResponseWire{
		Decision: guardDecisionWire{
			ID:         "gdec_test",
			Conclusion: "GUARD_CONCLUSION_DENY",
			Reason:     "GUARD_REASON_RATE_LIMIT",
			RuleResults: []guardRuleResultWire{{
				ConfigID: "cfg_1",
				InputID:  "in_1",
				Type:     "GUARD_RULE_TYPE_TOKEN_BUCKET",
				Error:    &ArcjetError{Message: "boom", Code: "INTERNAL"},
			}},
		},
	}
	d := resp.toGuardDecision()
	if d.Conclusion != ConclusionDeny {
		t.Errorf("expected DENY, got %s", d.Conclusion)
	}
	if d.HasFailedOpen() {
		t.Error("a DENY decision should not be failed-open")
	}
	if len(d.ErrorResults()) != 1 {
		t.Error("the errored rule should still surface via ErrorResults()")
	}
}

func TestGuardDecisionWarningAndErrorAreDistinctAxes(t *testing.T) {
	// A warning (processed correctly, fix it) and an error (could not
	// process) are independent: a warning does not make the decision fail
	// open, but an errored rule does.
	resp := guardResponseWire{
		Decision: guardDecisionWire{
			ID:         "gdec_test",
			Conclusion: "GUARD_CONCLUSION_ALLOW",
			Reason:     "GUARD_REASON_UNSPECIFIED",
			RuleResults: []guardRuleResultWire{{
				ConfigID: "cfg_1",
				InputID:  "in_1",
				Type:     "GUARD_RULE_TYPE_TOKEN_BUCKET",
				Error:    &ArcjetError{Message: "boom", Code: "INTERNAL"},
			}},
		},
		Warnings: []Warning{{Code: "AJ1002", Message: "stripped key"}},
	}
	d := resp.toGuardDecision()
	if len(d.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(d.Warnings))
	}
	if len(d.ErrorResults()) != 1 {
		t.Errorf("expected 1 errored result, got %d", len(d.ErrorResults()))
	}
	// Failed open is driven by the error, not the warning.
	if !d.HasFailedOpen() {
		t.Error("ALLOW with an errored rule should be failed-open")
	}
}

func TestWarningsFromWirePreservesServerValues(t *testing.T) {
	// warningsFromWire copies exactly what the server sent — including empty
	// fields — rather than coercing, matching the JS and Python SDKs.
	got := warningsFromWire([]Warning{
		{Code: "AJ1001", Message: "invalid metadata key"},
		{Code: "", Message: "only a message"},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(got))
	}
	if got[0] != (Warning{Code: "AJ1001", Message: "invalid metadata key"}) {
		t.Errorf("first warning altered: %+v", got[0])
	}
	if got[1] != (Warning{Code: "", Message: "only a message"}) {
		t.Errorf("empty code should be preserved, got %+v", got[1])
	}
	// The result is a fresh slice, independent of the input.
	in := []Warning{{Code: "AJ1", Message: "m"}}
	out := warningsFromWire(in)
	out[0].Code = "mutated"
	if in[0].Code != "AJ1" {
		t.Error("warningsFromWire should not alias the input slice")
	}
	// Nil/empty input stays nil (not an empty slice).
	if warningsFromWire(nil) != nil {
		t.Error("nil input should produce nil warnings")
	}
}
