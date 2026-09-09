package arcjet

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewGuardDenialResultRateLimitDerivesRetryAfter(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	d := GuardDecision{
		Conclusion: ConclusionDeny,
		Reason:     ReasonRateLimit,
		Results: []GuardRuleResult{{
			Conclusion:  ConclusionDeny,
			Reason:      ReasonRateLimit,
			TokenBucket: &GuardTokenBucketResult{Conclusion: ConclusionDeny, ResetAtUnixSeconds: 1_000_030},
		}},
	}
	got := newGuardDenialResultAt(d, now)
	if !got.ArcjetDenied || got.Reason != "RATE_LIMIT" || !got.Retryable {
		t.Fatalf("payload = %+v", got)
	}
	if got.RetryAfterSeconds == nil {
		t.Fatal("retryAfterSeconds = nil, want 30")
	}
	if *got.RetryAfterSeconds != 30 {
		t.Fatalf("retryAfterSeconds = %d, want 30", *got.RetryAfterSeconds)
	}
	if got.Message != "Arcjet denied this call (RATE_LIMIT). It may be retried after 30 seconds." {
		t.Fatalf("message = %q", got.Message)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"arcjetDenied":true,"reason":"RATE_LIMIT","message":"Arcjet denied this call (RATE_LIMIT). It may be retried after 30 seconds.","retryable":true,"retryAfterSeconds":30}`
	if string(raw) != want {
		t.Fatalf("json = %s", raw)
	}
}

func TestNewGuardDenialResultRateLimitPastResetClampsToZero(t *testing.T) {
	now := time.Unix(1_000_100, 0)
	d := GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonRateLimit, Results: []GuardRuleResult{{
		FixedWindow: &GuardFixedWindowResult{Conclusion: ConclusionDeny, ResetAtUnixSeconds: 1_000_030},
	}}}
	got := newGuardDenialResultAt(d, now)
	if got.RetryAfterSeconds == nil {
		t.Fatal("retryAfterSeconds = nil, want 0")
	}
	if *got.RetryAfterSeconds != 0 {
		t.Fatalf("retryAfterSeconds = %d, want 0", *got.RetryAfterSeconds)
	}
}

func TestNewGuardDenialResultRateLimitIgnoresAllowingResults(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	d := GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonRateLimit, Results: []GuardRuleResult{
		// A bucket that allowed. Its reset says nothing about this denial.
		{TokenBucket: &GuardTokenBucketResult{Conclusion: ConclusionAllow, ResetAtUnixSeconds: 1_000_005}},
		// The window that actually denied.
		{FixedWindow: &GuardFixedWindowResult{Conclusion: ConclusionDeny, ResetAtUnixSeconds: 1_000_045}},
	}}
	got := newGuardDenialResultAt(d, now)
	if got.RetryAfterSeconds == nil {
		t.Fatal("retryAfterSeconds = nil, want 45 from the denying rule")
	}
	if *got.RetryAfterSeconds != 45 {
		t.Fatalf("retryAfterSeconds = %d, want 45 from the denying rule", *got.RetryAfterSeconds)
	}
}

func TestNewGuardDenialResultRateLimitTakesLatestDenyingReset(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	d := GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonRateLimit, Results: []GuardRuleResult{
		{TokenBucket: &GuardTokenBucketResult{Conclusion: ConclusionDeny, ResetAtUnixSeconds: 1_000_010}},
		{SlidingWindow: &GuardSlidingWindowResult{Conclusion: ConclusionDeny, ResetAtUnixSeconds: 1_000_060}},
	}}
	got := newGuardDenialResultAt(d, now)
	if got.RetryAfterSeconds == nil {
		t.Fatal("retryAfterSeconds = nil, want 60: a caller cannot retry until the last denying limit resets")
	}
	if *got.RetryAfterSeconds != 60 {
		t.Fatalf("retryAfterSeconds = %d, want 60: a caller cannot retry until the last denying limit resets", *got.RetryAfterSeconds)
	}
	if got.Message != "Arcjet denied this call (RATE_LIMIT). It may be retried after 60 seconds." {
		t.Fatalf("message = %q", got.Message)
	}
}

func TestNewGuardDenialResultRateLimitWithoutResetSaysLater(t *testing.T) {
	d := GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonRateLimit}
	got := newGuardDenialResultAt(d, time.Unix(0, 0))
	if got.RetryAfterSeconds != nil {
		t.Fatalf("retryAfterSeconds = %d, want absent", *got.RetryAfterSeconds)
	}
	if got.Message != "Arcjet denied this call (RATE_LIMIT). It may be retried later." {
		t.Fatalf("message = %q", got.Message)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"arcjetDenied":true,"reason":"RATE_LIMIT","message":"Arcjet denied this call (RATE_LIMIT). It may be retried later.","retryable":true}` {
		t.Fatalf("json = %s", raw)
	}
}

func TestNewGuardDenialResultOtherReasonIsNotRetryable(t *testing.T) {
	d := GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonPromptInjection, Results: []GuardRuleResult{{
		// A co-occurring rate limit result that allowed must not leak a retry hint.
		TokenBucket: &GuardTokenBucketResult{Conclusion: ConclusionAllow, ResetAtUnixSeconds: 99},
	}}}
	got := newGuardDenialResultAt(d, time.Unix(0, 0))
	if got.Retryable || got.RetryAfterSeconds != nil {
		t.Fatalf("payload = %+v", got)
	}
	if got.Message != "Arcjet denied this call (PROMPT_INJECTION). Do not retry; explain the denial to the user or try a different approach." {
		t.Fatalf("message = %q", got.Message)
	}
}

func TestNewGuardUnavailableResultLiterals(t *testing.T) {
	got := NewGuardUnavailableResult()
	if !got.ArcjetDenied || got.Reason != "ERROR" || !got.Retryable {
		t.Fatalf("payload = %+v", got)
	}
	if got.RetryAfterSeconds == nil {
		t.Fatal("retryAfterSeconds = nil, want 5")
	}
	if *got.RetryAfterSeconds != 5 {
		t.Fatalf("retryAfterSeconds = %d, want 5", *got.RetryAfterSeconds)
	}
	if got.Message != "Arcjet security check could not be completed; please retry later." {
		t.Fatalf("message = %q", got.Message)
	}
}
