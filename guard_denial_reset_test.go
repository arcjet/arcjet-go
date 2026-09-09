package arcjet

import (
	"testing"
	"time"
)

// proto3 encodes an omitted uint32 as zero, so a denying rate-limit result
// that carries no reset must not read as "retry immediately".
func TestNewGuardDenialResultIgnoresAZeroReset(t *testing.T) {
	d := GuardDecision{
		Conclusion: ConclusionDeny,
		Reason:     ReasonRateLimit,
		Results: []GuardRuleResult{
			{TokenBucket: &GuardTokenBucketResult{Conclusion: ConclusionDeny}},
		},
	}
	got := newGuardDenialResultAt(d, time.Unix(1780000000, 0))
	if got.RetryAfterSeconds != nil {
		t.Fatalf("retryAfterSeconds = %d, want absent for an unset reset", *got.RetryAfterSeconds)
	}
	if got.Message != "Arcjet denied this call (RATE_LIMIT). It may be retried later." {
		t.Fatalf("message = %q", got.Message)
	}
}

// A reset near the uint32 ceiling is a server bug or clock skew. It must not
// reach the model as a multi-decade wait, nor narrow to a negative number on
// a 32-bit consumer.
func TestNewGuardDenialResultClampsAnAbsurdReset(t *testing.T) {
	now := time.Unix(1780000000, 0)
	d := GuardDecision{
		Conclusion: ConclusionDeny,
		Reason:     ReasonRateLimit,
		Results: []GuardRuleResult{
			{TokenBucket: &GuardTokenBucketResult{
				Conclusion:         ConclusionDeny,
				ResetAtUnixSeconds: 4294967295,
			}},
		},
	}
	got := newGuardDenialResultAt(d, now)
	if got.RetryAfterSeconds == nil {
		t.Fatal("retryAfterSeconds absent, want the clamp")
	}
	if *got.RetryAfterSeconds != maxRetryAfterSeconds {
		t.Fatalf("retryAfterSeconds = %d, want %d", *got.RetryAfterSeconds, maxRetryAfterSeconds)
	}
}

// A reason the SDK does not recognise must never render as an empty string:
// the model is handed the reason verbatim inside a sentence.
func TestParseGuardReasonCoversInputConstraint(t *testing.T) {
	if got := parseGuardReason("GUARD_REASON_INPUT_CONSTRAINT"); got != ReasonInputConstraint {
		t.Fatalf("parseGuardReason = %q, want %q", got, ReasonInputConstraint)
	}
}

func TestNewGuardDenialResultRendersAnInputConstraintReason(t *testing.T) {
	d := GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonInputConstraint}
	got := newGuardDenialResultAt(d, time.Unix(0, 0))
	if got.Reason != "INPUT_CONSTRAINT" {
		t.Fatalf("reason = %q, want INPUT_CONSTRAINT", got.Reason)
	}
	if got.Message != "Arcjet denied this call (INPUT_CONSTRAINT). Do not retry; explain the denial to the user or try a different approach." {
		t.Fatalf("message = %q", got.Message)
	}
}
