package arcjet

import (
	"errors"
	"testing"
	"time"
)

// A reason the SDK cannot map must not reach the model as an empty string
// inside a sentence.
func TestNewGuardDenialResultNamesAnUnmappedReason(t *testing.T) {
	d := GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonUnknown}
	got := newGuardDenialResultAt(d, time.Unix(1780000000, 0))
	if got.Reason != string(ReasonUnknownName) {
		t.Fatalf("reason = %q, want %q", got.Reason, ReasonUnknownName)
	}
	if got.Message != "Arcjet denied this call (UNKNOWN). Do not retry; explain the denial to the user or try a different approach." {
		t.Fatalf("message = %q", got.Message)
	}
}

// Retryability follows the results. A denying rate-limit result carries a
// reset even when the decision's reason did not map, and the model must not
// be told to give up on a call it could make in thirty seconds.
func TestNewGuardDenialResultRetriesOnAResetDespiteAnUnmappedReason(t *testing.T) {
	now := time.Unix(1780000000, 0)
	d := GuardDecision{
		Conclusion: ConclusionDeny,
		Reason:     ReasonUnknown,
		Results: []GuardRuleResult{
			{TokenBucket: &GuardTokenBucketResult{
				Conclusion:         ConclusionDeny,
				ResetAtUnixSeconds: now.Unix() + 30,
			}},
		},
	}
	got := newGuardDenialResultAt(d, now)
	if !got.Retryable {
		t.Fatal("retryable = false; a denying result carried a reset")
	}
	if got.RetryAfterSeconds == nil || *got.RetryAfterSeconds != 30 {
		t.Fatalf("retryAfterSeconds = %v, want 30", got.RetryAfterSeconds)
	}
}

// A locally enforced denial whose report to the server failed must keep the
// transport error, or nothing can alert on the lost telemetry.
func TestGuardDeniedErrorUnwrapsAnAccompanyingFailure(t *testing.T) {
	cause := errors.New("report rpc failed")
	err := error(&GuardDeniedError{
		Action:   "refund.issued",
		Decision: GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonRateLimit},
		Err:      cause,
	})
	if !errors.Is(err, cause) {
		t.Fatal("errors.Is did not reach the accompanying failure")
	}
	var denied *GuardDeniedError
	if !errors.As(err, &denied) || denied.Action != "refund.issued" {
		t.Fatalf("errors.As = %v", denied)
	}
}
