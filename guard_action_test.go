package arcjet

import (
	"errors"
	"testing"
)

func TestOnGuardErrorZeroValueIsDeny(t *testing.T) {
	var o OnGuardError
	if o != OnGuardErrorDeny {
		t.Fatalf("zero value = %v, want deny", o)
	}
	if got := OnGuardErrorDeny.String(); got != "deny" {
		t.Fatalf("String() = %q", got)
	}
	if got := OnGuardErrorAllow.String(); got != "allow" {
		t.Fatalf("String() = %q", got)
	}
}

func TestGuardDeniedErrorMessage(t *testing.T) {
	err := &GuardDeniedError{Action: "refund.issued", Decision: GuardDecision{Conclusion: ConclusionDeny, Reason: ReasonRateLimit}}
	if got := err.Error(); got != `arcjet: denied action "refund.issued" (RATE_LIMIT)` {
		t.Fatalf("Error() = %q", got)
	}
}

func TestGuardUnavailableErrorUnwraps(t *testing.T) {
	err := &GuardUnavailableError{Action: "refund.issued", Err: ErrInvalidLabel}
	if !errors.Is(err, ErrInvalidLabel) {
		t.Fatal("expected errors.Is to see the wrapped programmer error")
	}
	if got := err.Error(); got != `arcjet: policy for action "refund.issued" could not be evaluated: invalid guard label` {
		t.Fatalf("Error() = %q", got)
	}
	bare := &GuardUnavailableError{Action: "refund.issued"}
	if got := bare.Error(); got != `arcjet: policy for action "refund.issued" could not be evaluated` {
		t.Fatalf("Error() = %q", got)
	}
}
