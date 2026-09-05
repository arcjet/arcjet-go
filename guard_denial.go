package arcjet

import (
	"fmt"
	"time"
)

// GuardDenialResult is the payload a model-facing helper returns in place of
// a tool result when Arcjet denied the call or could not evaluate it. The
// JSON field names match the JavaScript and Python SDKs so a model sees one
// shape across integrations.
type GuardDenialResult struct {
	ArcjetDenied bool `json:"arcjetDenied"`
	// Reason is the decision reason, for example "RATE_LIMIT", or "ERROR"
	// when the policy could not be evaluated.
	Reason string `json:"reason"`
	// Message explains the denial to a model or a person.
	Message string `json:"message"`
	// Retryable is true for rate limits and for an unavailable guard.
	Retryable bool `json:"retryable"`
	// RetryAfterSeconds is set when a retry hint can be derived.
	RetryAfterSeconds *int `json:"retryAfterSeconds,omitempty"`
}

const guardUnavailableRetryAfterSeconds = 5

// NewGuardDenialResult builds the payload for a DENY decision. A rate-limit
// denial derives RetryAfterSeconds from the denying rule's reset time; other
// reasons carry no hint and are not retryable.
func NewGuardDenialResult(d GuardDecision) GuardDenialResult {
	return newGuardDenialResultAt(d, time.Now())
}

func newGuardDenialResultAt(d GuardDecision, now time.Time) GuardDenialResult {
	reason := string(d.Reason)
	result := GuardDenialResult{ArcjetDenied: true, Reason: reason}
	if d.Reason != ReasonRateLimit {
		result.Message = fmt.Sprintf("Arcjet denied this call (%s). Do not retry; explain the denial to the user or try a different approach.", reason)
		return result
	}
	result.Retryable = true
	secs, ok := guardRetryAfterSeconds(d, now)
	if !ok {
		result.Message = fmt.Sprintf("Arcjet denied this call (%s). It may be retried later.", reason)
		return result
	}
	result.RetryAfterSeconds = &secs
	result.Message = fmt.Sprintf("Arcjet denied this call (%s). It may be retried after %d seconds.", reason, secs)
	return result
}

// guardRetryAfterSeconds returns whole seconds until the caller may retry:
// the latest reset time among the rate limit results that denied, clamped at
// zero. It reports false when no denying result carries one.
//
// Only denying results count. A decision can carry a rate limit result that
// allowed beside one that denied, and the allowing rule's reset says nothing
// about when this call may succeed. When several denied, the caller cannot
// succeed until the last of them resets, so the latest wins.
func guardRetryAfterSeconds(d GuardDecision, now time.Time) (int, bool) {
	var latest int64
	found := false
	for _, r := range d.Results {
		var conclusion Conclusion
		var reset int64
		switch {
		case r.TokenBucket != nil:
			conclusion, reset = r.TokenBucket.Conclusion, r.TokenBucket.ResetAtUnixSeconds
		case r.FixedWindow != nil:
			conclusion, reset = r.FixedWindow.Conclusion, r.FixedWindow.ResetAtUnixSeconds
		case r.SlidingWindow != nil:
			conclusion, reset = r.SlidingWindow.Conclusion, r.SlidingWindow.ResetAtUnixSeconds
		default:
			continue
		}
		if conclusion != ConclusionDeny {
			continue
		}
		if !found || reset > latest {
			latest, found = reset, true
		}
	}
	if !found {
		return 0, false
	}
	return int(max(latest-now.Unix(), 0)), true
}

// GuardUnavailableResult builds the payload returned when policy could not be
// evaluated and the helper fails closed. It carries a fixed retry hint because
// there is no decision to derive one from.
func GuardUnavailableResult() GuardDenialResult {
	retry := guardUnavailableRetryAfterSeconds
	return GuardDenialResult{
		ArcjetDenied:      true,
		Reason:            string(ReasonError),
		Message:           "Arcjet security check could not be completed; please retry later.",
		Retryable:         true,
		RetryAfterSeconds: &retry,
	}
}
