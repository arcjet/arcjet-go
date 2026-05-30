package arcjet

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// SetRateLimitHeaders writes rate limit headers describing the decision onto
// w, following the IETF "RateLimit header fields for HTTP" draft. It sets:
//
//   - RateLimit: limit=<max>, remaining=<remaining>, reset=<seconds>
//   - RateLimit-Policy: <max>;w=<window>[, <max>;w=<window>...]
//
// When the decision ran multiple rate limit rules, RateLimit reports the limit
// nearest to being exhausted (lowest remaining, then soonest reset, then
// smallest max) while RateLimit-Policy lists every policy. SetRateLimitHeaders
// is a no-op when the decision carries no rate limit reason, so it is safe to
// call unconditionally. Mirrors setRateLimitHeaders from @arcjet/decorate in
// arcjet-js.
func SetRateLimitHeaders(w http.ResponseWriter, d Decision) {
	reasons := d.rateLimitReasons()
	if len(reasons) == 0 {
		return
	}

	// One policy entry per distinct max, sorted by lowest max. A policy is
	// "<max>;w=<window>" per the draft spec.
	type policy struct{ max, window int }
	var policies []policy
	for _, r := range reasons {
		if slices.ContainsFunc(policies, func(p policy) bool { return p.max == r.Max }) {
			continue
		}
		policies = append(policies, policy{max: r.Max, window: r.WindowInSeconds})
	}
	slices.SortFunc(policies, func(a, b policy) int { return cmp.Compare(a.max, b.max) })

	parts := make([]string, len(policies))
	for i, p := range policies {
		parts[i] = fmt.Sprintf("%d;w=%d", p.max, p.window)
	}

	nearest := reasons[0]
	for _, r := range reasons[1:] {
		nearest = nearerLimit(nearest, r)
	}

	header := w.Header()
	header.Set("RateLimit", fmt.Sprintf("limit=%d, remaining=%d, reset=%d", nearest.Max, nearest.Remaining, nearest.ResetInSeconds))
	header.Set("RateLimit-Policy", strings.Join(parts, ", "))
}

// rateLimitReasons collects every rate limit reason that drove the decision,
// preferring the per-rule results and falling back to the top-level reason for
// cached decisions that don't carry rule results.
func (d Decision) rateLimitReasons() []RateLimitReason {
	var reasons []RateLimitReason
	for _, res := range d.Results {
		if rl := res.Reason.RateLimit; rl != nil {
			reasons = append(reasons, *rl)
		}
	}
	if len(reasons) == 0 && d.Reason.RateLimit != nil {
		reasons = append(reasons, *d.Reason.RateLimit)
	}
	return reasons
}

// nearerLimit returns whichever rate limit is closer to being exhausted:
// lowest remaining wins, then soonest reset, then smallest max.
func nearerLimit(current, next RateLimitReason) RateLimitReason {
	if current.Remaining != next.Remaining {
		if current.Remaining < next.Remaining {
			return current
		}
		return next
	}
	if current.ResetInSeconds != next.ResetInSeconds {
		if current.ResetInSeconds < next.ResetInSeconds {
			return current
		}
		return next
	}
	if current.Max < next.Max {
		return current
	}
	return next
}
