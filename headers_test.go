package arcjet

import (
	"net/http/httptest"
	"testing"
)

func TestSetRateLimitHeadersFromResults(t *testing.T) {
	d := Decision{
		Results: []RuleResult{
			{State: RuleStateRun, Reason: Reason{Type: ReasonRateLimit, RateLimit: &RateLimitReason{Max: 100, Remaining: 90, ResetInSeconds: 60, WindowInSeconds: 60}}},
			{State: RuleStateRun, Reason: Reason{Type: ReasonRateLimit, RateLimit: &RateLimitReason{Max: 10, Remaining: 2, ResetInSeconds: 5, WindowInSeconds: 1}}},
		},
	}
	rec := httptest.NewRecorder()
	SetRateLimitHeaders(rec, d)

	if got, want := rec.Header().Get("Ratelimit"), "limit=10, remaining=2, reset=5"; got != want {
		t.Fatalf("RateLimit = %q, want %q", got, want)
	}
	// Policies sorted by lowest max.
	if got, want := rec.Header().Get("Ratelimit-Policy"), "10;w=1, 100;w=60"; got != want {
		t.Fatalf("RateLimit-Policy = %q, want %q", got, want)
	}
}

func TestSetRateLimitHeadersKeepsDistinctPoliciesSharingAMax(t *testing.T) {
	// Two policies with the same max but different windows are distinct and must
	// both appear (dedup key is (max, window), not max alone).
	d := Decision{
		Results: []RuleResult{
			{State: RuleStateRun, Reason: Reason{Type: ReasonRateLimit, RateLimit: &RateLimitReason{Max: 100, Remaining: 50, ResetInSeconds: 30, WindowInSeconds: 60}}},
			{State: RuleStateRun, Reason: Reason{Type: ReasonRateLimit, RateLimit: &RateLimitReason{Max: 100, Remaining: 90, ResetInSeconds: 3000, WindowInSeconds: 3600}}},
		},
	}
	rec := httptest.NewRecorder()
	SetRateLimitHeaders(rec, d)

	if got, want := rec.Header().Get("Ratelimit-Policy"), "100;w=60, 100;w=3600"; got != want {
		t.Fatalf("RateLimit-Policy = %q, want %q", got, want)
	}
	// Nearest-to-exhausted is the lower-remaining (50) one.
	if got, want := rec.Header().Get("Ratelimit"), "limit=100, remaining=50, reset=30"; got != want {
		t.Fatalf("RateLimit = %q, want %q", got, want)
	}
}

func TestSetRateLimitHeadersFallsBackToTopLevelReason(t *testing.T) {
	d := Decision{Reason: Reason{Type: ReasonRateLimit, RateLimit: &RateLimitReason{Max: 5, Remaining: 1, ResetInSeconds: 30, WindowInSeconds: 30}}}
	rec := httptest.NewRecorder()
	SetRateLimitHeaders(rec, d)

	if got, want := rec.Header().Get("Ratelimit"), "limit=5, remaining=1, reset=30"; got != want {
		t.Fatalf("RateLimit = %q, want %q", got, want)
	}
	if got, want := rec.Header().Get("Ratelimit-Policy"), "5;w=30"; got != want {
		t.Fatalf("RateLimit-Policy = %q, want %q", got, want)
	}
}

func TestSetRateLimitHeadersNoopWithoutRateLimit(t *testing.T) {
	d := Decision{Reason: Reason{Type: ReasonBot, Bot: &BotReason{}}}
	rec := httptest.NewRecorder()
	SetRateLimitHeaders(rec, d)

	if rec.Header().Get("Ratelimit") != "" || rec.Header().Get("Ratelimit-Policy") != "" {
		t.Fatalf("expected no rate limit headers, got %v", rec.Header())
	}
}
