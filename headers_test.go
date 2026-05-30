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

	if got, want := rec.Header().Get("RateLimit"), "limit=10, remaining=2, reset=5"; got != want {
		t.Fatalf("RateLimit = %q, want %q", got, want)
	}
	// Policies sorted by lowest max.
	if got, want := rec.Header().Get("RateLimit-Policy"), "10;w=1, 100;w=60"; got != want {
		t.Fatalf("RateLimit-Policy = %q, want %q", got, want)
	}
}

func TestSetRateLimitHeadersFallsBackToTopLevelReason(t *testing.T) {
	d := Decision{Reason: Reason{Type: ReasonRateLimit, RateLimit: &RateLimitReason{Max: 5, Remaining: 1, ResetInSeconds: 30, WindowInSeconds: 30}}}
	rec := httptest.NewRecorder()
	SetRateLimitHeaders(rec, d)

	if got, want := rec.Header().Get("RateLimit"), "limit=5, remaining=1, reset=30"; got != want {
		t.Fatalf("RateLimit = %q, want %q", got, want)
	}
	if got, want := rec.Header().Get("RateLimit-Policy"), "5;w=30"; got != want {
		t.Fatalf("RateLimit-Policy = %q, want %q", got, want)
	}
}

func TestSetRateLimitHeadersNoopWithoutRateLimit(t *testing.T) {
	d := Decision{Reason: Reason{Type: ReasonBot, Bot: &BotReason{}}}
	rec := httptest.NewRecorder()
	SetRateLimitHeaders(rec, d)

	if rec.Header().Get("RateLimit") != "" || rec.Header().Get("RateLimit-Policy") != "" {
		t.Fatalf("expected no rate limit headers, got %v", rec.Header())
	}
}
