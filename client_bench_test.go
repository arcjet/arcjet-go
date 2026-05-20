package arcjet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1/decidev1alpha1connect"
)

// benchDenyDecision is the canned deny decision returned by the in-process
// Decide stub used in client benchmarks. Hoisted so each benchmark does not
// re-allocate the same proto tree at setup time.
func benchDenyDecision() *decidev1.Decision {
	return &decidev1.Decision{
		Id:         "req_remote",
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
			RateLimit: &decidev1.RateLimitReason{Max: 10},
		}},
		RuleResults: []*decidev1.RuleResult{
			{
				RuleId:     "rule_remote",
				State:      decidev1.RuleState_RULE_STATE_RUN,
				Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
				Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
					RateLimit: &decidev1.RateLimitReason{Max: 10},
				}},
				Ttl: 30,
			},
		},
		Ttl: 30,
	}
}

// newBenchClient builds a Client wired to an in-process Decide handler. The
// returned client makes no network calls — Decide and Report are served by
// the supplied handler via handlerTransport (defined in client_test.go).
func newBenchClient(b *testing.B, handler *testDecideHandler, rules ...Rule) *Client {
	b.Helper()
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Rules:      rules,
	})
	if err != nil {
		b.Fatal(err)
	}
	return client
}

// BenchmarkProtectDetailsCacheHit measures the cache-hit fast path of
// ProtectDetails: a cached deny is cloned, TTL is rewritten, Report fires
// asynchronously, and the call returns without touching the network.
func BenchmarkProtectDetailsCacheHit(b *testing.B) {
	handler := &testDecideHandler{
		// Large buffer prevents the report goroutine from blocking during
		// the benchmark; overflow is dropped via the select-default in
		// Report itself.
		reportCh: make(chan struct{}, 100000),
		decision: benchDenyDecision(),
	}
	client := newBenchClient(b, handler,
		TokenBucket(TokenBucketOptions{
			Mode:       ModeLive,
			RefillRate: 1,
			Interval:   time.Minute,
			Capacity:   10,
		}),
	)

	ctx := context.Background()
	details := ProtectDetails{IP: "203.0.113.10"}

	// Populate the cache.
	if _, err := client.ProtectDetails(ctx, details); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := client.ProtectDetails(ctx, details)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkProtectDetailsCacheMiss measures the cache-miss path: cache key
// hashing, local-rule iteration, Decide RPC round-trip through the in-process
// handler, and cache population. The handler returns a non-cacheable allow so
// each iteration stays on the miss path.
func BenchmarkProtectDetailsCacheMiss(b *testing.B) {
	handler := &testDecideHandler{
		// Allow decisions are not cached, so every iteration re-hits Decide.
		decision: &decidev1.Decision{
			Id:         "req_allow",
			Conclusion: decidev1.Conclusion_CONCLUSION_ALLOW,
		},
	}
	client := newBenchClient(b, handler,
		TokenBucket(TokenBucketOptions{
			Mode:       ModeLive,
			RefillRate: 1,
			Interval:   time.Minute,
			Capacity:   10,
		}),
	)

	ctx := context.Background()
	details := ProtectDetails{IP: "203.0.113.10"}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := client.ProtectDetails(ctx, details); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkProtectDetailsLocalBotDeny measures the local-deny path: the bot
// Wasm evaluator denies a curl user-agent in-process and the deny is cached
// on the first iteration. Subsequent iterations exercise the cache hit so
// the steady-state cost reflects the cached fast path. Kept separate from
// BenchmarkProtectDetailsCacheHit because the cache is populated by a local
// evaluator instead of a Decide response.
func BenchmarkProtectDetailsLocalBotDeny(b *testing.B) {
	handler := &testDecideHandler{
		reportCh: make(chan struct{}, 100000),
	}
	client := newBenchClient(b, handler,
		DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
	)

	ctx := context.Background()
	details := ProtectDetails{
		IP:      "203.0.113.10",
		Headers: map[string]string{"user-agent": "curl/8.7.1"},
	}

	// Prime the local-deny cache so the benchmark measures the cached fast
	// path, not the per-call Wasm instantiation cost (that path is covered
	// by the local evaluator's own tests).
	if _, err := client.ProtectDetails(ctx, details); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := client.ProtectDetails(ctx, details); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkProtect measures the full Protect path including
// detailsFromRequest header copy and IP resolution. Uses a primed cache so
// the steady-state cost is the request-to-details conversion plus the
// cache-hit fast path.
func BenchmarkProtect(b *testing.B) {
	handler := &testDecideHandler{
		reportCh: make(chan struct{}, 100000),
		decision: benchDenyDecision(),
	}
	client := newBenchClient(b, handler,
		TokenBucket(TokenBucketOptions{
			Mode:       ModeLive,
			RefillRate: 1,
			Interval:   time.Minute,
			Capacity:   10,
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/chat?debug=1", http.NoBody)
	req.RemoteAddr = "203.0.113.10:4567"
	req.Header.Set("User-Agent", "bench")
	req.Header.Set("Cookie", "sid=abc")

	ctx := context.Background()
	if _, err := client.Protect(ctx, req); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := client.Protect(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDetailsFromRequest measures the standalone request-to-details
// conversion: header map copy, host fallback, and IP extraction with no
// trusted proxies or hosting platform configured.
func BenchmarkDetailsFromRequest(b *testing.B) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/chat?debug=1", http.NoBody)
	req.RemoteAddr = "203.0.113.10:4567"
	req.Header.Set("User-Agent", "bench")
	req.Header.Set("Cookie", "sid=abc")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = DetailsFromRequest(req)
	}
}

// BenchmarkWithRule measures the cost of deriving a route-scoped client from
// a base client: rule validation, proto encoding, and rules-hash recompute.
// This runs at startup or per-route registration rather than per-request,
// but is worth tracking because misuse (calling it inside a handler) would
// be expensive.
func BenchmarkWithRule(b *testing.B) {
	handler := &testDecideHandler{}
	base := newBenchClient(b, handler,
		Shield(ShieldOptions{Mode: ModeLive}),
	)
	extra := TokenBucket(TokenBucketOptions{
		Mode:       ModeLive,
		RefillRate: 1,
		Interval:   time.Minute,
		Capacity:   10,
	})

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := base.WithRule(extra); err != nil {
			b.Fatal(err)
		}
	}
}
