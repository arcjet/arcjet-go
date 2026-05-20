package arcjet

import (
	"testing"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

func benchCachedDecision() *decidev1.Decision {
	return &decidev1.Decision{
		Id:         "req_cached",
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
			RateLimit: &decidev1.RateLimitReason{Max: 10},
		}},
		RuleResults: []*decidev1.RuleResult{
			{
				RuleId:     "rule_cached",
				State:      decidev1.RuleState_RULE_STATE_RUN,
				Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
				Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
					RateLimit: &decidev1.RateLimitReason{Max: 10},
				}},
				Ttl: 300,
			},
		},
		Ttl: 300,
	}
}

// BenchmarkMakeDecisionCacheKey measures the per-call cache key derivation:
// JSON-marshal a struct holding details + filter-local + rules hash, then
// hex-encode a SHA-256 of the payload. Runs on every ProtectDetails call,
// regardless of whether the cache subsequently hits or misses.
func BenchmarkMakeDecisionCacheKey(b *testing.B) {
	details := ProtectDetails{
		IP:       "203.0.113.10",
		Method:   "POST",
		Protocol: "HTTP/1.1",
		Host:     "example.com",
		Path:     "/api/chat",
		Headers: map[string]string{
			"user-agent": "bench",
			"accept":     "application/json",
		},
		Cookies: "sid=abc",
		Query:   "?debug=1",
		Extra:   map[string]string{"requested": "1"},
	}
	options := ProtectOptions{}
	rulesHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := makeDecisionCacheKey(details, rulesHash, options); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecisionCacheGet measures the cache-hit path of decisionCache:
// map lookup, proto.Clone of the cached decision, fresh request ID, and
// TTL/state rewrites on every rule result. This is the work performed
// inside the cache-hit ProtectDetails path, isolated from network and
// hashing.
func BenchmarkDecisionCacheGet(b *testing.B) {
	cache := newDecisionCache()
	key := "bench_key"
	cache.set(key, benchCachedDecision())

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if d := cache.get(key); d == nil {
			b.Fatal("expected cache hit")
		}
	}
}

// BenchmarkDecisionCacheGetMiss measures the cache-miss path: a map lookup
// that returns nothing. Realistic for new request signatures.
func BenchmarkDecisionCacheGetMiss(b *testing.B) {
	cache := newDecisionCache()
	cache.set("warm_key", benchCachedDecision())

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if d := cache.get("missing_key"); d != nil {
			b.Fatal("expected cache miss")
		}
	}
}

// BenchmarkDecisionCacheSet measures cache population: proto.Clone of the
// decision, TTL arithmetic, and the map insert under the mutex. Runs once
// per cache-miss decision, so allocations here matter for steady-state
// behaviour under traffic with high signature churn.
func BenchmarkDecisionCacheSet(b *testing.B) {
	cache := newDecisionCache()
	decision := benchCachedDecision()

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		// Vary the key so each set actually inserts rather than overwriting
		// the same slot — that keeps the benchmark honest about the cost of
		// growing the map under load. We don't care that the map grows
		// unboundedly here; b.N drives total work.
		cache.set(keyForIter(i), decision)
	}
}

func keyForIter(i int) string {
	// Small helper to avoid pulling strconv into the package's bench
	// transitive deps just for a key. Two hex digits cover the rotation
	// pattern we want without ever colliding within b.N at realistic sizes
	// — and even when it does collide the set still does the same work
	// (clone, lock, assign).
	const hex = "0123456789abcdef"
	return string([]byte{hex[(i>>4)&0xf], hex[i&0xf]})
}

// BenchmarkHashKey measures guard's per-call key hashing (SHA-256 of the
// key parts joined by 0x00). Runs once per rate-limit-style Guard rule
// input.
func BenchmarkHashKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = hashKey("user_123")
	}
}

// BenchmarkHashRules measures the rules-hash computation done by NewClient
// and WithRule: protojson-marshal each rule, JSON-encode the array,
// SHA-256, hex-encode. Runs at construction, not per request.
func BenchmarkHashRules(b *testing.B) {
	rules, err := buildRequestRules([]Rule{
		Shield(ShieldOptions{Mode: ModeLive}),
		TokenBucket(TokenBucketOptions{
			Mode:            ModeLive,
			Characteristics: []string{"userId"},
			RefillRate:      1,
			Interval:        60,
			Capacity:        10,
		}),
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := hashRules(rules); err != nil {
			b.Fatal(err)
		}
	}
}
