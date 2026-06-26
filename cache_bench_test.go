package arcjet

import (
	"testing"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

func benchCachedRuleResult() *decidev1.RuleResult {
	return &decidev1.RuleResult{
		RuleId:     "rule_cached",
		State:      decidev1.RuleState_RULE_STATE_RUN,
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
			RateLimit: &decidev1.RateLimitReason{Max: 10},
		}},
		Ttl: 300,
	}
}

// BenchmarkRuleCacheGet measures the cache-hit path: lookup under the
// mutex, proto.Clone of the cached RuleResult, and TTL/state/fingerprint
// rewrites. This is the work executed inside the per-rule loop in
// evaluateLocal for every cache hit.
func BenchmarkRuleCacheGet(b *testing.B) {
	cache := newRuleCache()
	const ruleID = "bench_rule"
	const fingerprint = "bench_fp"
	cache.set(ruleID, fingerprint, benchCachedRuleResult())

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if r := cache.get(ruleID, fingerprint); r == nil {
			b.Fatal("expected cache hit")
		}
	}
}

// BenchmarkRuleCacheGetMiss measures the cache-miss path — a map lookup
// that returns nothing. Realistic for new (ruleID, fingerprint) pairs.
func BenchmarkRuleCacheGetMiss(b *testing.B) {
	cache := newRuleCache()
	cache.set("warm_rule", "warm_fp", benchCachedRuleResult())

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if r := cache.get("missing_rule", "missing_fp"); r != nil {
			b.Fatal("expected cache miss")
		}
	}
}

// BenchmarkRuleCacheSet measures cache population: TTL arithmetic, proto
// Clone, and the map insert under the mutex. Runs once per cacheable
// rule result, so allocations here matter for steady-state behaviour under
// traffic with high fingerprint churn.
func BenchmarkRuleCacheSet(b *testing.B) {
	cache := newRuleCache()
	result := benchCachedRuleResult()

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		// Vary the fingerprint so each set actually inserts rather than
		// overwriting the same slot — keeps the benchmark honest about the
		// cost of growing the map under load.
		cache.set("rule_bench", fingerprintForIter(i), result)
	}
}

func fingerprintForIter(i int) string {
	// Two hex digits cover the rotation pattern we want without ever
	// colliding within b.N at realistic sizes — and even when they
	// collide the set still does the same work (clone, lock, assign).
	const hex = "0123456789abcdef"
	return string([]byte{hex[(i>>4)&0xf], hex[i&0xf]})
}

// BenchmarkHashKey measures guard's per-call key hashing (SHA-256 of the
// key parts joined by 0x00). Runs once per rate-limit-style Guard rule
// input, and per-rule once at construction for the ruleID hash.
func BenchmarkHashKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = hashKey("user_123")
	}
}
