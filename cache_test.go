package arcjet

import (
	"testing"
	"time"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

func TestRuleCacheSetSkipsNonCacheable(t *testing.T) {
	cache := newRuleCache()
	const ruleID = "rid"
	const fingerprint = "fp"

	allow := &decidev1.RuleResult{
		RuleId:     "allow",
		State:      decidev1.RuleState_RULE_STATE_RUN,
		Conclusion: decidev1.Conclusion_CONCLUSION_ALLOW,
		Ttl:        60,
	}
	cache.set(ruleID, fingerprint, allow)
	if got := cache.get(ruleID, fingerprint); got != nil {
		t.Error("ALLOW rule results must not be cached")
	}

	zeroTTL := &decidev1.RuleResult{
		RuleId:     "deny",
		State:      decidev1.RuleState_RULE_STATE_RUN,
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Ttl:        0,
	}
	cache.set(ruleID, fingerprint, zeroTTL)
	if got := cache.get(ruleID, fingerprint); got != nil {
		t.Error("zero-TTL DENY must not be cached")
	}

	dryRun := &decidev1.RuleResult{
		RuleId:     "deny",
		State:      decidev1.RuleState_RULE_STATE_DRY_RUN,
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Ttl:        60,
	}
	cache.set(ruleID, fingerprint, dryRun)
	if got := cache.get(ruleID, fingerprint); got != nil {
		t.Error("DRY_RUN results must not be cached — they do not enforce")
	}

	// Empty keys are silently dropped so the cache never collides results
	// from rules whose ID failed to compute, or from a request where the
	// WASM fingerprint failed.
	live := &decidev1.RuleResult{
		State:      decidev1.RuleState_RULE_STATE_RUN,
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Ttl:        60,
	}
	cache.set("", fingerprint, live)
	if got := cache.get("", fingerprint); got != nil {
		t.Error("empty ruleID must not be readable")
	}
	cache.set(ruleID, "", live)
	if got := cache.get(ruleID, ""); got != nil {
		t.Error("empty fingerprint must not be readable")
	}

	cache.set(ruleID, fingerprint, nil)
	if got := cache.get(ruleID, fingerprint); got != nil {
		t.Error("nil result must not cache")
	}
}

func TestRuleCacheGetPurgesExpiredAndRefreshesState(t *testing.T) {
	cache := newRuleCache()
	const ruleID = "rid"
	const fingerprint = "fp"
	deny := &decidev1.RuleResult{
		RuleId:     "rule_original",
		State:      decidev1.RuleState_RULE_STATE_RUN,
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Ttl:        60,
	}
	cache.set(ruleID, fingerprint, deny)
	got := cache.get(ruleID, fingerprint)
	if got == nil {
		t.Fatal("expected cache hit")
	}
	if got.GetState() != decidev1.RuleState_RULE_STATE_CACHED {
		t.Errorf("expected state CACHED on hit, got %s", got.GetState())
	}
	if got.GetTtl() == 0 {
		t.Error("expected nonzero TTL on cache hit")
	}
	if got.GetFingerprint() != fingerprint {
		t.Errorf("expected fingerprint to be stamped on the hit, got %q", got.GetFingerprint())
	}
	// The cached entry must be defensively cloned: a caller mutating the
	// returned result must not corrupt the cache for the next reader.
	got.RuleId = "tampered"
	again := cache.get(ruleID, fingerprint)
	if again == nil || again.GetRuleId() == "tampered" {
		t.Fatalf("cache returned a shared pointer; mutation leaked: %#v", again)
	}

	key := ruleCacheKey{ruleID: ruleID, fingerprint: fingerprint}
	cache.entries[key] = ruleCacheEntry{
		result:    deny,
		expiresAt: time.Now().Add(-time.Second),
	}
	if got := cache.get(ruleID, fingerprint); got != nil {
		t.Error("expired entry should not be returned")
	}
	if _, ok := cache.entries[key]; ok {
		t.Error("expired entry should be evicted from map")
	}
}

func TestDecisionFromRuleResultWrapsDeny(t *testing.T) {
	result := &decidev1.RuleResult{
		RuleId:     "rule_x",
		State:      decidev1.RuleState_RULE_STATE_CACHED,
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Reason:     &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{RateLimit: &decidev1.RateLimitReason{Max: 10}}},
		Ttl:        42,
	}
	decision := decisionFromRuleResult(result)
	if decision == nil || decision.decision == nil {
		t.Fatal("expected wrapped decision")
	}
	if !decision.liveDeny() {
		t.Error("wrapped decision should be a live DENY")
	}
	if decision.decision.GetTtl() != 42 || len(decision.decision.GetRuleResults()) != 1 {
		t.Errorf("wrapped decision = %#v", decision.decision)
	}
	if decision.decision.GetId() == "" {
		t.Error("wrapped decision should have a fresh ID")
	}
}
