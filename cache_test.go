package arcjet

import (
	"testing"
	"time"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

func TestDecisionCacheKeyExcludesCorrelationId(t *testing.T) {
	base := ProtectDetails{IP: "203.0.113.10", Method: "GET", Path: "/"}
	options := ProtectOptions{}

	without := makeDecisionCacheKey(base, "rules-hash", options)

	withID := base
	withID.CorrelationId = "wf_abcdef"
	withCorrelationID := makeDecisionCacheKey(withID, "rules-hash", options)

	if without != withCorrelationID {
		t.Fatalf("correlation_id changed the cache key: %q != %q", without, withCorrelationID)
	}
}

func TestDecisionCacheSetSkipsNonCacheable(t *testing.T) {
	cache := newDecisionCache()
	allow := &decidev1.Decision{
		Id:         "allow",
		Conclusion: decidev1.Conclusion_CONCLUSION_ALLOW,
		Ttl:        60,
	}
	cache.set("k", allow)
	if got := cache.get("k"); got != nil {
		t.Error("allow decisions must not be cached")
	}
	zeroTTL := &decidev1.Decision{
		Id:         "deny",
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Ttl:        0,
	}
	cache.set("k2", zeroTTL)
	if got := cache.get("k2"); got != nil {
		t.Error("zero TTL deny must not be cached")
	}
	cache.set("", &decidev1.Decision{Conclusion: decidev1.Conclusion_CONCLUSION_DENY, Ttl: 60})
	if got := cache.get(""); got != nil {
		t.Error("empty key must not be readable")
	}
	cache.set("k3", nil)
	if got := cache.get("k3"); got != nil {
		t.Error("nil decision must not cache")
	}
}

func TestDecisionCacheGetPurgesExpiredAndRefreshesState(t *testing.T) {
	cache := newDecisionCache()
	deny := &decidev1.Decision{
		Id:         "original",
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Ttl:        60,
		RuleResults: []*decidev1.RuleResult{
			{RuleId: "r1", State: decidev1.RuleState_RULE_STATE_RUN},
		},
	}
	cache.set("hit", deny)
	got := cache.get("hit")
	if got == nil {
		t.Fatal("expected cache hit")
	}
	if got.GetId() == "original" {
		t.Error("expected fresh ID on cache hit")
	}
	if got.GetTtl() == 0 {
		t.Error("expected nonzero TTL on cache hit")
	}
	if state := got.GetRuleResults()[0].GetState(); state != decidev1.RuleState_RULE_STATE_CACHED {
		t.Errorf("expected rule state CACHED, got %s", state)
	}

	cache.entries["hit"] = decisionCacheEntry{
		decision:  deny,
		expiresAt: time.Now().Add(-time.Second),
	}
	if got := cache.get("hit"); got != nil {
		t.Error("expired entry should not be returned")
	}
	if _, ok := cache.entries["hit"]; ok {
		t.Error("expired entry should be evicted from map")
	}
}
