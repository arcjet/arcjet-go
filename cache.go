package arcjet

import (
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

// ruleCache stores per-rule decision results keyed by (ruleID, fingerprint).
//
// Mirrors arcjet-js: each local rule consults its slot before running and
// repopulates it after; results from the Decide RPC are written back so a
// subsequent call can short-circuit on a server-side DENY without another
// network round-trip. Only conclusion=DENY rule results with state=RUN and
// a non-zero TTL are stored — matching JS's rate-limit caching policy and
// the previous whole-decision cache's policy.
type ruleCache struct {
	mu      sync.Mutex
	entries map[ruleCacheKey]ruleCacheEntry
}

type ruleCacheKey struct {
	ruleID      string
	fingerprint string
}

type ruleCacheEntry struct {
	result    *decidev1.RuleResult
	expiresAt time.Time
}

func newRuleCache() *ruleCache {
	return &ruleCache{entries: make(map[ruleCacheKey]ruleCacheEntry)}
}

// get returns a cloned cached RuleResult with state set to RULE_STATE_CACHED
// and TTL rewritten to the remaining lifetime in seconds. Returns nil on
// miss or expiry; an expired entry is also removed from the map.
//
// Empty ruleID or fingerprint produces a miss without lock acquisition —
// the protect path uses an empty fingerprint when WASM is unavailable, and
// we never want to share a slot across rules whose IDs failed to compute.
func (c *ruleCache) get(ruleID, fingerprint string) *decidev1.RuleResult {
	if c == nil || ruleID == "" || fingerprint == "" {
		return nil
	}
	key := ruleCacheKey{ruleID: ruleID, fingerprint: fingerprint}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !entry.expiresAt.After(now) {
		delete(c.entries, key)
		return nil
	}
	cloned, ok := proto.Clone(entry.result).(*decidev1.RuleResult)
	if !ok {
		return nil
	}
	remaining := time.Until(entry.expiresAt).Round(time.Second) / time.Second
	ttl := safeUint32(int(remaining))
	if ttl == 0 {
		ttl = 1
	}
	cloned.State = decidev1.RuleState_RULE_STATE_CACHED
	cloned.Ttl = ttl
	cloned.Fingerprint = fingerprint
	return cloned
}

// set stores a rule result if it is an enforced DENY with TTL > 0. DRY_RUN
// results are skipped — they don't enforce, so caching them would suppress
// the next request's evaluation without producing any user-visible effect.
// ALLOW / CHALLENGE / ERROR are skipped to match JS, which only effectively
// caches DENY (other conclusions are written with TTL 0 and therefore not
// cacheable).
func (c *ruleCache) set(ruleID, fingerprint string, result *decidev1.RuleResult) {
	if c == nil || ruleID == "" || fingerprint == "" || result == nil {
		return
	}
	if result.GetConclusion() != decidev1.Conclusion_CONCLUSION_DENY || result.GetTtl() == 0 {
		return
	}
	if result.GetState() != decidev1.RuleState_RULE_STATE_RUN {
		return
	}
	cloned, ok := proto.Clone(result).(*decidev1.RuleResult)
	if !ok {
		return
	}
	key := ruleCacheKey{ruleID: ruleID, fingerprint: fingerprint}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = ruleCacheEntry{
		result:    cloned,
		expiresAt: time.Now().Add(time.Duration(result.GetTtl()) * time.Second),
	}
}

// decisionFromRuleResult wraps a cached RuleResult in the *localDecision
// shape the rest of the protect flow expects. Used after a cache hit so
// the aggregation path doesn't need to know whether the rule ran or was
// served from cache. Cached results are always live DENY (see set's
// guards), so the outer conclusion matches the result's.
func decisionFromRuleResult(result *decidev1.RuleResult) *localDecision {
	return wrapRuleResult(result, result.GetConclusion())
}

// wrapRuleResult builds a *localDecision around one RuleResult with an
// explicit outer conclusion. Both decisionFromRuleResult (cached DENY,
// outer = result.Conclusion) and localDeny (fresh evaluation, outer may
// be ALLOW when the rule is in dry-run mode) delegate here so the
// shared scaffolding — fresh ID, single-element RuleResults slice, TTL
// pass-through — has one definition.
func wrapRuleResult(result *decidev1.RuleResult, outer decidev1.Conclusion) *localDecision {
	return &localDecision{decision: &decidev1.Decision{
		Id:          newTypeID("lreq"),
		Conclusion:  outer,
		Reason:      result.GetReason(),
		RuleResults: []*decidev1.RuleResult{result},
		Ttl:         result.GetTtl(),
	}}
}
