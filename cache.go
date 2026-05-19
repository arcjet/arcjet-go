package arcjet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

type decisionCache struct {
	mu      sync.Mutex
	entries map[string]decisionCacheEntry
}

type decisionCacheEntry struct {
	decision  *decidev1.Decision
	expiresAt time.Time
}

func newDecisionCache() *decisionCache {
	return &decisionCache{entries: make(map[string]decisionCacheEntry)}
}

func (c *decisionCache) get(key string) *decidev1.Decision {
	if c == nil || key == "" {
		return nil
	}
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
	cloned, ok := proto.Clone(entry.decision).(*decidev1.Decision)
	if !ok {
		return nil
	}
	cloned.Id = newTypeID("lreq")
	remaining := time.Until(entry.expiresAt).Round(time.Second) / time.Second
	ttl := safeUint32(int(remaining))
	if ttl == 0 {
		ttl = 1
	}
	cloned.Ttl = ttl
	for _, result := range cloned.GetRuleResults() {
		result.State = decidev1.RuleState_RULE_STATE_CACHED
		result.Ttl = ttl
	}
	return cloned
}

func (c *decisionCache) set(key string, decision *decidev1.Decision) {
	if c == nil || key == "" || decision == nil {
		return
	}
	if decision.GetConclusion() != decidev1.Conclusion_CONCLUSION_DENY || decision.GetTtl() == 0 {
		return
	}
	cloned, ok := proto.Clone(decision).(*decidev1.Decision)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = decisionCacheEntry{
		decision:  cloned,
		expiresAt: time.Now().Add(time.Duration(decision.GetTtl()) * time.Second),
	}
}

func makeDecisionCacheKey(details ProtectDetails, rules []*decidev1.Rule, options ProtectOptions) (string, error) {
	ruleJSON := make([]json.RawMessage, 0, len(rules))
	for _, rule := range rules {
		data, err := protojson.Marshal(rule)
		if err != nil {
			return "", err
		}
		ruleJSON = append(ruleJSON, json.RawMessage(data))
	}
	data, err := jsonMarshal(struct {
		Details     ProtectDetails    `json:"details"`
		FilterLocal map[string]string `json:"filterLocal,omitempty"`
		Rules       []json.RawMessage `json:"rules"`
	}{
		Details:     details,
		FilterLocal: options.FilterLocal,
		Rules:       ruleJSON,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
