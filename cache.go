package arcjet

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"sync"
	"time"

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

// cacheKeyBuf is a reusable accumulator for makeDecisionCacheKey. It pairs a
// growable byte buffer with a scratch slice of map keys so the function
// performs only one allocation per call (the returned string) after the
// pool warms up.
type cacheKeyBuf struct {
	buf  []byte
	keys []string
}

// cacheKeyBufCap bounds the buffer capacity we keep in the pool. A request
// with a very large Body could grow the buffer arbitrarily; capping the
// returned-to-pool capacity keeps memory usage predictable without giving
// up reuse for typical payloads.
const cacheKeyBufCap = 16 * 1024

var cacheKeyBufPool = sync.Pool{
	New: func() any {
		return &cacheKeyBuf{buf: make([]byte, 0, 1024)}
	},
}

// makeDecisionCacheKey returns a stable digest of every input that can change
// an Arcjet decision: each ProtectDetails field, the FilterLocal map, and the
// precomputed rules hash. Inputs are concatenated into a pooled byte buffer
// with uint32 length-prefix framing — preventing boundary aliasing like
// {"a":"bc"} vs {"ab":"c"} — then hashed in one shot. Maps are emitted in
// sorted key order so iteration randomness does not affect the digest.
func makeDecisionCacheKey(details ProtectDetails, rulesHash string, options ProtectOptions) string {
	b, ok := cacheKeyBufPool.Get().(*cacheKeyBuf)
	if !ok {
		// The pool only stores *cacheKeyBuf values, so this branch is
		// unreachable in practice. Fall back to a fresh buffer rather
		// than panicking if a future change ever violates that invariant.
		b = &cacheKeyBuf{buf: make([]byte, 0, 1024)}
	}
	b.buf = b.buf[:0]
	b.keys = b.keys[:0]

	b.appendLenString(details.IP)
	b.appendLenString(details.Method)
	b.appendLenString(details.Protocol)
	b.appendLenString(details.Host)
	b.appendLenString(details.Path)
	b.appendLenStringMap(details.Headers)
	b.appendLenBytes(details.Body)
	b.appendLenString(details.Email)
	b.appendLenString(details.Cookies)
	b.appendLenString(details.Query)
	b.appendLenStringMap(details.Extra)
	b.appendLenStringMap(options.FilterLocal)
	b.appendLenString(rulesHash)

	sum := sha256.Sum256(b.buf)
	var out [sha256.Size * 2]byte
	hex.Encode(out[:], sum[:])

	if cap(b.buf) <= cacheKeyBufCap {
		cacheKeyBufPool.Put(b)
	}
	return string(out[:])
}

func (b *cacheKeyBuf) appendLenString(s string) {
	b.buf = binary.BigEndian.AppendUint32(b.buf, safeUint32(len(s)))
	b.buf = append(b.buf, s...)
}

func (b *cacheKeyBuf) appendLenBytes(p []byte) {
	b.buf = binary.BigEndian.AppendUint32(b.buf, safeUint32(len(p)))
	b.buf = append(b.buf, p...)
}

func (b *cacheKeyBuf) appendLenStringMap(m map[string]string) {
	b.buf = binary.BigEndian.AppendUint32(b.buf, safeUint32(len(m)))
	if len(m) == 0 {
		return
	}
	keys := b.keys[:0]
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		b.appendLenString(k)
		b.appendLenString(m[k])
	}
	b.keys = keys[:0]
}
