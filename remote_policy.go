package arcjet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"connectrpc.com/connect"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

var guardPolicyCapabilities = []string{"guard-policy-v1", "local-sensitive-info-v1"}

// GuardPolicyInput is an explicitly exposed, wire-typed remote-policy input.
// It is sealed; values can only be made by the constructors below.
type GuardPolicyInput interface{ guardPolicyInput() policyInputValue }

type policyInput struct{ value policyInputValue }
type policyInputValue struct {
	kind  decidev2.GuardPolicyInputKind
	local bool
	value any
}

func (p policyInput) guardPolicyInput() policyInputValue { return p.value }

// GuardPolicyServerString creates a server-exposed string policy input.
func GuardPolicyServerString(v string) GuardPolicyInput {
	return policyInput{policyInputValue{decidev2.GuardPolicyInputKind_GUARD_POLICY_INPUT_KIND_STRING, false, v}}
}

// GuardPolicyServerBoolean creates a server-exposed boolean policy input.
func GuardPolicyServerBoolean(v bool) GuardPolicyInput {
	return policyInput{policyInputValue{decidev2.GuardPolicyInputKind_GUARD_POLICY_INPUT_KIND_BOOLEAN, false, v}}
}

// GuardPolicyServerInteger creates a server-exposed signed integer policy input.
func GuardPolicyServerInteger(v int64) GuardPolicyInput {
	return policyInput{policyInputValue{decidev2.GuardPolicyInputKind_GUARD_POLICY_INPUT_KIND_INTEGER, false, v}}
}

// GuardPolicyServerNumber creates a server-exposed floating-point policy input.
// Non-finite values are rejected by [GuardClient.Guard].
func GuardPolicyServerNumber(v float64) GuardPolicyInput {
	return policyInput{policyInputValue{decidev2.GuardPolicyInputKind_GUARD_POLICY_INPUT_KIND_NUMBER, false, v}}
}

// GuardPolicyServerStringList creates a server-exposed string-list policy input.
// The slice is copied so later caller mutations do not alter the input.
func GuardPolicyServerStringList(v []string) GuardPolicyInput {
	return policyInput{policyInputValue{decidev2.GuardPolicyInputKind_GUARD_POLICY_INPUT_KIND_STRING_LIST, false, append([]string(nil), v...)}}
}

// GuardPolicyLocalString keeps v in process. Only a domain-separated digest is sent.
func GuardPolicyLocalString(v string) GuardPolicyInput {
	return policyInput{policyInputValue{decidev2.GuardPolicyInputKind_GUARD_POLICY_INPUT_KIND_STRING, true, v}}
}

func localPolicyDigest(value string) []byte {
	prefix := append([]byte("arcjet.guard.policy-input.v1"), 0)
	b := make([]byte, len(prefix)+4+len(value))
	copy(b, prefix)
	// wirePolicyInputs validates the protocol's uint32 byte-length bound before
	// calling this for application input.
	binary.BigEndian.PutUint32(b[len(prefix):], uint32(len(value))) //nolint:gosec // protocol bound checked by caller
	copy(b[len(prefix)+4:], value)
	sum := sha256.Sum256(b)
	return sum[:]
}

type policyCacheEntry struct {
	status    decidev2.GuardPolicyLookupStatus
	policy    *decidev2.GuardLocalPolicyProjection
	refreshAt time.Time
}
type policyFetch struct {
	done   chan struct{}
	result policyCacheEntry
}

const guardPolicyFetchTimeout = 2 * time.Second

var guardPolicyNow = time.Now
var guardPolicyJitter = rand.Float64

type remotePolicyRuntime struct {
	mu             sync.Mutex
	cache          map[string]policyCacheEntry
	inflight       map[string]*policyFetch
	client         decidePolicyClient
	key, userAgent string
	local          *localEvaluator
	backend        SensitiveInfoBackend
}
type decidePolicyClient interface {
	GetGuardPolicy(context.Context, *connect.Request[decidev2.GetGuardPolicyRequest]) (*connect.Response[decidev2.GetGuardPolicyResponse], error)
}

func newRemotePolicyRuntime(client decidePolicyClient, key, ua string, local *localEvaluator, backend SensitiveInfoBackend) *remotePolicyRuntime {
	return &remotePolicyRuntime{cache: make(map[string]policyCacheEntry), inflight: make(map[string]*policyFetch), client: client, key: key, userAgent: ua, local: local, backend: backend}
}

func (r *remotePolicyRuntime) get(ctx context.Context, label string, force bool) (policyCacheEntry, error) {
	r.mu.Lock()
	old, ok := r.cache[label]
	if !force && ok && guardPolicyNow().Before(old.refreshAt) {
		r.mu.Unlock()
		return old, nil
	}
	if f := r.inflight[label]; f != nil {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return old, ctx.Err()
		case <-f.done:
			return f.result, nil
		}
	}
	f := &policyFetch{done: make(chan struct{})}
	r.inflight[label] = f
	r.mu.Unlock()
	// The shared fetch must outlive any one waiter; fetch applies its own
	// bounded context so this cannot leak an unbounded goroutine.
	go r.fetch(context.WithoutCancel(ctx), label, old, ok, f)
	select {
	case <-ctx.Done():
		return old, ctx.Err()
	case <-f.done:
		return f.result, nil
	}
}

func (r *remotePolicyRuntime) fetch(parent context.Context, label string, old policyCacheEntry, hadOld bool, f *policyFetch) {
	ctx, cancel := context.WithTimeout(parent, guardPolicyFetchTimeout)
	defer cancel()
	req := connect.NewRequest(&decidev2.GetGuardPolicyRequest{UserAgent: r.userAgent, Label: label, PolicyCapabilities: guardPolicyCapabilities})
	req.Header().Set("Authorization", "Bearer "+r.key)
	req.Header().Set("User-Agent", r.userAgent)
	resp, err := r.client.GetGuardPolicy(ctx, req)
	now := guardPolicyNow()
	result := old
	if err == nil && resp != nil && resp.Msg != nil && resp.Msg.GetStatus() == decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED {
		result = policyCacheEntry{status: resp.Msg.GetStatus(), refreshAt: now.Add(5 * time.Minute)}
	} else if err == nil && resp != nil && resp.Msg != nil && resp.Msg.GetStatus() == decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_AVAILABLE && resp.Msg.GetPolicy() != nil {
		result = policyCacheEntry{status: resp.Msg.GetStatus(), policy: resp.Msg.GetPolicy(), refreshAt: now.Add(5 * time.Minute)}
	} else if hadOld {
		result.refreshAt = now.Add(5 * time.Minute)
	} else {
		delay := time.Duration(float64(5*time.Second) * (0.8 + 0.4*guardPolicyJitter()))
		result = policyCacheEntry{status: decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_UNAVAILABLE, refreshAt: now.Add(delay)}
	}
	r.mu.Lock()
	r.cache[label] = result
	f.result = result
	delete(r.inflight, label)
	close(f.done)
	r.mu.Unlock()
}

var guardPolicyEntityTypes = map[EntityType]struct{}{
	SensitiveInfoEmail:            {},
	SensitiveInfoPhoneNumber:      {},
	SensitiveInfoIPAddress:        {},
	SensitiveInfoCreditCardNumber: {},
	SensitiveInfoURL:              {},
	SensitiveInfoSSN:              {},
	SensitiveInfoGivenName:        {},
	SensitiveInfoSurname:          {},
	SensitiveInfoTaxID:            {},
	SensitiveInfoBankAccount:      {},
	SensitiveInfoRoutingNumber:    {},
	SensitiveInfoGovernmentID:     {},
	SensitiveInfoPassport:         {},
	SensitiveInfoDriversLicense:   {},
	SensitiveInfoBuildingNumber:   {},
	SensitiveInfoStreetName:       {},
	SensitiveInfoSecondaryAddress: {},
	SensitiveInfoCity:             {},
	SensitiveInfoState:            {},
	SensitiveInfoZipCode:          {},
}

func wirePolicyInputs(inputs map[string]GuardPolicyInput) (map[string]*decidev2.GuardPolicyInput, map[string]policyInputValue, bool, error) {
	wire := make(map[string]*decidev2.GuardPolicyInput, len(inputs))
	values := make(map[string]policyInputValue, len(inputs))
	local := false
	for name, in := range inputs {
		if in == nil {
			return nil, nil, false, fmt.Errorf("arcjet: guard policy input %q is nil: %w", name, ErrInvalidPolicyInput)
		}
		v := in.guardPolicyInput()
		values[name] = v
		if v.local {
			value, ok := v.value.(string)
			if !ok {
				return nil, nil, false, fmt.Errorf("arcjet: guard policy input %q has invalid local value: %w", name, ErrInvalidPolicyInput)
			}
			if uint64(len(value)) > uint64(math.MaxUint32) {
				return nil, nil, false, fmt.Errorf("arcjet: guard policy input %q exceeds the local string size limit: %w", name, ErrInvalidPolicyInput)
			}
			local = true
			wire[name] = &decidev2.GuardPolicyInput{Representation: &decidev2.GuardPolicyInput_Local{Local: &decidev2.GuardPolicyLocalInput{Kind: v.kind, ValueSha256: localPolicyDigest(value)}}}
			continue
		}
		s := &decidev2.GuardPolicyServerInput{}
		switch x := v.value.(type) {
		case string:
			s.Value = &decidev2.GuardPolicyServerInput_StringValue{StringValue: x}
		case bool:
			s.Value = &decidev2.GuardPolicyServerInput_BooleanValue{BooleanValue: x}
		case int64:
			s.Value = &decidev2.GuardPolicyServerInput_IntegerValue{IntegerValue: x}
		case float64:
			if math.IsNaN(x) || math.IsInf(x, 0) {
				return nil, nil, false, fmt.Errorf("arcjet: guard policy input %q must be finite: %w", name, ErrInvalidPolicyInput)
			}
			s.Value = &decidev2.GuardPolicyServerInput_NumberValue{NumberValue: x}
		case []string:
			s.Value = &decidev2.GuardPolicyServerInput_StringListValue{StringListValue: &decidev2.GuardStringList{Values: append([]string(nil), x...)}}
		default:
			return nil, nil, false, fmt.Errorf("arcjet: guard policy input %q has invalid value: %w", name, ErrInvalidPolicyInput)
		}
		wire[name] = &decidev2.GuardPolicyInput{Representation: &decidev2.GuardPolicyInput_Server{Server: s}}
	}
	return wire, values, local, nil
}

func (r *remotePolicyRuntime) prepare(ctx context.Context, label string, inputs map[string]GuardPolicyInput, force bool) (map[string]*decidev2.GuardPolicyInput, string, []*decidev2.GuardLocalPolicyResult, bool, error) {
	wire, values, hasLocal, err := wirePolicyInputs(inputs)
	if err != nil {
		return nil, "", nil, false, err
	}
	if !hasLocal {
		return wire, "", nil, false, nil
	}
	entry, err := r.get(ctx, label, force)
	if err != nil {
		return wire, "", nil, true, err
	}
	if entry.policy == nil {
		return wire, "", nil, true, nil
	}
	results := r.localResults(ctx, entry.policy, values)
	return wire, entry.policy.GetRevision(), results, true, nil
}

func (r *remotePolicyRuntime) localResults(ctx context.Context, policy *decidev2.GuardLocalPolicyProjection, values map[string]policyInputValue) []*decidev2.GuardLocalPolicyResult {
	rules := policy.GetSensitiveInfoRules()
	results := make([]*decidev2.GuardLocalPolicyResult, 0, len(rules))
	for _, rule := range rules {
		v, ok := values[rule.GetInputName()]
		if !ok || !v.local {
			continue
		}
		text, ok := v.value.(string)
		if !ok {
			continue
		}
		results = append(results, r.localResult(ctx, policy, rule, text))
	}
	return results
}

func (r *remotePolicyRuntime) localResult(ctx context.Context, policy *decidev2.GuardLocalPolicyProjection, rule *decidev2.GuardLocalSensitiveInfoRule, text string) *decidev2.GuardLocalPolicyResult {
	var allow, deny []EntityType
	if e := rule.GetEntitiesAllow(); e != nil {
		for _, entity := range e.GetEntities() {
			allow = append(allow, EntityType(entity))
		}
	}
	if e := rule.GetEntitiesDeny(); e != nil {
		for _, entity := range e.GetEntities() {
			deny = append(deny, EntityType(entity))
		}
	}
	result := &decidev2.GuardLocalPolicyResult{
		PolicyId:       policy.GetPolicyId(),
		PolicyRevision: policy.GetRevision(),
		RuleId:         rule.GetRuleId(),
		InputName:      rule.GetInputName(),
		ValueSha256:    localPolicyDigest(text),
		Type:           decidev2.GuardRuleType_GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO,
	}
	outcome, err := r.local.scanSensitiveInfo(ctx, text, allow, deny, r.backend)
	if err != nil {
		result.Result = &decidev2.GuardLocalPolicyResult_Error{Error: &decidev2.ResultError{Code: "LOCAL_POLICY_ERROR", Message: "local policy evaluation failed"}}
		return result
	}

	entities := make([]*decidev2.GuardSensitiveInfoEntity, 0, len(outcome.Denied))
	deniedTypes := make([]string, 0, len(outcome.Denied))
	seen := make(map[EntityType]struct{})
	for _, entity := range outcome.Denied {
		if _, recognized := guardPolicyEntityTypes[entity.IdentifiedType]; !recognized {
			continue
		}
		entities = append(entities, &decidev2.GuardSensitiveInfoEntity{Type: string(entity.IdentifiedType), Start: entity.Start, End: entity.End})
		if _, duplicate := seen[entity.IdentifiedType]; !duplicate {
			deniedTypes = append(deniedTypes, string(entity.IdentifiedType))
			seen[entity.IdentifiedType] = struct{}{}
		}
	}
	conclusion := decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW
	if len(entities) > 0 {
		conclusion = decidev2.GuardConclusion_GUARD_CONCLUSION_DENY
	}
	result.DurationMs = &outcome.ElapsedMs
	result.Result = &decidev2.GuardLocalPolicyResult_LocalSensitiveInfo{LocalSensitiveInfo: &decidev2.ResultLocalSensitiveInfo{
		Conclusion: conclusion,
		// Policy evidence is denied-only: allowed detections remain local and
		// do not set detected or cross the SDK boundary.
		Detected:            len(entities) > 0,
		DetectedEntityTypes: deniedTypes,
		DetectedEntities:    entities,
	}}
	return result
}
