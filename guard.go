package arcjet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"go.jetify.com/typeid"
	"google.golang.org/protobuf/encoding/protojson"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

// GuardConfig configures a GuardClient.
type GuardConfig struct {
	// Key is the Arcjet site key. If empty, ARCJET_KEY is used.
	Key string
	// HTTPClient is the client used for Arcjet RPCs. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
	// BaseURL overrides the Arcjet Guard API base URL.
	BaseURL string
	// SDKVersion overrides the version reported to Arcjet.
	SDKVersion string
	// SensitiveInfoDetect, if set, classifies tokens the bundled analyzer
	// didn't recognise. Shared across every GuardSensitiveInfo rule on
	// this client.
	SensitiveInfoDetect SensitiveInfoDetect
}

// GuardClient evaluates non-HTTP inputs such as tool calls, jobs, and queues.
//
// A GuardClient is safe for concurrent use and should be created once at
// startup.
type GuardClient struct {
	key         string
	guardClient decidev2connect.DecideServiceClient
	userAgent   string
	local       *localEvaluator
}

// NewGuardClient creates a reusable Guard client.
//
// If GuardConfig.Key is empty, NewGuardClient reads ARCJET_KEY from the
// environment.
func NewGuardClient(cfg GuardConfig) (*GuardClient, error) {
	key := cfg.Key
	if key == "" {
		key = os.Getenv("ARCJET_KEY")
	}
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("arcjet: %w", ErrMissingKey)
	}
	version := cfg.SDKVersion
	if version == "" {
		version = Version
	}
	baseURL := defaultBaseURL(cfg.BaseURL)
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	ua := userAgent("arcjet-guard-go", version)
	return &GuardClient{
		key:         key,
		userAgent:   ua,
		guardClient: decidev2connect.NewDecideServiceClient(httpClient, baseURL),
		// Lazy: only Guard rules that evaluate locally (today just
		// sensitive info) trigger wasm compilation.
		local: newLazyLocalEvaluator(cfg.SensitiveInfoDetect),
	}, nil
}

// Close releases the locally-compiled wasm factory, if any. Safe to call
// even if no local Guard rule was ever used.
func (c *GuardClient) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return c.local.close(ctx)
}

// GuardRequest is a single Guard evaluation request.
type GuardRequest struct {
	// Label identifies this Guard call.
	Label string
	// Metadata is optional key-value metadata for this Guard call.
	Metadata map[string]string
	// Rules are bound rule inputs evaluated by Guard.
	Rules []GuardRuleInput
}

// Guard evaluates bound guard rule inputs.
func (c *GuardClient) Guard(ctx context.Context, req GuardRequest) (GuardDecision, error) {
	if c == nil {
		return GuardDecision{}, fmt.Errorf("arcjet: %w", ErrNilClient)
	}
	if err := validateGuardLabel(req.Label); err != nil {
		return GuardDecision{}, err
	}
	start := time.Now()
	submissions := make([]*decidev2.GuardRuleSubmission, 0, len(req.Rules))
	for _, rule := range req.Rules {
		if rule == nil {
			return GuardDecision{}, fmt.Errorf("arcjet: guard request: %w", ErrNilRule)
		}
		wireSub, err := rule.guardSubmission(ctx, c.local)
		if err != nil {
			return GuardDecision{}, err
		}
		if wireSub.Rule == nil {
			// No-op rule input (e.g. an analyzer that isn't shipped yet).
			continue
		}
		data, err := jsonMarshal(wireSub)
		if err != nil {
			return GuardDecision{}, err
		}
		var sub decidev2.GuardRuleSubmission
		if err := protojson.Unmarshal(data, &sub); err != nil {
			return GuardDecision{}, err
		}
		submissions = append(submissions, &sub)
	}
	elapsed := safeUint64FromInt64(time.Since(start).Milliseconds())
	sentAt := safeUint64FromInt64(time.Now().UnixMilli())

	wireReq := &decidev2.GuardRequest{
		UserAgent:           c.userAgent,
		LocalEvalDurationMs: &elapsed,
		SentAtUnixMs:        &sentAt,
		Label:               req.Label,
		Metadata:            cloneMap(req.Metadata),
		RuleSubmissions:     submissions,
	}

	connectReq := connect.NewRequest(wireReq)
	connectReq.Header().Set("Authorization", "Bearer "+c.key)
	connectReq.Header().Set("User-Agent", c.userAgent)
	resp, err := c.guardClient.Guard(ctx, connectReq)
	if err != nil {
		return GuardDecision{}, err
	}
	return guardDecisionFromProto(resp.Msg), nil
}

// GuardRuleInput is a rule bound to runtime input for a Guard call.
//
// The unexported `guardSubmission` method seals the interface so external
// types can't implement it; SDK-provided rules use it to build the wire
// submission, optionally running locally via the shared evaluator.
type GuardRuleInput interface {
	guardSubmission(ctx context.Context, eval *localEvaluator) (guardRuleSubmissionWire, error)
}

type guardRuleBase struct {
	configID string
	label    string
	metadata map[string]string
	mode     Mode
}

func newGuardRuleBase(mode Mode, label string, metadata map[string]string) (guardRuleBase, error) {
	if err := validateMode(mode); err != nil {
		return guardRuleBase{}, err
	}
	if label != "" {
		if err := validateGuardLabel(label); err != nil {
			return guardRuleBase{}, err
		}
	}
	return guardRuleBase{
		configID: newTypeID("gcfg"),
		label:    label,
		metadata: cloneMap(metadata),
		mode:     normalizeMode(mode),
	}, nil
}

func newInputID() string {
	return newTypeID("ginp")
}

func newTypeID(prefix string) string {
	id, err := typeid.WithPrefix(prefix)
	if err != nil {
		panic("arcjet: invalid static typeid prefix: " + err.Error())
	}
	return id.String()
}

func (b guardRuleBase) submission(rule map[string]any) guardRuleSubmissionWire {
	sub := guardRuleSubmissionWire{
		ConfigID: b.configID,
		InputID:  newInputID(),
		Rule:     rule,
		Mode:     guardMode(b.mode),
		Metadata: cloneMap(b.metadata),
	}
	if b.label != "" {
		sub.Label = &b.label
	}
	return sub
}

// GuardTokenBucketOptions configures a Guard token bucket rule.
type GuardTokenBucketOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// RefillRate is the number of tokens added per interval.
	RefillRate int
	// Interval is the token refill interval.
	Interval time.Duration
	// Capacity is the maximum bucket size.
	Capacity int
	// Bucket groups counters for this rule.
	Bucket string
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule.
	Metadata map[string]string
}

// GuardTokenBucketRule is a configured Guard token bucket rule.
type GuardTokenBucketRule struct {
	base            guardRuleBase
	refillRate      uint32
	intervalSeconds uint32
	capacity        uint32
	bucket          string
}

// GuardTokenBucket creates a Guard token bucket rule.
func GuardTokenBucket(opts GuardTokenBucketOptions) (*GuardTokenBucketRule, error) {
	base, err := newGuardRuleBase(opts.Mode, opts.Label, opts.Metadata)
	if err != nil {
		return nil, err
	}
	if opts.RefillRate <= 0 || opts.Interval <= 0 || opts.Capacity <= 0 {
		return nil, fmt.Errorf("arcjet: guard token bucket requires positive refill rate, interval, and capacity: %w", ErrInvalidRateLimit)
	}
	bucket := opts.Bucket
	if bucket == "" {
		bucket = "default"
	}
	if err := validateGuardLabel(bucket); err != nil {
		return nil, fmt.Errorf("arcjet: guard token bucket: bucket name must be a label-like slug: %w", ErrInvalidLabel)
	}
	return &GuardTokenBucketRule{
		base:            base,
		refillRate:      safeUint32(opts.RefillRate),
		intervalSeconds: seconds(opts.Interval),
		capacity:        safeUint32(opts.Capacity),
		bucket:          bucket,
	}, nil
}

// Key binds a token bucket key and requested token count for one Guard call.
func (r *GuardTokenBucketRule) Key(key string, requested int) GuardRuleInput {
	return guardRuleInputFunc(func(_ context.Context, _ *localEvaluator) (guardRuleSubmissionWire, error) {
		if key == "" {
			return guardRuleSubmissionWire{}, fmt.Errorf("arcjet: guard token bucket: %w", ErrEmptyKey)
		}
		if requested <= 0 {
			requested = 1
		}
		return r.base.submission(map[string]any{"tokenBucket": map[string]any{
			"configRefillRate":      r.refillRate,
			"configIntervalSeconds": r.intervalSeconds,
			"configMaxTokens":       r.capacity,
			"configBucket":          r.bucket,
			"inputKeyHash":          hashKey(key),
			"inputRequested":        safeUint32(requested),
		}}), nil
	})
}

// Result returns this rule's token bucket result from the given Guard
// decision, or nil if the rule did not produce one.
func (r *GuardTokenBucketRule) Result(d GuardDecision) *GuardTokenBucketResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.TokenBucket != nil {
			return res.TokenBucket
		}
	}
	return nil
}

// DeniedResult returns this rule's token bucket result if it denied the Guard
// call, or nil otherwise. Useful for reading reset and remaining-token
// information when returning a "rate limited" response to the caller.
func (r *GuardTokenBucketRule) DeniedResult(d GuardDecision) *GuardTokenBucketResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.IsDenied() && res.TokenBucket != nil {
			return res.TokenBucket
		}
	}
	return nil
}

// GuardFixedWindowOptions configures a Guard fixed window rule.
type GuardFixedWindowOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Window is the fixed window duration.
	Window time.Duration
	// MaxRequests is the maximum number of requests per window.
	MaxRequests int
	// Bucket groups counters for this rule.
	Bucket string
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule.
	Metadata map[string]string
}

// GuardFixedWindowRule is a configured Guard fixed window rule.
type GuardFixedWindowRule struct {
	base          guardRuleBase
	windowSeconds uint32
	maxRequests   uint32
	bucket        string
}

// GuardFixedWindow creates a Guard fixed window rule.
func GuardFixedWindow(opts GuardFixedWindowOptions) (*GuardFixedWindowRule, error) {
	base, err := newGuardRuleBase(opts.Mode, opts.Label, opts.Metadata)
	if err != nil {
		return nil, err
	}
	if opts.Window <= 0 || opts.MaxRequests <= 0 {
		return nil, fmt.Errorf("arcjet: guard fixed window requires positive window and max requests: %w", ErrInvalidRateLimit)
	}
	bucket := opts.Bucket
	if bucket == "" {
		bucket = "default"
	}
	if err := validateGuardLabel(bucket); err != nil {
		return nil, fmt.Errorf("arcjet: guard fixed window bucket must be a label-like slug: %w", ErrInvalidLabel)
	}
	return &GuardFixedWindowRule{base: base, windowSeconds: seconds(opts.Window), maxRequests: safeUint32(opts.MaxRequests), bucket: bucket}, nil
}

// Key binds a fixed window key and requested count for one Guard call.
func (r *GuardFixedWindowRule) Key(key string, requested int) GuardRuleInput {
	return guardRuleInputFunc(func(_ context.Context, _ *localEvaluator) (guardRuleSubmissionWire, error) {
		if key == "" {
			return guardRuleSubmissionWire{}, fmt.Errorf("arcjet: guard fixed window: %w", ErrEmptyKey)
		}
		if requested <= 0 {
			requested = 1
		}
		return r.base.submission(map[string]any{"fixedWindow": map[string]any{
			"configMaxRequests":   r.maxRequests,
			"configWindowSeconds": r.windowSeconds,
			"configBucket":        r.bucket,
			"inputKeyHash":        hashKey(key),
			"inputRequested":      safeUint32(requested),
		}}), nil
	})
}

// Result returns this rule's fixed window result from the given Guard
// decision, or nil if the rule did not produce one.
func (r *GuardFixedWindowRule) Result(d GuardDecision) *GuardFixedWindowResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.FixedWindow != nil {
			return res.FixedWindow
		}
	}
	return nil
}

// DeniedResult returns this rule's fixed window result if it denied the Guard
// call, or nil otherwise.
func (r *GuardFixedWindowRule) DeniedResult(d GuardDecision) *GuardFixedWindowResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.IsDenied() && res.FixedWindow != nil {
			return res.FixedWindow
		}
	}
	return nil
}

// GuardSlidingWindowOptions configures a Guard sliding window rule.
type GuardSlidingWindowOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Interval is the sliding window interval.
	Interval time.Duration
	// MaxRequests is the maximum number of requests per interval.
	MaxRequests int
	// Bucket groups counters for this rule.
	Bucket string
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule.
	Metadata map[string]string
}

// GuardSlidingWindowRule is a configured Guard sliding window rule.
type GuardSlidingWindowRule struct {
	base            guardRuleBase
	intervalSeconds uint32
	maxRequests     uint32
	bucket          string
}

// GuardSlidingWindow creates a Guard sliding window rule.
func GuardSlidingWindow(opts GuardSlidingWindowOptions) (*GuardSlidingWindowRule, error) {
	base, err := newGuardRuleBase(opts.Mode, opts.Label, opts.Metadata)
	if err != nil {
		return nil, err
	}
	if opts.Interval <= 0 || opts.MaxRequests <= 0 {
		return nil, fmt.Errorf("arcjet: guard sliding window requires positive interval and max requests: %w", ErrInvalidRateLimit)
	}
	bucket := opts.Bucket
	if bucket == "" {
		bucket = "default"
	}
	if err := validateGuardLabel(bucket); err != nil {
		return nil, fmt.Errorf("arcjet: guard sliding window bucket must be a label-like slug: %w", ErrInvalidLabel)
	}
	return &GuardSlidingWindowRule{base: base, intervalSeconds: seconds(opts.Interval), maxRequests: safeUint32(opts.MaxRequests), bucket: bucket}, nil
}

// Key binds a sliding window key and requested count for one Guard call.
func (r *GuardSlidingWindowRule) Key(key string, requested int) GuardRuleInput {
	return guardRuleInputFunc(func(_ context.Context, _ *localEvaluator) (guardRuleSubmissionWire, error) {
		if key == "" {
			return guardRuleSubmissionWire{}, fmt.Errorf("arcjet: guard sliding window: %w", ErrEmptyKey)
		}
		if requested <= 0 {
			requested = 1
		}
		return r.base.submission(map[string]any{"slidingWindow": map[string]any{
			"configMaxRequests":     r.maxRequests,
			"configIntervalSeconds": r.intervalSeconds,
			"configBucket":          r.bucket,
			"inputKeyHash":          hashKey(key),
			"inputRequested":        safeUint32(requested),
		}}), nil
	})
}

// Result returns this rule's sliding window result from the given Guard
// decision, or nil if the rule did not produce one.
func (r *GuardSlidingWindowRule) Result(d GuardDecision) *GuardSlidingWindowResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.SlidingWindow != nil {
			return res.SlidingWindow
		}
	}
	return nil
}

// DeniedResult returns this rule's sliding window result if it denied the
// Guard call, or nil otherwise.
func (r *GuardSlidingWindowRule) DeniedResult(d GuardDecision) *GuardSlidingWindowResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.IsDenied() && res.SlidingWindow != nil {
			return res.SlidingWindow
		}
	}
	return nil
}

// GuardPromptInjectionOptions configures a Guard prompt injection rule.
type GuardPromptInjectionOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule.
	Metadata map[string]string
}

// GuardPromptInjectionRule is a configured Guard prompt injection rule.
type GuardPromptInjectionRule struct {
	base guardRuleBase
}

// GuardPromptInjection creates a Guard prompt injection rule.
func GuardPromptInjection(opts GuardPromptInjectionOptions) (*GuardPromptInjectionRule, error) {
	base, err := newGuardRuleBase(opts.Mode, opts.Label, opts.Metadata)
	if err != nil {
		return nil, err
	}
	return &GuardPromptInjectionRule{base: base}, nil
}

// Text binds text to scan for one Guard call.
func (r *GuardPromptInjectionRule) Text(text string) GuardRuleInput {
	return guardRuleInputFunc(func(_ context.Context, _ *localEvaluator) (guardRuleSubmissionWire, error) {
		return r.base.submission(map[string]any{"detectPromptInjection": map[string]any{
			"inputText": text,
		}}), nil
	})
}

// Result returns this rule's prompt injection result from the given Guard
// decision, or nil if the rule did not produce one.
func (r *GuardPromptInjectionRule) Result(d GuardDecision) *GuardPromptResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.PromptInjection != nil {
			return res.PromptInjection
		}
	}
	return nil
}

// DeniedResult returns this rule's prompt injection result if it denied the
// Guard call, or nil otherwise.
func (r *GuardPromptInjectionRule) DeniedResult(d GuardDecision) *GuardPromptResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.IsDenied() && res.PromptInjection != nil {
			return res.PromptInjection
		}
	}
	return nil
}

// GuardSensitiveInfoOptions configures local Guard sensitive information detection.
type GuardSensitiveInfoOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Allow lists entity types allowed in scanned text.
	Allow []EntityType
	// Deny lists entity types denied in scanned text.
	Deny []EntityType
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule.
	Metadata map[string]string
}

// GuardSensitiveInfoRule is a configured local Guard sensitive information rule.
type GuardSensitiveInfoRule struct {
	base  guardRuleBase
	allow []EntityType
	deny  []EntityType
}

// GuardSensitiveInfo creates a local Guard sensitive information rule.
func GuardSensitiveInfo(opts GuardSensitiveInfoOptions) (*GuardSensitiveInfoRule, error) {
	base, err := newGuardRuleBase(opts.Mode, opts.Label, opts.Metadata)
	if err != nil {
		return nil, err
	}
	if len(opts.Allow) > 0 && len(opts.Deny) > 0 {
		return nil, fmt.Errorf("arcjet: guard sensitive info: %w", ErrAllowDenyConflict)
	}
	return &GuardSensitiveInfoRule{
		base:  base,
		allow: append([]EntityType(nil), opts.Allow...),
		deny:  append([]EntityType(nil), opts.Deny...),
	}, nil
}

// Result returns this rule's sensitive information result from the given
// Guard decision, or nil if the rule did not produce one.
func (r *GuardSensitiveInfoRule) Result(d GuardDecision) *GuardSensitiveInfoResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.LocalSensitiveInfo != nil {
			return res.LocalSensitiveInfo
		}
	}
	return nil
}

// DeniedResult returns this rule's sensitive information result if it denied
// the Guard call, or nil otherwise.
func (r *GuardSensitiveInfoRule) DeniedResult(d GuardDecision) *GuardSensitiveInfoResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.IsDenied() && res.LocalSensitiveInfo != nil {
			return res.LocalSensitiveInfo
		}
	}
	return nil
}

// Text binds text to scan for one Guard call.
//
// Detection runs locally via the bundled WebAssembly analyzer (the same
// `arcjet_analyze_js_req` component used by arcjet-js and arcjet-py); the
// text never leaves the SDK. The submission carries a SHA-256 hash of the
// text alongside the locally-computed result so the server can correlate
// inputs without seeing the raw value.
func (r *GuardSensitiveInfoRule) Text(text string) GuardRuleInput {
	allow := append([]EntityType(nil), r.allow...)
	deny := append([]EntityType(nil), r.deny...)
	return guardRuleInputFunc(func(ctx context.Context, eval *localEvaluator) (guardRuleSubmissionWire, error) {
		payload := map[string]any{
			"inputTextHash": sha256Hex(text),
		}
		switch {
		case len(allow) > 0:
			payload["configEntitiesAllow"] = map[string]any{"entities": stringSlice(allow)}
		case len(deny) > 0:
			payload["configEntitiesDeny"] = map[string]any{"entities": stringSlice(deny)}
		}
		outcome, err := eval.scanSensitiveInfo(ctx, text, allow, deny)
		if err != nil {
			payload["resultError"] = map[string]any{"message": err.Error(), "code": "AJ1200"}
			return r.base.submission(map[string]any{"localSensitiveInfo": payload}), nil
		}
		denied := identifiedEntityTypes(outcome.Denied)
		conclusion := ConclusionAllow
		if len(denied) > 0 {
			conclusion = ConclusionDeny
		}
		payload["resultComputed"] = map[string]any{
			"conclusion":          guardConclusion(conclusion),
			"detected":            len(denied) > 0,
			"detectedEntityTypes": denied,
		}
		payload["resultDurationMs"] = outcome.ElapsedMs
		return r.base.submission(map[string]any{"localSensitiveInfo": payload}), nil
	})
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// GuardCustomResult is the result returned by a custom local Guard rule.
type GuardCustomResult struct {
	// Conclusion is the custom rule conclusion.
	Conclusion Conclusion
	// Data is optional result data recorded with the custom rule result.
	Data map[string]string
}

// GuardCustomFunc evaluates one custom local Guard rule input.
type GuardCustomFunc func(context.Context, map[string]string) (GuardCustomResult, error)

// GuardCustomOptions configures a custom local Guard rule.
type GuardCustomOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Config is the rule configuration recorded with each invocation.
	Config map[string]string
	// Func is the local evaluation function. Required.
	Func GuardCustomFunc
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule.
	Metadata map[string]string
}

// GuardCustomRule is a configured custom local Guard rule.
type GuardCustomRule struct {
	base   guardRuleBase
	config map[string]string
	fn     GuardCustomFunc
}

// GuardCustom creates a custom local Guard rule.
func GuardCustom(opts GuardCustomOptions) (*GuardCustomRule, error) {
	base, err := newGuardRuleBase(opts.Mode, opts.Label, opts.Metadata)
	if err != nil {
		return nil, err
	}
	if opts.Func == nil {
		return nil, fmt.Errorf("arcjet: %w", ErrMissingFunc)
	}
	return &GuardCustomRule{base: base, config: cloneMap(opts.Config), fn: opts.Func}, nil
}

// Result returns this rule's custom result from the given Guard decision, or
// nil if the rule did not produce one.
func (r *GuardCustomRule) Result(d GuardDecision) *GuardLocalCustomResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.LocalCustom != nil {
			return res.LocalCustom
		}
	}
	return nil
}

// DeniedResult returns this rule's custom result if it denied the Guard call,
// or nil otherwise.
func (r *GuardCustomRule) DeniedResult(d GuardDecision) *GuardLocalCustomResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.IsDenied() && res.LocalCustom != nil {
			return res.LocalCustom
		}
	}
	return nil
}

// Input binds custom rule input data for one Guard call.
func (r *GuardCustomRule) Input(data map[string]string) GuardRuleInput {
	return guardRuleInputFunc(func(ctx context.Context, _ *localEvaluator) (guardRuleSubmissionWire, error) {
		start := time.Now()
		result, err := r.fn(ctx, cloneMap(data))
		duration := safeUint64FromInt64(time.Since(start).Milliseconds())
		payload := map[string]any{
			"configData":       cloneMap(r.config),
			"inputData":        cloneMap(data),
			"resultDurationMs": duration,
		}
		if err != nil {
			payload["resultError"] = map[string]any{"message": err.Error(), "code": "AJ1100"}
		} else {
			if result.Conclusion == "" {
				result.Conclusion = ConclusionAllow
			}
			payload["resultComputed"] = map[string]any{
				"conclusion": guardConclusion(result.Conclusion),
				"data":       cloneMap(result.Data),
			}
		}
		return r.base.submission(map[string]any{"localCustom": payload}), nil
	})
}

type guardRuleInputFunc func(ctx context.Context, eval *localEvaluator) (guardRuleSubmissionWire, error)

func (f guardRuleInputFunc) guardSubmission(ctx context.Context, eval *localEvaluator) (guardRuleSubmissionWire, error) {
	return f(ctx, eval)
}

func hashKey(parts ...string) string {
	// Common case: a single key. sha256.Sum256 returns a value-typed
	// [Size]byte without heap-allocating an internal digest, which is the
	// dominant cost in the variadic loop below.
	var sum [sha256.Size]byte
	if len(parts) == 1 {
		sum = sha256.Sum256([]byte(parts[0]))
	} else {
		h := sha256.New()
		for i, p := range parts {
			if i > 0 {
				h.Write([]byte{0})
			}
			h.Write([]byte(p))
		}
		h.Sum(sum[:0])
	}
	// Encode into a stack buffer so the only heap allocation is the
	// returned string itself; hex.EncodeToString would allocate twice
	// (intermediate slice + string).
	var buf [sha256.Size * 2]byte
	hex.Encode(buf[:], sum[:])
	return string(buf[:])
}

func guardConclusion(c Conclusion) string {
	if c == ConclusionDeny {
		return "GUARD_CONCLUSION_DENY"
	}
	return "GUARD_CONCLUSION_ALLOW"
}

func validateGuardLabel(label string) error {
	if label == "" {
		return fmt.Errorf("%w: required", ErrInvalidLabel)
	}
	if len(label) > 256 {
		return fmt.Errorf("%w: exceeds 256 bytes", ErrInvalidLabel)
	}
	if !isLowerDigit(label[0]) || !isLowerDigit(label[len(label)-1]) {
		return fmt.Errorf("%w: must start and end with a lowercase letter or digit", ErrInvalidLabel)
	}
	for i := range len(label) {
		c := label[i]
		if isLowerDigit(c) || c == '-' || c == '.' {
			continue
		}
		return fmt.Errorf("%w: may contain only lowercase letters, digits, dash, and dot", ErrInvalidLabel)
	}
	return nil
}

func isLowerDigit(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
