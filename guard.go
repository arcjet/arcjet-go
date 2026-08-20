package arcjet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"go.jetify.com/typeid"
	"google.golang.org/protobuf/encoding/protojson"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

// GuardConfig configures a GuardClient.
type GuardConfig struct {
	// Key is the Arcjet site key. If empty, ARCJET_KEY is used. This matches
	// [NewClient] and is the intended Go policy: process configuration belongs
	// in the environment. The JavaScript Guard SDK never reads environment
	// variables; the Python Guard SDK requires an explicit key.
	Key string
	// HTTPClient is the client used for Arcjet RPCs. If nil, http.DefaultClient
	// is used, which honors the standard HTTP_PROXY, HTTPS_PROXY, and NO_PROXY
	// environment variables via http.ProxyFromEnvironment. Supply a custom
	// client only if you need different behavior; set its Transport's Proxy to
	// http.ProxyFromEnvironment to preserve outbound proxy support.
	HTTPClient *http.Client
	// BaseURL overrides the Arcjet Guard API base URL.
	BaseURL string
	// SDKVersion overrides the version reported to Arcjet.
	SDKVersion string
	// SensitiveInfoDetect, if set, classifies tokens the bundled analyzer
	// didn't recognise. Shared across every GuardSensitiveInfo rule on
	// this client.
	SensitiveInfoDetect SensitiveInfoDetect
	// SensitiveInfoBackend evaluates sensitive-info rules projected by remote
	// policies. If nil, the bundled WebAssembly analyzer is used.
	SensitiveInfoBackend SensitiveInfoBackend
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
	policy      *remotePolicyRuntime

	deliveryMu        sync.Mutex
	delivery          *captureDelivery
	diagnose          captureDiagnose
	captureQueueSize  int
	captureBatchSize  int
	captureBatchDelay time.Duration
}

// NewGuardClient creates a reusable Guard client.
//
// If GuardConfig.Key is empty, NewGuardClient reads ARCJET_KEY from the
// environment. This matches [NewClient] and is intentional: Go conventionally
// reads process configuration from the environment. The JavaScript Guard SDK
// never reads environment variables, and the Python Guard SDK requires an
// explicit key. There is no ARCJET_ENV / development-mode switch; set
// [Config.Platform] and [WithIPSrc] on the request-protection client to control
// request identity.
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
	client := &GuardClient{
		key:         key,
		userAgent:   ua,
		guardClient: decidev2connect.NewDecideServiceClient(httpClient, baseURL),
		// Lazy: only Guard rules that evaluate locally (today just
		// sensitive info) trigger wasm compilation.
		local: newLazyLocalEvaluator(cfg.SensitiveInfoDetect),
	}
	client.policy = newRemotePolicyRuntime(client.guardClient, key, ua, client.local, cfg.SensitiveInfoBackend)
	return client, nil
}

// Close flushes any buffered capture events, then releases the
// locally-compiled wasm factory, if any. Safe to call even if no local
// Guard rule was ever used and nothing was captured. A nil ctx is treated
// as [context.Background] for the flush (one-second default deadline).
func (c *GuardClient) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.Flush(ctx)
	if ctx == nil {
		ctx = context.Background()
	}
	return c.local.close(ctx)
}

// GuardRequest is a single Guard evaluation request.
type GuardRequest struct {
	// Label identifies this Guard call.
	Label string
	// Actor is an optional actor identity available to remote policies.
	Actor *string
	// Inputs are explicitly typed and exposed values for remote policies.
	Inputs map[string]GuardPolicyInput
	// Metadata is optional metadata for this Guard call: string keys mapped to
	// any JSON-serializable value, including nested maps and slices. Each
	// top-level value is JSON-encoded by the SDK and stored verbatim.
	//
	// Server-enforced limits: 128 top-level keys, 4 KiB per serialized value,
	// 10 levels of nesting, and key names limited to letters, digits, dash,
	// dot, and underscore. Anything over a limit drops that one key and reports
	// it on GuardDecision.Warnings. Nothing here can fail the call or change
	// the decision.
	Metadata Metadata
	// CorrelationId is an optional, caller-supplied opaque identifier used to
	// correlate this Guard call with other Guard and Protect calls that belong
	// to the same workflow, agent run, or multi-step task. Unlike Metadata it
	// is a dedicated, indexable field; it does not affect the decision. Bounded
	// server-side to 256 bytes of printable ASCII; invalid values are dropped.
	CorrelationId string
	// Rules are bound rule inputs evaluated by Guard.
	Rules []GuardRuleInput
}

// Guard evaluates bound guard rule inputs.
//
// Programmer errors (nil client, invalid label, nil rule, or a rule that
// cannot be encoded) return the zero-value decision and a non-nil error —
// callers must handle the error. These are not fail-open: they reflect misuse
// or misconfiguration, not runtime degradation.
//
// Runtime degradation — a transport failure reaching the Decide service — is
// fail-open: the returned decision is a usable ALLOW carrying a synthetic
// errored result (code TRANSPORT_ERROR) alongside the non-nil error. A caller
// that ignores the error still gets a decision where [GuardDecision.HasFailedOpen]
// reports true and [GuardDecision.ErrorResults] surfaces the failure, so a
// fail-closed policy stays honest. A missing or malformed response is also
// fail-open (synthesized by guardDecisionFromProto), but returns a nil error.
func (c *GuardClient) Guard(ctx context.Context, req GuardRequest) (GuardDecision, error) {
	if c == nil {
		return GuardDecision{}, fmt.Errorf("arcjet: %w", ErrNilClient)
	}
	if err := validateGuardLabel(req.Label); err != nil {
		return GuardDecision{}, err
	}
	start := time.Now()
	// Metadata keys the SDK could not encode. These are reported to the server as
	// untrusted local_warnings and surfaced on the decision, so a dropped key is
	// never silent.
	envelopeMetadata, warnings := encodeMetadata(req.Metadata, "")

	prepared, err := c.policy.prepare(ctx, req.Label, req.Inputs, false)
	if err != nil {
		if errors.Is(err, ErrInvalidPolicyInput) {
			return GuardDecision{}, err
		}
		return withLocalWarnings(guardErrorDecision("REMOTE_POLICY_UNAVAILABLE", "remote Guard policy preparation failed"), warnings), err
	}
	if prepared.decision != nil {
		warnings = append(warnings, enforceMetadataBudget([]map[string]string{envelopeMetadata})...)
		return c.reportLocalPolicyDenial(ctx, req, start, envelopeMetadata, prepared, warnings)
	}
	sanitizeInputs := prepared.sanitizeInputs

	submissions := make([]*decidev2.GuardRuleSubmission, 0, len(req.Rules))
	for ruleIndex, rule := range req.Rules {
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
		// Encoded here rather than in submission() because the warning message
		// names the rule by its index, which only this loop knows.
		encoded, ruleWarnings := encodeMetadata(
			wireSub.metadata,
			fmt.Sprintf("rules[%d].", ruleIndex),
		)
		wireSub.MetadataJSON = encoded
		warnings = append(warnings, ruleWarnings...)

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
		MetadataJson:        envelopeMetadata,
		RuleSubmissions:     submissions,
		CorrelationId:       req.CorrelationId,
		PolicyInputs:        prepared.inputs,
		LocalPolicyRevision: prepared.revision,
		LocalPolicyResults:  prepared.results,
		PolicyCapabilities:  guardPolicyCapabilities,
	}
	wireReq.Actor = req.Actor
	if sanitizeInputs {
		wireReq.PolicyInputs = localOnlyPolicyInputs(wireReq.GetPolicyInputs())
	}

	// Trim to the SDK ceiling across every metadata map on the request — the
	// envelope plus one per rule — so an oversized blob cannot push the request
	// past the 1 MiB protocol limit and get it rejected. A rejected request is a
	// fail open, which would let metadata affect the decision.
	budgetMaps := make([]map[string]string, 0, len(submissions)+1)
	budgetMaps = append(budgetMaps, wireReq.GetMetadataJson())
	for _, sub := range submissions {
		budgetMaps = append(budgetMaps, sub.GetMetadataJson())
	}
	warnings = append(warnings, enforceMetadataBudget(budgetMaps)...)
	wireReq.LocalWarnings = warningsToProtoV2(warnings)

	connectReq := connect.NewRequest(wireReq)
	connectReq.Header().Set("Authorization", "Bearer "+c.key)
	connectReq.Header().Set("User-Agent", c.userAgent)
	resp, err := c.guardClient.Guard(ctx, connectReq)
	if err != nil {
		// Fail open: a transport failure is runtime degradation, not a
		// programmer error. Return a usable ALLOW carrying a synthetic errored
		// result so HasFailedOpen()/ErrorResults() flag it even if the caller
		// ignores err.
		return withLocalWarnings(guardErrorDecision("TRANSPORT_ERROR", err.Error()), warnings), err
	}
	// Keep the forced refresh and retry together so a newly projected local
	// denial can sanitize the retry RPC before reporting it.
	//nolint:nestif // the nested branches are the refresh/retry transaction
	if prepared.hasLocal && resp.Msg.GetDecision() != nil && resp.Msg.GetDecision().GetPolicyEvaluation() != nil {
		e := resp.Msg.GetDecision().GetPolicyEvaluation()
		if e.GetRefreshRequired() || (prepared.revision != "" && e.GetRevision() != "" && prepared.revision != e.GetRevision()) {
			prepared, err = c.policy.prepare(ctx, req.Label, req.Inputs, true)
			if err != nil {
				return withLocalWarnings(guardErrorDecision("REMOTE_POLICY_UNAVAILABLE", "remote Guard policy preparation failed"), warnings), err
			}
			sanitizeInputs = sanitizeInputs || prepared.sanitizeInputs
			if prepared.decision != nil {
				wireReq.PolicyInputs = localOnlyPolicyInputs(prepared.inputs)
				wireReq.LocalPolicyRevision, wireReq.LocalPolicyResults = prepared.revision, prepared.results
				resp, err = c.guardClient.Guard(ctx, connectReq)
				if err != nil {
					return withLocalWarnings(*prepared.decision, warnings), err
				}
				decision := localPolicyReportedDecision(resp.Msg, *prepared.decision)
				return withLocalWarnings(decision, warnings), nil
			}
			wireReq.PolicyInputs, wireReq.LocalPolicyRevision, wireReq.LocalPolicyResults = prepared.inputs, prepared.revision, prepared.results
			if sanitizeInputs {
				wireReq.PolicyInputs = localOnlyPolicyInputs(wireReq.GetPolicyInputs())
			}
			resp, err = c.guardClient.Guard(ctx, connectReq)
			if err != nil {
				return withLocalWarnings(guardErrorDecision("TRANSPORT_ERROR", err.Error()), warnings), err
			}
		}
	}
	return withLocalWarnings(guardDecisionFromProto(resp.Msg), warnings), nil
}

// reportLocalPolicyDenial makes a best-effort, privacy-safe Guard call so the
// server can record the denial and assign its final decision ID. The local
// denial remains authoritative if reporting fails.
func (c *GuardClient) reportLocalPolicyDenial(ctx context.Context, req GuardRequest, start time.Time, metadata map[string]string, prepared preparedRemotePolicy, warnings []Warning) (GuardDecision, error) {
	wireReq := localPolicyDenialRequest(req, c.userAgent, start, metadata, prepared, warnings)
	connectReq := connect.NewRequest(wireReq)
	connectReq.Header().Set("Authorization", "Bearer "+c.key)
	connectReq.Header().Set("User-Agent", c.userAgent)
	resp, err := c.guardClient.Guard(ctx, connectReq)
	decision := *prepared.decision
	if err != nil {
		return withLocalWarnings(decision, warnings), err
	}
	decision = localPolicyReportedDecision(resp.Msg, decision)
	return withLocalWarnings(decision, warnings), nil
}

func localPolicyDenialRequest(req GuardRequest, userAgent string, start time.Time, metadata map[string]string, prepared preparedRemotePolicy, warnings []Warning) *decidev2.GuardRequest {
	elapsed := safeUint64FromInt64(time.Since(start).Milliseconds())
	sentAt := safeUint64FromInt64(time.Now().UnixMilli())
	return &decidev2.GuardRequest{
		UserAgent:           userAgent,
		LocalEvalDurationMs: &elapsed,
		SentAtUnixMs:        &sentAt,
		Label:               req.Label,
		Actor:               req.Actor,
		CorrelationId:       req.CorrelationId,
		MetadataJson:        metadata,
		PolicyInputs:        localOnlyPolicyInputs(prepared.inputs),
		LocalPolicyRevision: prepared.revision,
		LocalPolicyResults:  prepared.results,
		PolicyCapabilities:  guardPolicyCapabilities,
		LocalWarnings:       warningsToProtoV2(warnings),
	}
}

func localPolicyReportedDecision(resp *decidev2.GuardResponse, fallback GuardDecision) GuardDecision {
	if resp.GetDecision() == nil || resp.GetDecision().GetId() == "" {
		return fallback
	}
	return guardDecisionFromProto(resp)
}

func localOnlyPolicyInputs(inputs map[string]*decidev2.GuardPolicyInput) map[string]*decidev2.GuardPolicyInput {
	local := make(map[string]*decidev2.GuardPolicyInput)
	for name, input := range inputs {
		if input != nil && input.GetLocal() != nil {
			local[name] = input
		}
	}
	return local
}

// withLocalWarnings appends the SDK's own client-side warnings to a decision.
//
// The server persists local_warnings but never echoes them back on the response,
// so without this a metadata key the SDK dropped would be invisible to the
// caller.
func withLocalWarnings(d GuardDecision, warnings []Warning) GuardDecision {
	if len(warnings) == 0 {
		return d
	}
	d.Warnings = append(d.Warnings, warnings...)
	return d
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
	metadata Metadata
	mode     Mode
}

func newGuardRuleBase(mode Mode, label string, metadata Metadata) (guardRuleBase, error) {
	if err := validateGuardMode(mode); err != nil {
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
		metadata: maps.Clone(metadata),
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
		metadata: maps.Clone(b.metadata),
	}
	if b.label != "" {
		sub.Label = &b.label
	}
	return sub
}

// GuardTokenBucketOptions configures a Guard token bucket rule.
type GuardTokenBucketOptions struct {
	// Mode is required (LIVE or DRY_RUN). Unlike HTTP rules, an empty Mode is
	// rejected rather than defaulting to DRY_RUN.
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
	// Metadata is recorded with every invocation of this rule. See
	// GuardRequest.Metadata for the accepted shape and limits.
	Metadata Metadata
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
		if res.ConfigID == r.base.configID && res.Error == nil && res.TokenBucket != nil {
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

// ErrorResult returns this rule's error if it failed to evaluate, or nil
// otherwise. Errors are fail-open (the conclusion stays ALLOW), so an errored
// rule never surfaces through Result or DeniedResult — this is the only
// accessor that returns it. Correlated by ConfigID like the other accessors.
func (r *GuardTokenBucketRule) ErrorResult(d GuardDecision) *ArcjetError {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error != nil {
			return res.Error
		}
	}
	return nil
}

// GuardFixedWindowOptions configures a Guard fixed window rule.
type GuardFixedWindowOptions struct {
	// Mode is required (LIVE or DRY_RUN). Unlike HTTP rules, an empty Mode is
	// rejected rather than defaulting to DRY_RUN.
	Mode Mode
	// Window is the fixed window duration.
	Window time.Duration
	// MaxRequests is the maximum number of requests per window.
	MaxRequests int
	// Bucket groups counters for this rule.
	Bucket string
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule. See
	// GuardRequest.Metadata for the accepted shape and limits.
	Metadata Metadata
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
		if res.ConfigID == r.base.configID && res.Error == nil && res.FixedWindow != nil {
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

// ErrorResult returns this rule's error if it failed to evaluate, or nil
// otherwise. Errors are fail-open, so an errored rule never surfaces through
// Result or DeniedResult — this is the only accessor that returns it.
func (r *GuardFixedWindowRule) ErrorResult(d GuardDecision) *ArcjetError {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error != nil {
			return res.Error
		}
	}
	return nil
}

// GuardSlidingWindowOptions configures a Guard sliding window rule.
type GuardSlidingWindowOptions struct {
	// Mode is required (LIVE or DRY_RUN). Unlike HTTP rules, an empty Mode is
	// rejected rather than defaulting to DRY_RUN.
	Mode Mode
	// Interval is the sliding window interval.
	Interval time.Duration
	// MaxRequests is the maximum number of requests per interval.
	MaxRequests int
	// Bucket groups counters for this rule.
	Bucket string
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule. See
	// GuardRequest.Metadata for the accepted shape and limits.
	Metadata Metadata
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
		if res.ConfigID == r.base.configID && res.Error == nil && res.SlidingWindow != nil {
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

// ErrorResult returns this rule's error if it failed to evaluate, or nil
// otherwise. Errors are fail-open, so an errored rule never surfaces through
// Result or DeniedResult — this is the only accessor that returns it.
func (r *GuardSlidingWindowRule) ErrorResult(d GuardDecision) *ArcjetError {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error != nil {
			return res.Error
		}
	}
	return nil
}

// GuardPromptInjectionOptions configures a Guard prompt injection rule.
type GuardPromptInjectionOptions struct {
	// Mode is required (LIVE or DRY_RUN). Unlike HTTP rules, an empty Mode is
	// rejected rather than defaulting to DRY_RUN.
	Mode Mode
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule. See
	// GuardRequest.Metadata for the accepted shape and limits.
	Metadata Metadata
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
		if res.ConfigID == r.base.configID && res.Error == nil && res.PromptInjection != nil {
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

// ErrorResult returns this rule's error if it failed to evaluate, or nil
// otherwise. Errors are fail-open, so an errored rule never surfaces through
// Result or DeniedResult — this is the only accessor that returns it.
func (r *GuardPromptInjectionRule) ErrorResult(d GuardDecision) *ArcjetError {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error != nil {
			return res.Error
		}
	}
	return nil
}

// GuardModerateContentOptions configures a Guard content moderation rule.
type GuardModerateContentOptions struct {
	// Mode is required (LIVE or DRY_RUN). Unlike HTTP rules, an empty Mode is
	// rejected rather than defaulting to DRY_RUN.
	Mode Mode
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule. See
	// GuardRequest.Metadata for the accepted shape and limits.
	Metadata Metadata
}

// GuardModerateContentRule is a configured Guard content moderation rule.
type GuardModerateContentRule struct {
	base guardRuleBase
}

// GuardModerateContent creates a Guard content moderation rule.
func GuardModerateContent(opts GuardModerateContentOptions) (*GuardModerateContentRule, error) {
	base, err := newGuardRuleBase(opts.Mode, opts.Label, opts.Metadata)
	if err != nil {
		return nil, err
	}
	return &GuardModerateContentRule{base: base}, nil
}

// Text binds text to moderate for one Guard call.
func (r *GuardModerateContentRule) Text(text string) GuardRuleInput {
	return guardRuleInputFunc(func(_ context.Context, _ *localEvaluator) (guardRuleSubmissionWire, error) {
		return r.base.submission(map[string]any{"moderateContent": map[string]any{
			"inputText": text,
		}}), nil
	})
}

// Result returns this rule's content moderation result from the given Guard
// decision, or nil if the rule did not produce one.
func (r *GuardModerateContentRule) Result(d GuardDecision) *GuardModerateContentResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error == nil && res.ModerateContent != nil {
			return res.ModerateContent
		}
	}
	return nil
}

// DeniedResult returns this rule's content moderation result if it denied the
// Guard call, or nil otherwise.
func (r *GuardModerateContentRule) DeniedResult(d GuardDecision) *GuardModerateContentResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.IsDenied() && res.ModerateContent != nil {
			return res.ModerateContent
		}
	}
	return nil
}

// ErrorResult returns this rule's error if it failed to evaluate, or nil
// otherwise. Errors are fail-open, so an errored rule never surfaces through
// Result or DeniedResult — this is the only accessor that returns it.
func (r *GuardModerateContentRule) ErrorResult(d GuardDecision) *ArcjetError {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error != nil {
			return res.Error
		}
	}
	return nil
}

// ExperimentalGuardModerateContentOptions is a deprecated alias of
// [GuardModerateContentOptions].
//
// Deprecated: use [GuardModerateContentOptions]. This alias will be removed in 1.0.
type ExperimentalGuardModerateContentOptions = GuardModerateContentOptions

// ExperimentalGuardModerateContentRule is a deprecated alias of
// [GuardModerateContentRule].
//
// Deprecated: use [GuardModerateContentRule]. This alias will be removed in 1.0.
type ExperimentalGuardModerateContentRule = GuardModerateContentRule

// ExperimentalGuardModerateContent is a deprecated alias of
// [GuardModerateContent].
//
// Deprecated: use [GuardModerateContent]. This alias will be removed in 1.0.
func ExperimentalGuardModerateContent(opts ExperimentalGuardModerateContentOptions) (*ExperimentalGuardModerateContentRule, error) {
	return GuardModerateContent(opts)
}

// GuardSensitiveInfoOptions configures local Guard sensitive information detection.
type GuardSensitiveInfoOptions struct {
	// Mode is required (LIVE or DRY_RUN). Unlike HTTP rules, an empty Mode is
	// rejected rather than defaulting to DRY_RUN.
	Mode Mode
	// Allow lists entity types allowed in scanned text.
	Allow []EntityType
	// Deny lists entity types denied in scanned text.
	Deny []EntityType
	// Backend optionally replaces the bundled WebAssembly analyzer with a
	// pluggable detection engine (see [SensitiveInfoBackend]). Required to
	// allow or deny any entity type the bundled analyzer does not detect on
	// its own.
	Backend SensitiveInfoBackend
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule. See
	// GuardRequest.Metadata for the accepted shape and limits.
	Metadata Metadata
}

// GuardSensitiveInfoRule is a configured local Guard sensitive information rule.
type GuardSensitiveInfoRule struct {
	base    guardRuleBase
	allow   []EntityType
	deny    []EntityType
	backend SensitiveInfoBackend
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
		base:    base,
		allow:   append([]EntityType(nil), opts.Allow...),
		deny:    append([]EntityType(nil), opts.Deny...),
		backend: opts.Backend,
	}, nil
}

// Result returns this rule's sensitive information result from the given
// Guard decision, or nil if the rule did not produce one.
func (r *GuardSensitiveInfoRule) Result(d GuardDecision) *GuardSensitiveInfoResult {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error == nil && res.LocalSensitiveInfo != nil {
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

// ErrorResult returns this rule's error if it failed to evaluate, or nil
// otherwise. Errors are fail-open, so an errored rule never surfaces through
// Result or DeniedResult — this is the only accessor that returns it.
func (r *GuardSensitiveInfoRule) ErrorResult(d GuardDecision) *ArcjetError {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error != nil {
			return res.Error
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
	backend := r.backend
	return guardRuleInputFunc(func(ctx context.Context, eval *localEvaluator) (guardRuleSubmissionWire, error) {
		if err := validateSensitiveInfoEntities(allow, deny, backend, eval.hasCustomDetect()); err != nil {
			return guardRuleSubmissionWire{}, err
		}
		payload := map[string]any{
			"inputTextHash": sha256Hex(text),
		}
		switch {
		case len(allow) > 0:
			payload["configEntitiesAllow"] = map[string]any{"entities": stringSlice(allow)}
		case len(deny) > 0:
			payload["configEntitiesDeny"] = map[string]any{"entities": stringSlice(deny)}
		}
		outcome, err := eval.scanSensitiveInfo(ctx, text, allow, deny, backend)
		if err != nil {
			payload["resultError"] = map[string]any{"message": err.Error(), "code": "AJ1200"}
			// Fail open: the scan error is reported to Arcjet via resultError in
			// the submission, so the Guard call proceeds rather than erroring.
			return r.base.submission(map[string]any{"localSensitiveInfo": payload}), nil //nolint:nilerr // fail open (see above)
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
	// Mode is required (LIVE or DRY_RUN). Unlike HTTP rules, an empty Mode is
	// rejected rather than defaulting to DRY_RUN.
	Mode Mode
	// Config is the rule configuration recorded with each invocation.
	Config map[string]string
	// Func is the local evaluation function. Required.
	Func GuardCustomFunc
	// Label identifies this rule in the Arcjet dashboard.
	Label string
	// Metadata is recorded with every invocation of this rule. See
	// GuardRequest.Metadata for the accepted shape and limits.
	Metadata Metadata
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
		if res.ConfigID == r.base.configID && res.Error == nil && res.LocalCustom != nil {
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

// ErrorResult returns this rule's error if it failed to evaluate, or nil
// otherwise. Errors are fail-open, so an errored rule never surfaces through
// Result or DeniedResult — this is the only accessor that returns it.
func (r *GuardCustomRule) ErrorResult(d GuardDecision) *ArcjetError {
	for _, res := range d.Results {
		if res.ConfigID == r.base.configID && res.Error != nil {
			return res.Error
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
