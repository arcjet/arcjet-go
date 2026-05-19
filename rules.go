package arcjet

import (
	"context"
	"fmt"
	"math"
	"time"
)

// Rule is a request protection rule evaluated by Client.Protect.
type Rule interface {
	requestRule() (map[string]any, error)
	evaluateLocal(context.Context, ProtectDetails, ProtectOptions, *localEvaluator) (*localDecision, error)
	localKind() localKind
}

type ruleFunc struct {
	build func() (map[string]any, error)
	local func(context.Context, ProtectDetails, ProtectOptions, *localEvaluator) (*localDecision, error)
	kind  localKind
}

func (f ruleFunc) requestRule() (map[string]any, error) {
	return f.build()
}

func (f ruleFunc) evaluateLocal(ctx context.Context, details ProtectDetails, opts ProtectOptions, evaluator *localEvaluator) (*localDecision, error) {
	if f.local == nil {
		return nil, nil
	}
	return f.local(ctx, details, opts, evaluator)
}

func (f ruleFunc) localKind() localKind {
	return f.kind
}

// TokenBucketOptions configures a token bucket rate limit rule.
type TokenBucketOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Characteristics are rate-limit keys such as "userId".
	Characteristics []string
	// RefillRate is the number of tokens added per interval.
	RefillRate int
	// Interval is the token refill interval.
	Interval time.Duration
	// Capacity is the maximum bucket size.
	Capacity int
}

// TokenBucket creates a token bucket rate limit rule.
//
// Token buckets are useful for AI token budgets because callers can pass the
// consumed token count with WithRequested.
func TokenBucket(opts TokenBucketOptions) Rule {
	return ruleFunc{build: func() (map[string]any, error) {
		if err := validateMode(opts.Mode); err != nil {
			return nil, err
		}
		if opts.RefillRate <= 0 || opts.Interval <= 0 || opts.Capacity <= 0 {
			return nil, fmt.Errorf("arcjet: token bucket requires positive refill rate, interval, and capacity: %w", ErrInvalidRateLimit)
		}
		return map[string]any{"rateLimit": cleanMap(map[string]any{
			"mode":            requestMode(opts.Mode),
			"characteristics": opts.Characteristics,
			"algorithm":       "RATE_LIMIT_ALGORITHM_TOKEN_BUCKET",
			"refillRate":      safeUint32(opts.RefillRate),
			"interval":        seconds(opts.Interval),
			"capacity":        safeUint32(opts.Capacity),
		})}, nil
	}}
}

// FixedWindowOptions configures a fixed window rate limit rule.
type FixedWindowOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Characteristics are rate-limit keys such as "userId".
	Characteristics []string
	// Window is the fixed window duration.
	Window time.Duration
	// MaxRequests is the maximum number of requests per window.
	MaxRequests int
}

// FixedWindow creates a fixed window rate limit rule.
func FixedWindow(opts FixedWindowOptions) Rule {
	return ruleFunc{build: func() (map[string]any, error) {
		if err := validateMode(opts.Mode); err != nil {
			return nil, err
		}
		if opts.Window <= 0 || opts.MaxRequests <= 0 {
			return nil, fmt.Errorf("arcjet: fixed window requires positive window and max requests: %w", ErrInvalidRateLimit)
		}
		return map[string]any{"rateLimit": cleanMap(map[string]any{
			"mode":            requestMode(opts.Mode),
			"characteristics": opts.Characteristics,
			"algorithm":       "RATE_LIMIT_ALGORITHM_FIXED_WINDOW",
			"windowInSeconds": seconds(opts.Window),
			"max":             safeUint32(opts.MaxRequests),
		})}, nil
	}}
}

// SlidingWindowOptions configures a sliding window rate limit rule.
type SlidingWindowOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Characteristics are rate-limit keys such as "userId".
	Characteristics []string
	// Interval is the sliding window interval.
	Interval time.Duration
	// MaxRequests is the maximum number of requests per interval.
	MaxRequests int
}

// SlidingWindow creates a sliding window rate limit rule.
func SlidingWindow(opts SlidingWindowOptions) Rule {
	return ruleFunc{build: func() (map[string]any, error) {
		if err := validateMode(opts.Mode); err != nil {
			return nil, err
		}
		if opts.Interval <= 0 || opts.MaxRequests <= 0 {
			return nil, fmt.Errorf("arcjet: sliding window requires positive interval and max requests: %w", ErrInvalidRateLimit)
		}
		return map[string]any{"rateLimit": cleanMap(map[string]any{
			"mode":            requestMode(opts.Mode),
			"characteristics": opts.Characteristics,
			"algorithm":       "RATE_LIMIT_ALGORITHM_SLIDING_WINDOW",
			"interval":        seconds(opts.Interval),
			"max":             safeUint32(opts.MaxRequests),
		})}, nil
	}}
}

// ShieldOptions configures Arcjet Shield.
type ShieldOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Characteristics are optional keys associated with Shield evaluation.
	Characteristics []string
}

// Shield creates a rule that protects against common web attacks.
func Shield(opts ShieldOptions) Rule {
	return ruleFunc{build: func() (map[string]any, error) {
		if err := validateMode(opts.Mode); err != nil {
			return nil, err
		}
		return map[string]any{"shield": cleanMap(map[string]any{
			"mode":            requestMode(opts.Mode),
			"characteristics": opts.Characteristics,
		})}, nil
	}}
}

// BotOptions configures bot detection.
//
// Allow and Deny are mutually exclusive. An empty Allow list blocks all detected
// bots.
type BotOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Allow lists allowed bot categories or identifiers.
	Allow []string
	// Deny lists denied bot categories or identifiers.
	Deny []string
}

// DetectBot creates a bot detection rule.
func DetectBot(opts BotOptions) Rule {
	return ruleFunc{
		build: func() (map[string]any, error) {
			if err := validateBotOptions(opts); err != nil {
				return nil, err
			}
			return map[string]any{"botV2": cleanMap(map[string]any{
				"mode":  requestMode(opts.Mode),
				"allow": opts.Allow,
				"deny":  opts.Deny,
			})}, nil
		},
		local: func(ctx context.Context, details ProtectDetails, _ ProtectOptions, evaluator *localEvaluator) (*localDecision, error) {
			if err := validateBotOptions(opts); err != nil {
				return nil, err
			}
			return evaluator.detectBot(ctx, opts, details)
		},
		kind: localKindBot,
	}
}

// EmailOptions configures email validation.
type EmailOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Allow lists allowed email types.
	Allow []EmailType
	// Deny lists denied email types.
	Deny []EmailType
	// RequireTopLevelDomain requires a top-level domain in the address when true.
	RequireTopLevelDomain *bool
	// AllowDomainLiteral allows domain literals such as user@[192.0.2.1] when true.
	AllowDomainLiteral *bool
}

// ValidateEmail creates an email validation rule.
func ValidateEmail(opts EmailOptions) Rule {
	return ruleFunc{
		build: func() (map[string]any, error) {
			if err := validateEmailOptions(opts); err != nil {
				return nil, err
			}
			return map[string]any{"email": cleanMap(map[string]any{
				"mode":                  requestMode(opts.Mode),
				"allow":                 emailEnums(opts.Allow),
				"deny":                  emailEnums(opts.Deny),
				"requireTopLevelDomain": opts.RequireTopLevelDomain,
				"allowDomainLiteral":    opts.AllowDomainLiteral,
			})}, nil
		},
		local: func(ctx context.Context, details ProtectDetails, options ProtectOptions, evaluator *localEvaluator) (*localDecision, error) {
			if err := validateEmailOptions(opts); err != nil {
				return nil, err
			}
			return evaluator.validateEmail(ctx, opts, details, options)
		},
		kind: localKindEmail,
	}
}

// SensitiveInfoOptions configures request sensitive information detection.
//
// Allow and Deny are mutually exclusive. Pass text for each request with
// WithSensitiveInfoValue.
type SensitiveInfoOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Allow lists entity types allowed in scanned text.
	Allow []EntityType
	// Deny lists entity types denied in scanned text.
	Deny []EntityType
}

// SensitiveInfo creates a sensitive information detection rule.
//
// Currently a no-op: this SDK does not yet bundle the WebAssembly analyzer
// for sensitive-info detection (the analyzer in @arcjet/analyze-wasm used by
// the JavaScript SDK has not been ported to Go yet). The function and types
// are kept stable so calling code does not need to change once the analyzer
// lands; until then, the rule contributes nothing to the wire request and
// has no effect on the decision.
//
// Mode, Allow, and Deny are validated for shape so configuration mistakes
// still surface at NewClient time.
func SensitiveInfo(opts SensitiveInfoOptions) Rule {
	return ruleFunc{build: func() (map[string]any, error) {
		if err := validateMode(opts.Mode); err != nil {
			return nil, err
		}
		if len(opts.Allow) > 0 && len(opts.Deny) > 0 {
			return nil, fmt.Errorf("arcjet: sensitive info: %w", ErrAllowDenyConflict)
		}
		// Returning a nil wire map signals buildRequestRule to skip this
		// rule. See the godoc above for why.
		return nil, nil
	}}
}

// PromptInjectionOptions configures prompt injection detection.
//
// Arcjet no longer exposes a prompt injection threshold; use Mode to enforce or
// dry-run the rule.
type PromptInjectionOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
}

// DetectPromptInjection creates a prompt injection detection rule.
func DetectPromptInjection(opts PromptInjectionOptions) Rule {
	return ruleFunc{build: func() (map[string]any, error) {
		if err := validateMode(opts.Mode); err != nil {
			return nil, err
		}
		return map[string]any{"promptInjectionDetection": map[string]any{
			"mode": requestMode(opts.Mode),
		}}, nil
	}}
}

// FilterOptions configures request filters.
//
// Allow and Deny expressions are mutually exclusive.
type FilterOptions struct {
	// Mode controls whether the rule enforces denials or only reports them.
	Mode Mode
	// Allow expressions allow matching requests and deny non-matching requests.
	Allow []string
	// Deny expressions deny matching requests.
	Deny []string
}

// Filter creates a request filter rule.
//
// Local filter values passed with WithFilterLocal are available to expressions
// as local["name"].
func Filter(opts FilterOptions) Rule {
	return ruleFunc{
		build: func() (map[string]any, error) {
			if err := validateFilterOptions(opts); err != nil {
				return nil, err
			}
			return map[string]any{"filter": cleanMap(map[string]any{
				"mode":  requestMode(opts.Mode),
				"allow": opts.Allow,
				"deny":  opts.Deny,
			})}, nil
		},
		local: func(ctx context.Context, details ProtectDetails, options ProtectOptions, evaluator *localEvaluator) (*localDecision, error) {
			if err := validateFilterOptions(opts); err != nil {
				return nil, err
			}
			return evaluator.matchFilter(ctx, opts, details, options)
		},
		kind: localKindFilter,
	}
}

func validateBotOptions(opts BotOptions) error {
	if err := validateMode(opts.Mode); err != nil {
		return err
	}
	if len(opts.Allow) > 0 && len(opts.Deny) > 0 {
		return fmt.Errorf("arcjet: bot rule: %w", ErrAllowDenyConflict)
	}
	return nil
}

func validateEmailOptions(opts EmailOptions) error {
	if err := validateMode(opts.Mode); err != nil {
		return err
	}
	if len(opts.Allow) > 0 && len(opts.Deny) > 0 {
		return fmt.Errorf("arcjet: email rule: %w", ErrAllowDenyConflict)
	}
	return nil
}

func validateFilterOptions(opts FilterOptions) error {
	if err := validateMode(opts.Mode); err != nil {
		return err
	}
	if len(opts.Allow) > 0 && len(opts.Deny) > 0 {
		return fmt.Errorf("arcjet: filter rule: %w", ErrAllowDenyConflict)
	}
	return nil
}

func seconds(d time.Duration) uint32 {
	if d < time.Second {
		return 1
	}
	return safeUint32(int(d.Round(time.Second) / time.Second))
}

// safeUint32 converts a non-negative int to uint32, clamping at MaxUint32.
// Negative values become 0. Used at boundaries that must produce a uint32
// from user-validated (already > 0) configuration or computed time deltas.
func safeUint32(n int) uint32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxUint32:
		return math.MaxUint32
	default:
		return uint32(n)
	}
}

// safeUint64FromInt64 converts a non-negative int64 to uint64. Negative values
// (e.g. from a backwards monotonic delta) become 0.
func safeUint64FromInt64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func cleanMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case nil:
			continue
		case []string:
			if len(t) == 0 {
				continue
			}
		case *bool:
			if t == nil {
				continue
			}
			out[k] = *t
			continue
		}
		out[k] = v
	}
	return out
}

func emailEnums(values []EmailType) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = "EMAIL_TYPE_" + string(v)
	}
	return out
}
