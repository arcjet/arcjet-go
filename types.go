package arcjet

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// Version is the Arcjet Go SDK version sent with Decide and Guard requests.
const Version = "0.1.0"

// Mode controls whether a rule enforces decisions or only reports them.
type Mode string

const (
	// ModeDryRun evaluates a rule without blocking the request or guard call.
	ModeDryRun Mode = "DRY_RUN"
	// ModeLive evaluates a rule and enforces denial decisions.
	ModeLive Mode = "LIVE"
)

func normalizeMode(mode Mode) Mode {
	if mode == "" {
		return ModeDryRun
	}
	return mode
}

func validateMode(mode Mode) error {
	switch normalizeMode(mode) {
	case ModeDryRun, ModeLive:
		return nil
	default:
		return fmt.Errorf("arcjet: %w: %q", ErrInvalidMode, string(mode))
	}
}

func requestMode(mode Mode) string {
	if normalizeMode(mode) == ModeLive {
		return "MODE_LIVE"
	}
	return "MODE_DRY_RUN"
}

func guardMode(mode Mode) string {
	if normalizeMode(mode) == ModeLive {
		return "GUARD_RULE_MODE_LIVE"
	}
	return "GUARD_RULE_MODE_DRY_RUN"
}

// LogValue implements [slog.LogValuer] so Mode logs as its string form.
func (m Mode) LogValue() slog.Value { return slog.StringValue(string(m)) }

// Conclusion is the top-level Arcjet decision outcome.
//
// Conclusion values are normalized when JSON-decoded: both the bare wire
// strings ("DENY", "ALLOW", "CHALLENGE", "ERROR") and the prefixed forms
// ("CONCLUSION_DENY", "GUARD_CONCLUSION_DENY", etc.) are mapped to the
// canonical constants below.
type Conclusion string

const (
	// ConclusionAllow means Arcjet allowed the request or guard call.
	ConclusionAllow Conclusion = "ALLOW"
	// ConclusionDeny means Arcjet denied the request or guard call.
	ConclusionDeny Conclusion = "DENY"
	// ConclusionChallenge means Arcjet returned a challenge decision.
	ConclusionChallenge Conclusion = "CHALLENGE"
	// ConclusionError means Arcjet or a local rule produced an error result.
	ConclusionError Conclusion = "ERROR"
)

// UnmarshalJSON normalizes wire-format conclusion strings to canonical
// Conclusion constants. Single source of truth is parseConclusion.
func (c *Conclusion) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*c = parseConclusion(s)
	return nil
}

// LogValue implements [slog.LogValuer] so Conclusion logs as its string form.
func (c Conclusion) LogValue() slog.Value { return slog.StringValue(string(c)) }

// ReasonType identifies the rule family or condition behind a decision.
type ReasonType string

const (
	// ReasonUnknown is used when a response does not include a known reason.
	ReasonUnknown ReasonType = ""
	// ReasonRateLimit means a rate limit rule determined the result.
	ReasonRateLimit ReasonType = "RATE_LIMIT"
	// ReasonBot means a bot detection rule determined the result.
	ReasonBot ReasonType = "BOT"
	// ReasonShield means Shield determined the result.
	ReasonShield ReasonType = "SHIELD"
	// ReasonEmail means an email validation rule determined the result.
	ReasonEmail ReasonType = "EMAIL"
	// ReasonSensitiveInfo means a sensitive information rule determined the result.
	ReasonSensitiveInfo ReasonType = "SENSITIVE_INFO"
	// ReasonPromptInjection means a prompt injection rule determined the result.
	ReasonPromptInjection ReasonType = "PROMPT_INJECTION"
	// ReasonFilter means a request filter rule determined the result.
	ReasonFilter ReasonType = "FILTER"
	// ReasonError means the decision contains an error.
	ReasonError ReasonType = "ERROR"
	// ReasonNotRun means a guard rule did not run.
	ReasonNotRun ReasonType = "NOT_RUN"
	// ReasonCustom means a custom guard rule determined the result.
	ReasonCustom ReasonType = "CUSTOM"
)

// LogValue implements [slog.LogValuer] so ReasonType logs as its string form.
func (r ReasonType) LogValue() slog.Value { return slog.StringValue(string(r)) }

// RuleState is the lifecycle state of a per-rule evaluation in a Decision.
type RuleState string

const (
	// RuleStateUnspecified means no rule state was provided.
	RuleStateUnspecified RuleState = ""
	// RuleStateRun means the rule was evaluated this request.
	RuleStateRun RuleState = "RULE_STATE_RUN"
	// RuleStateDryRun means the rule was evaluated but not enforced.
	RuleStateDryRun RuleState = "RULE_STATE_DRY_RUN"
	// RuleStateNotRun means the rule did not run.
	RuleStateNotRun RuleState = "RULE_STATE_NOT_RUN"
	// RuleStateCached means the rule result was served from cache.
	RuleStateCached RuleState = "RULE_STATE_CACHED"
)

// LogValue implements [slog.LogValuer] so RuleState logs as its string form.
func (s RuleState) LogValue() slog.Value { return slog.StringValue(string(s)) }

// GuardRuleType identifies a Guard rule family in a GuardRuleResult.
type GuardRuleType string

const (
	// GuardRuleTypeUnknown is used when a Guard rule type is unrecognized.
	GuardRuleTypeUnknown GuardRuleType = ""
	// GuardRuleTypeTokenBucket identifies a Guard token bucket rule.
	GuardRuleTypeTokenBucket GuardRuleType = "TOKEN_BUCKET"
	// GuardRuleTypeFixedWindow identifies a Guard fixed window rule.
	GuardRuleTypeFixedWindow GuardRuleType = "FIXED_WINDOW"
	// GuardRuleTypeSlidingWindow identifies a Guard sliding window rule.
	GuardRuleTypeSlidingWindow GuardRuleType = "SLIDING_WINDOW"
	// GuardRuleTypePromptInjection identifies a Guard prompt injection rule.
	GuardRuleTypePromptInjection GuardRuleType = "PROMPT_INJECTION"
	// GuardRuleTypeLocalSensitiveInfo identifies a local sensitive info Guard rule.
	GuardRuleTypeLocalSensitiveInfo GuardRuleType = "LOCAL_SENSITIVE_INFO"
	// GuardRuleTypeLocalCustom identifies a custom local Guard rule.
	GuardRuleTypeLocalCustom GuardRuleType = "LOCAL_CUSTOM"
)

// LogValue implements [slog.LogValuer] so GuardRuleType logs as its string form.
func (g GuardRuleType) LogValue() slog.Value { return slog.StringValue(string(g)) }

// EmailType classifies an email address for ValidateEmail rules.
//
// Values are stored in their canonical form (without the "EMAIL_TYPE_" wire
// prefix). UnmarshalJSON strips the prefix when decoding responses. See
// constants.go for the supported constants.
type EmailType string

// UnmarshalJSON strips the wire "EMAIL_TYPE_" prefix when present so values
// match the EmailType constants.
func (e *EmailType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	const prefix = "EMAIL_TYPE_"
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		s = s[len(prefix):]
	}
	*e = EmailType(s)
	return nil
}

// LogValue implements [slog.LogValuer] so EmailType logs as its string form.
func (e EmailType) LogValue() slog.Value { return slog.StringValue(string(e)) }

// EntityType classifies a sensitive-information entity. See constants.go for
// the supported constants.
type EntityType string

// LogValue implements [slog.LogValuer] so EntityType logs as its string form.
func (e EntityType) LogValue() slog.Value { return slog.StringValue(string(e)) }

// ArcjetError describes an error returned by Arcjet or a local guard rule.
type ArcjetError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Error formats an Arcjet error as a Go error string.
func (e ArcjetError) Error() string {
	if e.Code != "" && e.Message != "" {
		return e.Code + ": " + e.Message
	}
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

// Is reports whether target is an ArcjetError with the same Code. Use it
// with errors.Is to detect specific Arcjet error codes:
//
//	if errors.Is(err, ArcjetError{Code: "AJ1100"}) { ... }
func (e ArcjetError) Is(target error) bool {
	other, ok := target.(ArcjetError)
	if !ok {
		return false
	}
	return e.Code == other.Code
}

// Decision is the result of evaluating request protection rules.
type Decision struct {
	ID         string     `json:"id,omitempty"`
	Conclusion Conclusion `json:"conclusion,omitempty"`
	Reason     Reason     `json:"reason"`
	Results    []RuleResult
	// TTL is the number of seconds the decision can be cached.
	TTL int
	IP  IPDetails
	Raw json.RawMessage
}

// IsAllowed reports whether Arcjet allowed the request.
func (d Decision) IsAllowed() bool {
	return d.Conclusion == ConclusionAllow
}

// IsDenied reports whether Arcjet denied the request.
func (d Decision) IsDenied() bool {
	return d.Conclusion == ConclusionDeny
}

// IsChallenged reports whether Arcjet returned a challenge decision.
func (d Decision) IsChallenged() bool {
	return d.Conclusion == ConclusionChallenge
}

// IsErrored reports whether Arcjet returned or locally computed an error.
func (d Decision) IsErrored() bool {
	return d.Conclusion == ConclusionError || d.Reason.Type == ReasonError
}

// Err returns the decision's terminal error, or nil if the decision did not
// error. The returned error is an ArcjetError carrying the Reason message
// when available.
func (d Decision) Err() error {
	if !d.IsErrored() {
		return nil
	}
	msg := d.Reason.Message
	if msg == "" {
		msg = "decision errored"
	}
	return ArcjetError{Message: msg}
}

// IsSpoofedBot reports whether a bot rule detected a spoofed verified bot — one
// claiming to be a well-known crawler but originating from an IP outside that
// crawler's published ranges.
func (d Decision) IsSpoofedBot() bool {
	return d.anyActiveReason(func(r Reason) bool {
		return r.Bot != nil && r.Bot.Spoofed
	})
}

// IsVerifiedBot reports whether a bot rule confirmed the request came from a
// verified bot (for example a search engine crawler whose IP matches its
// published ranges). You may want to allow such requests even when other
// signals would otherwise deny them.
func (d Decision) IsVerifiedBot() bool {
	return d.anyActiveReason(func(r Reason) bool {
		return r.Bot != nil && r.Bot.Verified
	})
}

// IsMissingUserAgent reports whether a bot rule denied the request because it
// had no User-Agent header. A missing User-Agent is a common indicator of an
// automated client, since IETF HTTP Semantics (RFC 9110) recommends sending
// one. Mirrors @arcjet/inspect's isMissingUserAgent in arcjet-js.
func (d Decision) IsMissingUserAgent() bool {
	return d.anyActiveReason(isMissingUserAgentMessage)
}

// anyActiveReason reports whether the top-level reason or any non-dry-run rule
// result satisfies pred.
func (d Decision) anyActiveReason(pred func(Reason) bool) bool {
	if pred(d.Reason) {
		return true
	}
	for _, r := range d.Results {
		if r.State != RuleStateDryRun && pred(r.Reason) {
			return true
		}
	}
	return false
}

// isMissingUserAgentMessage reports whether an error reason carries one of the
// missing-User-Agent messages matched by @arcjet/inspect's isMissingUserAgent.
func isMissingUserAgentMessage(r Reason) bool {
	if r.Type != ReasonError {
		return false
	}
	return strings.Contains(r.Message, "missing User-Agent header") ||
		strings.Contains(r.Message, "requires user-agent header")
}

// Reason contains typed details about why Arcjet reached a decision.
type Reason struct {
	Type    ReasonType
	Message string

	RateLimit       *RateLimitReason
	Bot             *BotReason
	Shield          *ShieldReason
	Email           *EmailReason
	SensitiveInfo   *SensitiveInfoReason
	PromptInjection *PromptInjectionReason
	Filter          *FilterReason
}

// IsRateLimit reports whether a rate limit rule drove this reason.
func (r Reason) IsRateLimit() bool { return r.Type == ReasonRateLimit }

// IsBot reports whether a bot detection rule drove this reason.
func (r Reason) IsBot() bool { return r.Type == ReasonBot }

// IsShield reports whether Shield drove this reason.
func (r Reason) IsShield() bool { return r.Type == ReasonShield }

// IsEmail reports whether email validation drove this reason.
func (r Reason) IsEmail() bool { return r.Type == ReasonEmail }

// IsSensitiveInfo reports whether sensitive info detection drove this reason.
func (r Reason) IsSensitiveInfo() bool { return r.Type == ReasonSensitiveInfo }

// IsPromptInjection reports whether prompt injection detection drove this reason.
func (r Reason) IsPromptInjection() bool { return r.Type == ReasonPromptInjection }

// IsFilter reports whether a request filter drove this reason.
func (r Reason) IsFilter() bool { return r.Type == ReasonFilter }

// IsError reports whether an error drove this reason.
func (r Reason) IsError() bool { return r.Type == ReasonError }

// RateLimitReason contains details for a rate limit decision.
type RateLimitReason struct {
	Max             int `json:"max,omitempty"`
	Remaining       int `json:"remaining,omitempty"`
	ResetInSeconds  int `json:"resetInSeconds,omitempty"`
	WindowInSeconds int `json:"windowInSeconds,omitempty"`
}

// BotReason contains details for a bot detection decision.
type BotReason struct {
	Allowed  []string `json:"allowed,omitempty"`
	Denied   []string `json:"denied,omitempty"`
	Verified bool     `json:"verified,omitempty"`
	Spoofed  bool     `json:"spoofed,omitempty"`
}

// ShieldReason contains details for a Shield decision.
type ShieldReason struct {
	Triggered  bool `json:"shieldTriggered,omitempty"`
	Suspicious bool `json:"suspicious,omitempty"`
}

// EmailReason contains details for an email validation decision.
type EmailReason struct {
	Types []EmailType `json:"types,omitempty"`
}

// IdentifiedEntity describes a sensitive information entity found in text.
type IdentifiedEntity struct {
	Type  EntityType `json:"identifiedType,omitempty"`
	Start int        `json:"start,omitempty"`
	End   int        `json:"end,omitempty"`
}

// SensitiveInfoReason contains sensitive information detection results.
type SensitiveInfoReason struct {
	Allowed []IdentifiedEntity `json:"allowed,omitempty"`
	Denied  []IdentifiedEntity `json:"denied,omitempty"`
}

// PromptInjectionReason contains prompt injection detection results.
type PromptInjectionReason struct {
	Detected    bool `json:"injectionDetected,omitempty"`
	TotalTokens int  `json:"totalTokens,omitempty"`
}

// FilterReason contains request filter match results.
type FilterReason struct {
	MatchedExpressions      []string `json:"matchedExpressions,omitempty"`
	UndeterminedExpressions []string `json:"undeterminedExpressions,omitempty"`
}

// RuleResult is the per-rule result included in a request decision.
type RuleResult struct {
	RuleID     string
	State      RuleState
	Conclusion Conclusion
	Reason     Reason
	// TTL is the number of seconds the per-rule result can be cached.
	TTL         int
	Fingerprint string
}

// IPDetails contains geolocation, network, and reputation details for a request IP.
type IPDetails struct {
	Latitude       float64           `json:"latitude,omitempty"`
	Longitude      float64           `json:"longitude,omitempty"`
	AccuracyRadius int32             `json:"accuracyRadius,omitempty"`
	Timezone       string            `json:"timezone,omitempty"`
	PostalCode     string            `json:"postalCode,omitempty"`
	City           string            `json:"city,omitempty"`
	Region         string            `json:"region,omitempty"`
	Country        string            `json:"country,omitempty"`
	CountryName    string            `json:"countryName,omitempty"`
	Continent      string            `json:"continent,omitempty"`
	ContinentName  string            `json:"continentName,omitempty"`
	ASN            string            `json:"asn,omitempty"`
	ASNName        string            `json:"asnName,omitempty"`
	ASNDomain      string            `json:"asnDomain,omitempty"`
	ASNType        string            `json:"asnType,omitempty"`
	ASNCountry     string            `json:"asnCountry,omitempty"`
	Service        string            `json:"service,omitempty"`
	IsHosting      bool              `json:"isHosting,omitempty"`
	IsVPN          bool              `json:"isVpn,omitempty"`
	IsProxy        bool              `json:"isProxy,omitempty"`
	IsTor          bool              `json:"isTor,omitempty"`
	IsRelay        bool              `json:"isRelay,omitempty"`
	IsAbuser       bool              `json:"isAbuser,omitempty"`
	Bots           map[string]string `json:"bots,omitempty"`
}
