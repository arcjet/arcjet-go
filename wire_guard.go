package arcjet

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

type guardRuleSubmissionWire struct {
	ConfigID string            `json:"configId"`
	InputID  string            `json:"inputId"`
	Label    *string           `json:"label,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Rule     map[string]any    `json:"rule"`
	Mode     string            `json:"mode"`
}

type guardResponseWire struct {
	Decision guardDecisionWire `json:"decision"`
	Errors   []ArcjetError     `json:"errors,omitempty"`
}

type guardDecisionWire struct {
	ID          string                `json:"id"`
	Conclusion  string                `json:"conclusion"`
	Reason      string                `json:"reason"`
	RuleResults []guardRuleResultWire `json:"ruleResults"`
}

type guardRuleResultWire struct {
	ResultID           string                      `json:"resultId"`
	ConfigID           string                      `json:"configId"`
	InputID            string                      `json:"inputId"`
	Type               string                      `json:"type"`
	TokenBucket        *GuardTokenBucketResult     `json:"tokenBucket,omitempty"`
	FixedWindow        *GuardFixedWindowResult     `json:"fixedWindow,omitempty"`
	SlidingWindow      *GuardSlidingWindowResult   `json:"slidingWindow,omitempty"`
	PromptInjection    *GuardPromptResult          `json:"promptInjection,omitempty"`
	ModerateContent    *GuardModerateContentResult `json:"moderateContent,omitempty"`
	LocalSensitiveInfo *GuardSensitiveInfoResult   `json:"localSensitiveInfo,omitempty"`
	LocalCustom        *GuardLocalCustomResult     `json:"localCustom,omitempty"`
	Error              *ArcjetError                `json:"error,omitempty"`
	NotRun             map[string]any              `json:"notRun,omitempty"`
}

// GuardDecision is the result of a Guard evaluation.
type GuardDecision struct {
	ID         string
	Conclusion Conclusion
	Reason     ReasonType
	Results    []GuardRuleResult
	Errors     []ArcjetError
}

// IsAllowed reports whether Arcjet allowed the Guard call.
func (d GuardDecision) IsAllowed() bool {
	return d.Conclusion == ConclusionAllow
}

// IsDenied reports whether Arcjet denied the Guard call.
func (d GuardDecision) IsDenied() bool {
	return d.Conclusion == ConclusionDeny
}

// IsErrored reports whether any Guard rule or the Guard response has an
// error. Arcjet fails open — when this is true the call was allowed to
// proceed but rule evaluation was incomplete.
func (d GuardDecision) IsErrored() bool {
	if len(d.Errors) > 0 {
		return true
	}
	for _, result := range d.Results {
		if result.Error != nil {
			return true
		}
	}
	return false
}

// Err returns the first ArcjetError carried by this decision (top-level or
// per-rule) or nil if the decision did not error. Useful with errors.Is /
// errors.As when bubbling up Arcjet errors to handlers.
func (d GuardDecision) Err() error {
	if len(d.Errors) > 0 {
		return d.Errors[0]
	}
	for _, r := range d.Results {
		if r.Error != nil {
			return *r.Error
		}
	}
	return nil
}

// GuardRuleResult is the per-rule result included in a Guard decision.
type GuardRuleResult struct {
	ResultID           string
	ConfigID           string
	InputID            string
	Type               GuardRuleType
	Conclusion         Conclusion
	Reason             ReasonType
	TokenBucket        *GuardTokenBucketResult
	FixedWindow        *GuardFixedWindowResult
	SlidingWindow      *GuardSlidingWindowResult
	PromptInjection    *GuardPromptResult
	ModerateContent    *GuardModerateContentResult
	LocalSensitiveInfo *GuardSensitiveInfoResult
	LocalCustom        *GuardLocalCustomResult
	Error              *ArcjetError
	NotRun             bool
}

// GuardTokenBucketResult contains Guard token bucket result details.
type GuardTokenBucketResult struct {
	Conclusion            Conclusion `json:"conclusion"`
	RemainingTokens       int        `json:"remainingTokens"`
	MaxTokens             int        `json:"maxTokens"`
	ResetAtUnixSeconds    int64      `json:"resetAtUnixSeconds"`
	RefillRate            int        `json:"refillRate"`
	RefillIntervalSeconds int        `json:"refillIntervalSeconds"`
}

// GuardFixedWindowResult contains Guard fixed window result details.
type GuardFixedWindowResult struct {
	Conclusion         Conclusion `json:"conclusion"`
	RemainingRequests  int        `json:"remainingRequests"`
	MaxRequests        int        `json:"maxRequests"`
	ResetAtUnixSeconds int64      `json:"resetAtUnixSeconds"`
	WindowSeconds      int        `json:"windowSeconds"`
}

// GuardSlidingWindowResult contains Guard sliding window result details.
type GuardSlidingWindowResult struct {
	Conclusion         Conclusion `json:"conclusion"`
	RemainingRequests  int        `json:"remainingRequests"`
	MaxRequests        int        `json:"maxRequests"`
	ResetAtUnixSeconds int64      `json:"resetAtUnixSeconds"`
	IntervalSeconds    int        `json:"intervalSeconds"`
}

// GuardPromptResult contains Guard prompt injection result details.
type GuardPromptResult struct {
	Conclusion Conclusion `json:"conclusion"`
	Detected   bool       `json:"detected"`
}

// GuardModerateContentResult contains Guard content moderation result details.
type GuardModerateContentResult struct {
	Conclusion Conclusion `json:"conclusion"`
	Detected   bool       `json:"detected"`
}

// GuardSensitiveInfoResult contains Guard sensitive information result details.
type GuardSensitiveInfoResult struct {
	Conclusion          Conclusion   `json:"conclusion"`
	Detected            bool         `json:"detected"`
	DetectedEntityTypes []EntityType `json:"detectedEntityTypes"`
}

// GuardLocalCustomResult contains custom local Guard result details.
type GuardLocalCustomResult struct {
	Conclusion Conclusion        `json:"conclusion"`
	Data       map[string]string `json:"data,omitempty"`
}

// IsDenied reports whether this Guard rule result denied the Guard call.
func (r GuardRuleResult) IsDenied() bool {
	return r.Conclusion == ConclusionDeny
}

// IsErrored reports whether this Guard rule result contains an error.
func (r GuardRuleResult) IsErrored() bool {
	return r.Error != nil
}

func (resp guardResponseWire) toGuardDecision() GuardDecision {
	results := make([]GuardRuleResult, 0, len(resp.Decision.RuleResults))
	for _, r := range resp.Decision.RuleResults {
		results = append(results, r.toGuardRuleResult())
	}
	return GuardDecision{
		ID:         resp.Decision.ID,
		Conclusion: parseConclusion(resp.Decision.Conclusion),
		Reason:     parseGuardReason(resp.Decision.Reason),
		Results:    results,
		Errors:     append([]ArcjetError(nil), resp.Errors...),
	}
}

func guardDecisionFromProto(resp *decidev2.GuardResponse) GuardDecision {
	if resp == nil {
		return GuardDecision{
			Conclusion: ConclusionAllow,
			Reason:     ReasonError,
			Errors:     []ArcjetError{{Message: "empty guard response"}},
		}
	}
	data, err := protojson.Marshal(resp)
	if err != nil {
		return GuardDecision{
			Conclusion: ConclusionAllow,
			Reason:     ReasonError,
			Errors:     []ArcjetError{{Message: err.Error()}},
		}
	}
	var wire guardResponseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return GuardDecision{
			Conclusion: ConclusionAllow,
			Reason:     ReasonError,
			Errors:     []ArcjetError{{Message: err.Error()}},
		}
	}
	return wire.toGuardDecision()
}

func (r guardRuleResultWire) toGuardRuleResult() GuardRuleResult {
	result := GuardRuleResult{
		ResultID:           r.ResultID,
		ConfigID:           r.ConfigID,
		InputID:            r.InputID,
		Type:               parseGuardRuleType(r.Type),
		TokenBucket:        r.TokenBucket,
		FixedWindow:        r.FixedWindow,
		SlidingWindow:      r.SlidingWindow,
		PromptInjection:    r.PromptInjection,
		ModerateContent:    r.ModerateContent,
		LocalSensitiveInfo: r.LocalSensitiveInfo,
		LocalCustom:        r.LocalCustom,
		Error:              r.Error,
		NotRun:             r.NotRun != nil,
	}
	switch {
	case r.TokenBucket != nil:
		result.Conclusion = r.TokenBucket.Conclusion
		result.Reason = ReasonRateLimit
	case r.FixedWindow != nil:
		result.Conclusion = r.FixedWindow.Conclusion
		result.Reason = ReasonRateLimit
	case r.SlidingWindow != nil:
		result.Conclusion = r.SlidingWindow.Conclusion
		result.Reason = ReasonRateLimit
	case r.PromptInjection != nil:
		result.Conclusion = r.PromptInjection.Conclusion
		result.Reason = ReasonPromptInjection
	case r.ModerateContent != nil:
		result.Conclusion = r.ModerateContent.Conclusion
		result.Reason = ReasonModerateContent
	case r.LocalSensitiveInfo != nil:
		result.Conclusion = r.LocalSensitiveInfo.Conclusion
		result.Reason = ReasonSensitiveInfo
	case r.LocalCustom != nil:
		result.Conclusion = r.LocalCustom.Conclusion
		result.Reason = ReasonCustom
	case r.Error != nil:
		result.Conclusion = ConclusionAllow
		result.Reason = ReasonError
	case r.NotRun != nil:
		result.Conclusion = ConclusionAllow
		result.Reason = ReasonNotRun
	default:
		result.Conclusion = ConclusionAllow
	}
	return result
}

func parseGuardReason(s string) ReasonType {
	switch s {
	case "GUARD_REASON_RATE_LIMIT":
		return ReasonRateLimit
	case "GUARD_REASON_PROMPT_INJECTION":
		return ReasonPromptInjection
	case "GUARD_REASON_MODERATE_CONTENT":
		return ReasonModerateContent
	case "GUARD_REASON_SENSITIVE_INFO":
		return ReasonSensitiveInfo
	case "GUARD_REASON_CUSTOM":
		return ReasonCustom
	case "GUARD_REASON_ERROR":
		return ReasonError
	case "GUARD_REASON_NOT_RUN":
		return ReasonNotRun
	default:
		return ReasonUnknown
	}
}

func parseGuardRuleType(s string) GuardRuleType {
	switch s {
	case "GUARD_RULE_TYPE_TOKEN_BUCKET":
		return GuardRuleTypeTokenBucket
	case "GUARD_RULE_TYPE_FIXED_WINDOW":
		return GuardRuleTypeFixedWindow
	case "GUARD_RULE_TYPE_SLIDING_WINDOW":
		return GuardRuleTypeSlidingWindow
	case "GUARD_RULE_TYPE_PROMPT_INJECTION":
		return GuardRuleTypePromptInjection
	case "GUARD_RULE_TYPE_MODERATE_CONTENT":
		return GuardRuleTypeModerateContent
	case "GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO":
		return GuardRuleTypeLocalSensitiveInfo
	case "GUARD_RULE_TYPE_LOCAL_CUSTOM":
		return GuardRuleTypeLocalCustom
	default:
		return GuardRuleType(s)
	}
}
