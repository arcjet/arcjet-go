package arcjet

import (
	"encoding/json"
	"strconv"

	"google.golang.org/protobuf/encoding/protojson"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

type guardRuleSubmissionWire struct {
	ConfigID string  `json:"configId"`
	InputID  string  `json:"inputId"`
	Label    *string `json:"label,omitempty"`
	// MetadataJSON carries per-key JSON-encoded metadata. The legacy plain-string
	// `metadata` field is deliberately not written: the server prefers this one
	// and falls back to the legacy map only for older SDKs.
	MetadataJSON map[string]string `json:"metadataJson,omitempty"`
	Rule         map[string]any    `json:"rule"`
	Mode         string            `json:"mode"`

	// metadata is the caller's un-encoded metadata. Unexported so it is not
	// serialized: Guard encodes it once it knows the rule's index, which the
	// warning message needs.
	metadata Metadata
}

type guardResponseWire struct {
	Decision guardDecisionWire `json:"decision"`
	// The proto/wire field is named "errors" but carries request-validation
	// diagnostics (the decision is still valid) — surfaced as
	// GuardDecision.Warnings.
	Warnings []Warning `json:"errors,omitempty"`
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
	// Additive proto field; the Decide service does not emit per-rule
	// diagnostics yet, so this decodes empty until then.
	Warnings []Warning `json:"warnings,omitempty"`
}

// GuardDecision is the result of a Guard evaluation.
type GuardDecision struct {
	// ID is the server decision ID. It is empty when best-effort reporting of a
	// locally enforced decision fails.
	ID         string
	Conclusion Conclusion
	Reason     ReasonType
	Results    []GuardRuleResult
	// PolicyEvaluation reports remote-policy selection and availability.
	PolicyEvaluation *GuardPolicyEvaluation
	// PolicyResults are remote-policy results, separate from positional SDK rule Results.
	PolicyResults []GuardPolicyResult
	// Warnings are decision-level diagnostics from request validation (e.g. an
	// invalid metadata key that was stripped). The decision is still valid;
	// warnings never change the conclusion.
	Warnings []Warning
}

// IsAllowed reports whether Arcjet allowed the Guard call.
func (d GuardDecision) IsAllowed() bool {
	return d.Conclusion == ConclusionAllow
}

// IsDenied reports whether Arcjet denied the Guard call.
func (d GuardDecision) IsDenied() bool {
	return d.Conclusion == ConclusionDeny
}

// ErrorResults returns the rule results that errored — rules (or the decision
// itself) that could not be processed. Empty when nothing errored. Each carries
// its *ArcjetError in Error; correlate one to a rule via ConfigID/InputID.
// Arcjet fails open, so an errored result is still ALLOW.
func (d GuardDecision) ErrorResults() []GuardRuleResult {
	var out []GuardRuleResult
	for _, r := range d.Results {
		if r.Error != nil {
			out = append(out, r)
		}
	}
	for _, r := range d.PolicyResults {
		if r.Error != nil {
			out = append(out, erroredGuardRuleResult("", "", r.Error.Code, r.Error.Message))
		}
	}
	if d.PolicyEvaluation != nil && (d.PolicyEvaluation.Status == GuardPolicyStatusIncomplete || d.PolicyEvaluation.Status == GuardPolicyStatusUnavailable) {
		out = append(out, erroredGuardRuleResult("", "", "REMOTE_POLICY_UNAVAILABLE", "remote Guard policy was unavailable"))
	}
	return out
}

// GuardPolicyStatus is the aggregate remote-policy evaluation status.
type GuardPolicyStatus string

const (
	// GuardPolicyStatusUnknown represents an unspecified or future status.
	GuardPolicyStatusUnknown GuardPolicyStatus = "UNKNOWN"
	// GuardPolicyStatusNotConfigured means no remote policy matched the label.
	GuardPolicyStatusNotConfigured GuardPolicyStatus = "NOT_CONFIGURED"
	// GuardPolicyStatusApplied means the remote policy was fully evaluated.
	GuardPolicyStatusApplied GuardPolicyStatus = "APPLIED"
	// GuardPolicyStatusIncomplete means required policy evaluation was incomplete.
	GuardPolicyStatusIncomplete GuardPolicyStatus = "INCOMPLETE"
	// GuardPolicyStatusUnavailable means the remote policy could not be evaluated.
	GuardPolicyStatusUnavailable GuardPolicyStatus = "UNAVAILABLE"
)

// GuardPolicyEvaluation describes remote-policy selection for a Guard call.
type GuardPolicyEvaluation struct {
	Revision        string            `json:"revision"`
	Status          GuardPolicyStatus `json:"status"`
	RefreshRequired bool              `json:"refreshRequired"`
}

// GuardPolicyResult is one remotely configured rule result. Variant fields are
// nil unless that variant was evaluated; unknown variants fail open.
type GuardPolicyResult struct {
	ResultID             string                           `json:"resultId"`
	PolicyID             string                           `json:"policyId"`
	PolicyRevision       string                           `json:"policyRevision"`
	RuleID               string                           `json:"ruleId"`
	Type                 GuardRuleType                    `json:"type"`
	Mode                 Mode                             `json:"mode"`
	Execution            GuardRuleExecution               `json:"execution"`
	Source               GuardRuleSource                  `json:"source"`
	Conclusion           Conclusion                       `json:"conclusion"`
	Reason               ReasonType                       `json:"reason"`
	PromptInjection      *GuardPromptResult               `json:"promptInjection,omitempty"`
	AllowedStringValues  *GuardStringConstraintResult     `json:"allowedStringValues,omitempty"`
	DeniedStringValues   *GuardStringConstraintResult     `json:"deniedStringValues,omitempty"`
	StringLength         *GuardStringConstraintResult     `json:"stringLength,omitempty"`
	StringListMembership *GuardStringListMembershipResult `json:"stringListMembership,omitempty"`
	LocalSensitiveInfo   *GuardSensitiveInfoResult        `json:"localSensitiveInfo,omitempty"`
	Error                *ArcjetError                     `json:"error,omitempty"`
	NotRun               bool                             `json:"notRun,omitempty"`
}

// GuardRuleExecution identifies where a remote rule was evaluated.
type GuardRuleExecution string

const (
	GuardRuleExecutionUnknown GuardRuleExecution = "UNKNOWN"
	GuardRuleExecutionSDK     GuardRuleExecution = "SDK"
	GuardRuleExecutionServer  GuardRuleExecution = "SERVER"
)

// GuardRuleSource identifies where a rule was configured.
type GuardRuleSource string

const (
	GuardRuleSourceRemote GuardRuleSource = "REMOTE"
)

// GuardStringMatchOperator identifies string matching semantics.
type GuardStringMatchOperator string

const (
	GuardStringMatchOperatorExact       GuardStringMatchOperator = "EXACT"
	GuardStringMatchOperatorEmailDomain GuardStringMatchOperator = "EMAIL_DOMAIN"
	GuardStringMatchOperatorUnknown     GuardStringMatchOperator = "UNKNOWN"
)

type GuardStringConstraintResult struct {
	Conclusion    Conclusion                `json:"conclusion"`
	MatchOperator *GuardStringMatchOperator `json:"matchOperator,omitempty"`
}

// GuardStringListMembershipResult contains a string-list membership result.
type GuardStringListMembershipResult struct {
	Conclusion Conclusion `json:"conclusion"`
	Matched    bool       `json:"matched"`
}

// HasFailedOpen reports whether this decision returned ALLOW only because a
// rule or the decision could not be processed — i.e. it failed open. Gate a
// fail-closed policy on this:
//
//	if decision.HasFailedOpen() {
//		return deny()
//	}
//
// "Failed open" describes an outcome of this decision, not the policy
// configuration.
func (d GuardDecision) HasFailedOpen() bool {
	return d.Conclusion == ConclusionAllow && len(d.ErrorResults()) > 0
}

// Err returns the first per-rule ArcjetError carried by this decision, or nil
// if no rule errored. Warnings are not errors and are not returned here. Useful
// with errors.Is / errors.As when bubbling up Arcjet errors to handlers.
func (d GuardDecision) Err() error {
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
	// Warnings are per-rule diagnostics: this rule was processed correctly
	// (the result is trustworthy) but something about it should be fixed.
	// Informational; never changes the rule's conclusion. Empty until the
	// Decide service emits per-rule diagnostics.
	Warnings []Warning
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
	Conclusion Conclusion         `json:"conclusion"`
	Detected   bool               `json:"detected"`
	Billing    *GuardBillingUsage `json:"billing,omitempty"`
}

// GuardModerateContentResult contains Guard content moderation result details.
// Detected is the binary verdict; Billing is optional usage in text_units.
type GuardModerateContentResult struct {
	Conclusion Conclusion         `json:"conclusion"`
	Detected   bool               `json:"detected"`
	Billing    *GuardBillingUsage `json:"billing,omitempty"`
}

// GuardBillingUsage contains metered usage for a Guard rule evaluation.
type GuardBillingUsage struct {
	Unit  string `json:"unit"`
	Count uint64 `json:"count"`
}

// UnmarshalJSON accepts the quoted uint64 representation emitted by
// protojson while retaining the natural uint64 public API.
func (b *GuardBillingUsage) UnmarshalJSON(data []byte) error {
	var wire struct {
		Unit  string          `json:"unit"`
		Count json.RawMessage `json:"count"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	b.Unit = wire.Unit
	if len(wire.Count) == 0 {
		b.Count = 0
		return nil
	}
	var quoted string
	if err := json.Unmarshal(wire.Count, &quoted); err == nil {
		count, err := strconv.ParseUint(quoted, 10, 64)
		if err != nil {
			return err
		}
		b.Count = count
		return nil
	}
	return json.Unmarshal(wire.Count, &b.Count)
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
		Warnings:   warningsFromWire(resp.Warnings),
	}
}

// guardErrorDecision synthesizes a fail-open ALLOW decision carrying a single
// errored rule result. Used when the SDK cannot obtain a usable decision (no
// network, empty or malformed response).
//
// The failure is surfaced as a rule-level error — not a top-level Warning — so
// it travels the same channel as a server-reported rule evaluation error: a
// degraded signal a fail-closed caller detects via HasFailedOpen()/
// ErrorResults(), never a benign request-validation diagnostic.
func guardErrorDecision(code, message string) GuardDecision {
	return GuardDecision{
		Conclusion: ConclusionAllow,
		Reason:     ReasonError,
		Results:    []GuardRuleResult{erroredGuardRuleResult("", "", code, message)},
	}
}

// erroredGuardRuleResult builds the fail-open errored result for a rule (or
// the decision itself) that could not be processed. ConfigID/InputID are set
// when the failing rule is known, so rule-level correlation still works.
func erroredGuardRuleResult(configID, inputID, code, message string) GuardRuleResult {
	return GuardRuleResult{
		ConfigID:   configID,
		InputID:    inputID,
		Conclusion: ConclusionAllow,
		Reason:     ReasonError,
		Error:      &ArcjetError{Code: code, Message: message},
	}
}

// warningsFromWire copies the decoded wire warnings into a fresh slice,
// preserving exactly what the server sent. The values arrive via
// protojson.Marshal -> json.Unmarshal from a validated proto, so the fields are
// always well-typed strings; a copy here keeps the public Warnings slice
// independent of the wire struct without mutating server-provided values.
func warningsFromWire(in []Warning) []Warning {
	if len(in) == 0 {
		return nil
	}
	return append([]Warning(nil), in...)
}

func guardDecisionFromProto(resp *decidev2.GuardResponse) GuardDecision {
	if resp == nil {
		return guardErrorDecision("NO_DECISION", "empty guard response")
	}
	decision := resp.GetDecision()
	if decision == nil {
		return guardErrorDecision("NO_DECISION", "empty guard response")
	}
	// Keep the mature SDK-rule conversion independent while converting the new
	// remote-policy surface directly from generated protobuf values.
	data, err := protojson.Marshal(resp)
	if err != nil {
		return guardErrorDecision("TRANSPORT_ERROR", err.Error())
	}
	var wire guardResponseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return guardErrorDecision("TRANSPORT_ERROR", err.Error())
	}
	out := wire.toGuardDecision()
	if p := decision.GetPolicyEvaluation(); p != nil {
		out.PolicyEvaluation = &GuardPolicyEvaluation{Revision: p.GetRevision(), Status: policyStatus(p.GetStatus()), RefreshRequired: p.GetRefreshRequired()}
	}
	out.PolicyResults = make([]GuardPolicyResult, 0, len(decision.GetPolicyRuleResults()))
	for _, p := range decision.GetPolicyRuleResults() {
		out.PolicyResults = append(out.PolicyResults, policyResultFromProto(p))
	}
	return out
}

func policyStatus(s decidev2.GuardPolicyStatus) GuardPolicyStatus {
	switch s {
	case decidev2.GuardPolicyStatus_GUARD_POLICY_STATUS_NOT_CONFIGURED:
		return GuardPolicyStatusNotConfigured
	case decidev2.GuardPolicyStatus_GUARD_POLICY_STATUS_APPLIED:
		return GuardPolicyStatusApplied
	case decidev2.GuardPolicyStatus_GUARD_POLICY_STATUS_INCOMPLETE:
		return GuardPolicyStatusIncomplete
	case decidev2.GuardPolicyStatus_GUARD_POLICY_STATUS_UNAVAILABLE:
		return GuardPolicyStatusUnavailable
	default:
		return GuardPolicyStatusUnknown
	}
}

func policyConclusion(c decidev2.GuardConclusion) Conclusion {
	if c == decidev2.GuardConclusion_GUARD_CONCLUSION_DENY {
		return ConclusionDeny
	}
	return ConclusionAllow
}

func policyRuleType(t decidev2.GuardRuleType) GuardRuleType {
	switch t {
	case decidev2.GuardRuleType_GUARD_RULE_TYPE_PROMPT_INJECTION:
		return GuardRuleTypePromptInjection
	case decidev2.GuardRuleType_GUARD_RULE_TYPE_ALLOWED_STRING_VALUES:
		return GuardRuleTypeAllowedStringValues
	case decidev2.GuardRuleType_GUARD_RULE_TYPE_DENIED_STRING_VALUES:
		return GuardRuleTypeDeniedStringValues
	case decidev2.GuardRuleType_GUARD_RULE_TYPE_STRING_LENGTH:
		return GuardRuleTypeStringLength
	case decidev2.GuardRuleType_GUARD_RULE_TYPE_STRING_LIST_MEMBERSHIP:
		return GuardRuleTypeStringListMembership
	case decidev2.GuardRuleType_GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO:
		return GuardRuleTypeLocalSensitiveInfo
	default:
		return GuardRuleTypeUnknown
	}
}

func policyResultFromProto(p *decidev2.GuardPolicyRuleResult) GuardPolicyResult {
	r := GuardPolicyResult{Conclusion: ConclusionAllow, Source: GuardRuleSourceRemote}
	if p == nil {
		return r
	}
	r.ResultID, r.PolicyID, r.PolicyRevision, r.RuleID = p.GetResultId(), p.GetPolicyId(), p.GetPolicyRevision(), p.GetRuleId()
	r.Type = policyRuleType(p.GetType())
	if p.GetMode() == decidev2.GuardRuleMode_GUARD_RULE_MODE_DRY_RUN {
		r.Mode = ModeDryRun
	} else {
		r.Mode = ModeLive
	}
	switch p.GetExecution() {
	case decidev2.GuardRuleExecution_GUARD_RULE_EXECUTION_SDK:
		r.Execution = GuardRuleExecutionSDK
	case decidev2.GuardRuleExecution_GUARD_RULE_EXECUTION_SERVER:
		r.Execution = GuardRuleExecutionServer
	default:
		r.Execution = GuardRuleExecutionUnknown
	}
	setConstraint := func(v *decidev2.ResultStringConstraint, includeOperator bool) *GuardStringConstraintResult {
		op := GuardStringMatchOperatorUnknown
		switch v.GetMatchOperator() {
		case decidev2.GuardStringMatchOperator_GUARD_STRING_MATCH_OPERATOR_UNSPECIFIED, decidev2.GuardStringMatchOperator_GUARD_STRING_MATCH_OPERATOR_EXACT:
			op = GuardStringMatchOperatorExact
		case decidev2.GuardStringMatchOperator_GUARD_STRING_MATCH_OPERATOR_EMAIL_DOMAIN:
			op = GuardStringMatchOperatorEmailDomain
		}
		result := &GuardStringConstraintResult{Conclusion: policyConclusion(v.GetConclusion())}
		if includeOperator {
			result.MatchOperator = &op
		}
		return result
	}
	switch v := p.GetResult().(type) {
	case *decidev2.GuardPolicyRuleResult_PromptInjection:
		r.PromptInjection = &GuardPromptResult{Conclusion: policyConclusion(v.PromptInjection.GetConclusion()), Detected: v.PromptInjection.GetDetected()}
		r.Conclusion = r.PromptInjection.Conclusion
		r.Reason = ReasonPromptInjection
	case *decidev2.GuardPolicyRuleResult_AllowedStringValues:
		r.AllowedStringValues = setConstraint(v.AllowedStringValues, true)
		r.Conclusion = r.AllowedStringValues.Conclusion
		r.Reason = ReasonInputConstraint
	case *decidev2.GuardPolicyRuleResult_DeniedStringValues:
		r.DeniedStringValues = setConstraint(v.DeniedStringValues, true)
		r.Conclusion = r.DeniedStringValues.Conclusion
		r.Reason = ReasonInputConstraint
	case *decidev2.GuardPolicyRuleResult_StringLength:
		r.StringLength = setConstraint(v.StringLength, false)
		r.Conclusion = r.StringLength.Conclusion
		r.Reason = ReasonInputConstraint
	case *decidev2.GuardPolicyRuleResult_StringListMembership:
		r.StringListMembership = &GuardStringListMembershipResult{Conclusion: policyConclusion(v.StringListMembership.GetConclusion()), Matched: v.StringListMembership.GetMatched()}
		r.Conclusion = r.StringListMembership.Conclusion
		r.Reason = ReasonInputConstraint
	case *decidev2.GuardPolicyRuleResult_LocalSensitiveInfo:
		x := v.LocalSensitiveInfo
		types := make([]EntityType, len(x.GetDetectedEntityTypes()))
		for i, t := range x.GetDetectedEntityTypes() {
			types[i] = EntityType(t)
		}
		r.LocalSensitiveInfo = &GuardSensitiveInfoResult{Conclusion: policyConclusion(x.GetConclusion()), Detected: x.GetDetected(), DetectedEntityTypes: types}
		r.Conclusion = r.LocalSensitiveInfo.Conclusion
		r.Reason = ReasonSensitiveInfo
	case *decidev2.GuardPolicyRuleResult_Error:
		r.Error = &ArcjetError{Code: v.Error.GetCode(), Message: v.Error.GetMessage()}
		r.Reason = ReasonError
	case *decidev2.GuardPolicyRuleResult_NotRun:
		r.NotRun = true
		r.Reason = ReasonNotRun
	}
	return r
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
		Warnings:           warningsFromWire(r.Warnings),
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
	case "GUARD_RULE_TYPE_ALLOWED_STRING_VALUES":
		return GuardRuleTypeAllowedStringValues
	case "GUARD_RULE_TYPE_DENIED_STRING_VALUES":
		return GuardRuleTypeDeniedStringValues
	case "GUARD_RULE_TYPE_STRING_LENGTH":
		return GuardRuleTypeStringLength
	case "GUARD_RULE_TYPE_STRING_LIST_MEMBERSHIP":
		return GuardRuleTypeStringListMembership
	case "GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO":
		return GuardRuleTypeLocalSensitiveInfo
	case "GUARD_RULE_TYPE_LOCAL_CUSTOM":
		return GuardRuleTypeLocalCustom
	default:
		return GuardRuleType(s)
	}
}
