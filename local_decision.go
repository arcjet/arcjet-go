package arcjet

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/arcjet/arcjet-go/internal/local/jsreq"
	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

// Local WebAssembly evaluation.
//
// Mirrors arcjet-py and arcjet-js: the bindings_js_req WebAssembly
// component is the single source of truth for bot detection, email
// validation, filter matching, and sensitive-info detection. The factory
// is compiled once at client construction time and instances are
// created per request for clean concurrent isolation.

type localDecision struct {
	decision *decidev1.Decision
}

type localKind uint8

const (
	localKindEmail localKind = 1 << iota
	localKindBot
	localKindFilter
	localKindSensitiveInfo
)

func (d *localDecision) liveDeny() bool {
	return d != nil && d.decision.GetConclusion() == decidev1.Conclusion_CONCLUSION_DENY
}

type localEvaluator struct {
	mu      sync.Mutex
	factory *jsreq.JsReqFactory
}

// newLocalEvaluator compiles the shared js_req factory once, but only when
// at least one rule needs local WebAssembly evaluation. Module compilation
// is the expensive step; per-request work is limited to instantiation.
func newLocalEvaluator(ctx context.Context, rules []Rule) (*localEvaluator, error) {
	var kinds localKind
	for _, rule := range rules {
		if rule != nil {
			kinds |= rule.localKind()
		}
	}
	evaluator := &localEvaluator{}
	if kinds == 0 {
		return evaluator, nil
	}
	factory, err := jsreq.NewFactory(ctx, jsreq.Callbacks{})
	if err != nil {
		return nil, err
	}
	evaluator.factory = factory
	return evaluator, nil
}

func (e *localEvaluator) validateEmail(ctx context.Context, opts EmailOptions, details ProtectDetails, protectOpts ProtectOptions) (*localDecision, error) {
	email := details.Email
	if protectOpts.Email != "" {
		email = protectOpts.Email
	}
	if email == "" {
		return nil, nil
	}
	inst, release, err := e.instance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	result, err := inst.IsValidEmail(ctx, email, emailConfig(opts))
	if err != nil {
		return nil, err
	}
	// `Validity` is a sealed Go enum: `Valid` and `Invalid` are typed
	// constants of an unexported int type that both satisfy
	// `EmailValidity`. Comparing against the constants is the only way
	// to discriminate.
	if result.Validity != jsreq.Invalid {
		return nil, nil
	}
	reason := &decidev1.Reason{Reason: &decidev1.Reason_Email{
		Email: &decidev1.EmailReason{EmailTypes: emailTypes(result.Blocked)},
	}}
	return localDeny("local_email", opts.Mode, 0, reason), nil
}

func (e *localEvaluator) detectBot(ctx context.Context, opts BotOptions, details ProtectDetails) (*localDecision, error) {
	inst, release, err := e.instance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	request, err := jsonMarshal(localBotRequest(details))
	if err != nil {
		return nil, err
	}
	var config any
	if len(opts.Deny) > 0 {
		config = jsreq.DeniedBotConfig{Entities: stringSlice(opts.Deny)}
	} else {
		config = jsreq.AllowedBotConfig{Entities: stringSlice(opts.Allow)}
	}
	result, err := inst.DetectBot(ctx, string(request), config)
	if err != nil {
		return nil, err
	}
	if len(result.Denied) == 0 {
		return nil, nil
	}
	reason := &decidev1.Reason{Reason: &decidev1.Reason_BotV2{
		BotV2: &decidev1.BotV2Reason{
			Allowed:  result.Allowed,
			Denied:   result.Denied,
			Verified: result.Verified,
			Spoofed:  result.Spoofed,
		},
	}}
	return localDeny("local_bot", opts.Mode, 60, reason), nil
}

func (e *localEvaluator) matchFilter(ctx context.Context, opts FilterOptions, details ProtectDetails, protectOpts ProtectOptions) (*localDecision, error) {
	if len(opts.Allow) == 0 && len(opts.Deny) == 0 {
		return nil, nil
	}
	inst, release, err := e.instance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	request, err := jsonMarshal(localRequest(details))
	if err != nil {
		return nil, err
	}
	localFields := make(map[string]string, len(details.Extra)+len(protectOpts.FilterLocal))
	maps.Copy(localFields, details.Extra)
	maps.Copy(localFields, protectOpts.FilterLocal)
	fields, err := jsonMarshal(localFields)
	if err != nil {
		return nil, err
	}
	expressions := opts.Deny
	allowIfMatch := false
	if len(opts.Allow) > 0 {
		expressions = opts.Allow
		allowIfMatch = true
	}
	result, err := inst.MatchFilters(ctx, string(request), string(fields), expressions, allowIfMatch)
	if err != nil {
		return nil, err
	}
	if result.Allowed {
		return nil, nil
	}
	reason := &decidev1.Reason{Reason: &decidev1.Reason_Filter{
		Filter: &decidev1.FilterReason{
			MatchedExpressions:      append([]string(nil), result.MatchedExpressions...),
			UndeterminedExpressions: append([]string(nil), result.UndeterminedExpressions...),
		},
	}}
	return localDeny("local_filter", opts.Mode, 60, reason), nil
}

func (e *localEvaluator) detectSensitiveInfo(ctx context.Context, opts SensitiveInfoOptions, _ ProtectDetails, protectOpts ProtectOptions) (*localDecision, error) {
	if protectOpts.SensitiveInfoValue == "" {
		return nil, nil
	}
	inst, release, err := e.instance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	config := sensitiveInfoConfig(opts)
	result := inst.DetectSensitiveInfo(ctx, protectOpts.SensitiveInfoValue, config)
	if len(result.Denied) == 0 {
		return nil, nil
	}
	reason := &decidev1.Reason{Reason: &decidev1.Reason_SensitiveInfo{
		SensitiveInfo: &decidev1.SensitiveInfoReason{
			Allowed: identifiedEntitiesWire(result.Allowed),
			Denied:  identifiedEntitiesWire(result.Denied),
		},
	}}
	return localDeny("local_sensitive_info", opts.Mode, 0, reason), nil
}

func localDeny(ruleID string, mode Mode, ttl uint32, reason *decidev1.Reason) *localDecision {
	state := decidev1.RuleState_RULE_STATE_RUN
	conclusion := decidev1.Conclusion_CONCLUSION_DENY
	aggregate := decidev1.Conclusion_CONCLUSION_DENY
	if normalizeMode(mode) != ModeLive {
		state = decidev1.RuleState_RULE_STATE_DRY_RUN
		aggregate = decidev1.Conclusion_CONCLUSION_ALLOW
	}
	result := &decidev1.RuleResult{
		RuleId:     ruleID,
		State:      state,
		Conclusion: conclusion,
		Reason:     reason,
		Ttl:        ttl,
	}
	return &localDecision{decision: &decidev1.Decision{
		Id:          newTypeID("lreq"),
		Conclusion:  aggregate,
		Reason:      reason,
		RuleResults: []*decidev1.RuleResult{result},
		Ttl:         ttl,
	}}
}

// instance returns a fresh wazero instance plus a release callback. Callers
// `defer release()` to drop the instance — the underlying compiled module
// stays cached on the evaluator. Instantiation runs outside the lock so
// concurrent requests don't serialize on it.
func (e *localEvaluator) instance(ctx context.Context) (*jsreq.JsReqInstance, func(), error) {
	e.mu.Lock()
	factory := e.factory
	e.mu.Unlock()
	if factory == nil {
		return nil, func() {}, fmt.Errorf("arcjet: %w", ErrWasmClosed)
	}
	inst, err := factory.Instantiate(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	return inst, func() { inst.Close(ctx) }, nil
}

func (e *localEvaluator) close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.factory != nil {
		e.factory.Close(ctx)
		e.factory = nil
	}
	return nil
}

func localRequest(details ProtectDetails) map[string]any {
	return cleanMapAny(map[string]any{
		"ip":       details.IP,
		"method":   details.Method,
		"protocol": details.Protocol,
		"host":     details.Host,
		"path":     details.Path,
		"headers":  details.Headers,
		"cookies":  details.Cookies,
		"query":    details.Query,
		"extra":    details.Extra,
	})
}

func localBotRequest(details ProtectDetails) map[string]any {
	req := localRequest(details)
	req["crawler_name"] = ""
	req["bots"] = map[string]string{}
	return req
}

func cleanMapAny(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch value := v.(type) {
		case string:
			if value == "" {
				continue
			}
		case map[string]string:
			if len(value) == 0 {
				continue
			}
		}
		out[k] = v
	}
	return out
}

func emailConfig(opts EmailOptions) jsreq.EmailValidationConfig {
	requireTLD := true
	if opts.RequireTopLevelDomain != nil {
		requireTLD = *opts.RequireTopLevelDomain
	}
	allowDomainLiteral := false
	if opts.AllowDomainLiteral != nil {
		allowDomainLiteral = *opts.AllowDomainLiteral
	}
	if len(opts.Allow) > 0 {
		return jsreq.AllowEmailValidationConfig{
			RequireTopLevelDomain: requireTLD,
			AllowDomainLiteral:    allowDomainLiteral,
			Allow:                 stringSlice(opts.Allow),
		}
	}
	return jsreq.DenyEmailValidationConfig{
		RequireTopLevelDomain: requireTLD,
		AllowDomainLiteral:    allowDomainLiteral,
		Deny:                  stringSlice(opts.Deny),
	}
}

func sensitiveInfoConfig(opts SensitiveInfoOptions) jsreq.SensitiveInfoConfig {
	// Allow and Deny are mutually exclusive (validated upstream). An empty
	// deny list — the default — means "deny nothing", so the deny variant
	// is the right shape whenever Allow is unset.
	var entities jsreq.SensitiveInfoEntities = jsreq.SensitiveInfoEntitiesDeny{
		Value: sensitiveInfoEntitiesWire(opts.Deny),
	}
	if len(opts.Allow) > 0 {
		entities = jsreq.SensitiveInfoEntitiesAllow{Value: sensitiveInfoEntitiesWire(opts.Allow)}
	}
	return jsreq.SensitiveInfoConfig{
		Entities:         entities,
		SkipCustomDetect: true,
	}
}

// stringSlice converts a slice of a string-based named type (EmailType,
// EntityType, BotEntity, …) to []string, returning nil for empty input.
func stringSlice[T ~string](values []T) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

func emailTypes(values []string) []decidev1.EmailType {
	out := make([]decidev1.EmailType, 0, len(values))
	for _, value := range values {
		key := "EMAIL_TYPE_" + value
		if enum, ok := decidev1.EmailType_value[key]; ok {
			out = append(out, decidev1.EmailType(enum))
		}
	}
	return out
}

// sensitiveInfoEntitiesWire converts the SDK's EntityType list into the
// variant shape the wasm component expects. Custom labels fall through to
// `SensitiveInfoEntityCustom{Value: ...}`.
func sensitiveInfoEntitiesWire(values []EntityType) []jsreq.SensitiveInfoEntity {
	out := make([]jsreq.SensitiveInfoEntity, len(values))
	for i, v := range values {
		out[i] = sensitiveInfoEntityWire(v)
	}
	return out
}

func sensitiveInfoEntityWire(v EntityType) jsreq.SensitiveInfoEntity {
	switch v {
	case SensitiveInfoEmail:
		return jsreq.SensitiveInfoEntityEmail{}
	case SensitiveInfoPhoneNumber:
		return jsreq.SensitiveInfoEntityPhoneNumber{}
	case SensitiveInfoIPAddress:
		return jsreq.SensitiveInfoEntityIpAddress{}
	case SensitiveInfoCreditCardNumber:
		return jsreq.SensitiveInfoEntityCreditCardNumber{}
	default:
		return jsreq.SensitiveInfoEntityCustom{Value: string(v)}
	}
}

func identifiedEntitiesWire(entities []jsreq.DetectedSensitiveInfoEntity) []*decidev1.IdentifiedEntity {
	if len(entities) == 0 {
		return nil
	}
	out := make([]*decidev1.IdentifiedEntity, len(entities))
	for i, e := range entities {
		out[i] = &decidev1.IdentifiedEntity{
			Start:          e.Start,
			End:            e.End,
			IdentifiedType: identifiedEntityType(e.IdentifiedType),
		}
	}
	return out
}

func identifiedEntityType(t jsreq.SensitiveInfoEntity) string {
	switch v := t.(type) {
	case jsreq.SensitiveInfoEntityEmail:
		return string(SensitiveInfoEmail)
	case jsreq.SensitiveInfoEntityPhoneNumber:
		return string(SensitiveInfoPhoneNumber)
	case jsreq.SensitiveInfoEntityIpAddress:
		return string(SensitiveInfoIPAddress)
	case jsreq.SensitiveInfoEntityCreditCardNumber:
		return string(SensitiveInfoCreditCardNumber)
	case jsreq.SensitiveInfoEntityCustom:
		return v.Value
	default:
		return ""
	}
}
