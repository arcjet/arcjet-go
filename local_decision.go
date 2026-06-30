package arcjet

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

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
	mu        sync.Mutex
	factory   *jsreq.JsReqFactory
	closed    bool
	callbacks jsreq.Callbacks
}

// newLocalEvaluator returns an evaluator and eagerly compiles the shared
// js_req factory when the client has any rules. Both local evaluation and
// the per-rule cache's fingerprinting (see Client.ruleFingerprints) drive
// the WASM module, so any rule makes it a per-request dependency — compiling
// it here keeps the cold ~module-compile cost off the first Protect's hot
// path. The Guard path uses `newLazyLocalEvaluator` instead, since Guard
// rules arrive per-request rather than at client construction.
func newLocalEvaluator(ctx context.Context, rules []Rule, detect SensitiveInfoDetect) (*localEvaluator, error) {
	evaluator := newLazyLocalEvaluator(detect)
	hasRule := false
	for _, rule := range rules {
		if rule != nil {
			hasRule = true
			break
		}
	}
	if !hasRule {
		return evaluator, nil
	}
	if _, err := evaluator.factoryLazy(ctx); err != nil {
		return nil, err
	}
	return evaluator, nil
}

// newLazyLocalEvaluator returns an evaluator that defers wasm compilation
// until the first call that needs it. Used by GuardClient, which doesn't
// see its rules until each Guard call.
func newLazyLocalEvaluator(detect SensitiveInfoDetect) *localEvaluator {
	return &localEvaluator{callbacks: jsreqCallbacks(detect)}
}

// hasCustomDetect reports whether a user-supplied sensitive-info detect
// callback is wired. The wasm config uses this to flip
// `SkipCustomDetect` — leaving it true saves cycles when there's
// nothing to call.
func (e *localEvaluator) hasCustomDetect() bool {
	return e.callbacks.DetectSensitiveInfo != nil
}

// jsreqCallbacks wraps the public SensitiveInfoDetect callback in the
// jsreq-shaped form. Empty EntityType slots map to nil (unclassified);
// any other value maps to the matching built-in variant or a
// `SensitiveInfoEntityCustom{Value: ...}` for custom labels.
func jsreqCallbacks(detect SensitiveInfoDetect) jsreq.Callbacks {
	if detect == nil {
		return jsreq.Callbacks{}
	}
	return jsreq.Callbacks{
		DetectSensitiveInfo: func(ctx context.Context, tokens []string) []jsreq.SensitiveInfoEntity {
			classified := detect(ctx, tokens)
			out := make([]jsreq.SensitiveInfoEntity, len(tokens))
			for i := 0; i < len(tokens) && i < len(classified); i++ {
				if classified[i] == "" {
					continue
				}
				out[i] = sensitiveInfoEntityWire(classified[i])
			}
			return out
		},
	}
}

// fingerprint produces the per-request cache-key namespace by calling the
// bundled WASM's generate-fingerprint export. arcjet-js drives the same
// export from analyze.generateFingerprint, so for identical inputs the
// output matches byte-for-byte across SDKs.
//
// Returns an empty string when the evaluator is nil. Errors propagate to
// the caller, which treats them as "no caching for this request" rather
// than failing the protect call — the cache is an optimization, not a
// correctness boundary.
func (e *localEvaluator) fingerprint(ctx context.Context, details ProtectDetails, characteristics []string) (string, error) {
	if e == nil {
		return "", nil
	}
	inst, release, err := e.instance(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	payload, err := jsonMarshal(localRequest(details))
	if err != nil {
		return "", err
	}
	return inst.GenerateFingerprint(ctx, string(payload), characteristics)
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
	outcome, err := e.scanSensitiveInfo(ctx, protectOpts.SensitiveInfoValue, opts.Allow, opts.Deny)
	if err != nil {
		return nil, err
	}
	if len(outcome.Denied) == 0 {
		return nil, nil
	}
	reason := &decidev1.Reason{Reason: &decidev1.Reason_SensitiveInfo{
		SensitiveInfo: &decidev1.SensitiveInfoReason{
			Allowed: identifiedEntitiesWire(outcome.Allowed),
			Denied:  identifiedEntitiesWire(outcome.Denied),
		},
	}}
	return localDeny("local_sensitive_info", opts.Mode, 0, reason), nil
}

// sensitiveInfoOutcome is the shared shape both the HTTP-path
// `SensitiveInfo` rule and the Guard `GuardSensitiveInfoRule.Text`
// callback use after running the wasm analyzer.
type sensitiveInfoOutcome struct {
	Allowed   []jsreq.DetectedSensitiveInfoEntity
	Denied    []jsreq.DetectedSensitiveInfoEntity
	ElapsedMs uint64
}

func (e *localEvaluator) scanSensitiveInfo(ctx context.Context, text string, allow, deny []EntityType) (sensitiveInfoOutcome, error) {
	inst, release, err := e.instance(ctx)
	if err != nil {
		return sensitiveInfoOutcome{}, err
	}
	defer release()

	start := time.Now()
	result := inst.DetectSensitiveInfo(ctx, text, sensitiveInfoConfig(allow, deny, e.hasCustomDetect()))
	return sensitiveInfoOutcome{
		Allowed:   result.Allowed,
		Denied:    result.Denied,
		ElapsedMs: safeUint64FromInt64(time.Since(start).Milliseconds()),
	}, nil
}

func localDeny(ruleID string, mode Mode, ttl uint32, reason *decidev1.Reason) *localDecision {
	state := decidev1.RuleState_RULE_STATE_RUN
	aggregate := decidev1.Conclusion_CONCLUSION_DENY
	if normalizeMode(mode) != ModeLive {
		// Dry-run: the rule's RuleResult still records the DENY conclusion
		// (so reporting reflects what the rule detected), but the outer
		// Decision aggregates to ALLOW so the caller doesn't enforce.
		state = decidev1.RuleState_RULE_STATE_DRY_RUN
		aggregate = decidev1.Conclusion_CONCLUSION_ALLOW
	}
	return wrapRuleResult(&decidev1.RuleResult{
		RuleId:     ruleID,
		State:      state,
		Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
		Reason:     reason,
		Ttl:        ttl,
	}, aggregate)
}

// instance returns a fresh wazero instance plus a release callback. Callers
// `defer release()` to drop the instance — the underlying compiled module
// stays cached on the evaluator. Instantiation runs outside the lock so
// concurrent requests don't serialize on it.
func (e *localEvaluator) instance(ctx context.Context) (*jsreq.JsReqInstance, func(), error) {
	factory, err := e.factoryLazy(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	inst, err := factory.Instantiate(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	return inst, func() { inst.Close(ctx) }, nil
}

// factoryLazy returns the shared js_req factory, compiling it on first
// access. After `close` has run, returns ErrWasmClosed so post-teardown
// requests don't silently reopen the module.
func (e *localEvaluator) factoryLazy(ctx context.Context) (*jsreq.JsReqFactory, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, fmt.Errorf("arcjet: %w", ErrWasmClosed)
	}
	if e.factory != nil {
		return e.factory, nil
	}
	factory, err := jsreq.NewFactory(ctx, e.callbacks)
	if err != nil {
		return nil, err
	}
	e.factory = factory
	return factory, nil
}

func (e *localEvaluator) close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
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

func sensitiveInfoConfig(allow, deny []EntityType, customDetect bool) jsreq.SensitiveInfoConfig {
	// Allow and Deny are mutually exclusive (validated upstream). An empty
	// deny list — the default — means "deny nothing", so the deny variant
	// is the right shape whenever Allow is unset.
	var entities jsreq.SensitiveInfoEntities = jsreq.SensitiveInfoEntitiesDeny{
		Value: sensitiveInfoEntitiesWire(deny),
	}
	if len(allow) > 0 {
		entities = jsreq.SensitiveInfoEntitiesAllow{Value: sensitiveInfoEntitiesWire(allow)}
	}
	return jsreq.SensitiveInfoConfig{
		Entities:         entities,
		SkipCustomDetect: !customDetect,
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

// identifiedEntityTypes projects detected entities down to their type
// names, deduplicating in encounter order. Used by Guard submissions
// which carry only the type list, not start/end indices.
func identifiedEntityTypes(entities []jsreq.DetectedSensitiveInfoEntity) []string {
	if len(entities) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(entities))
	out := make([]string, 0, len(entities))
	for _, e := range entities {
		t := identifiedEntityType(e.IdentifiedType)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
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
