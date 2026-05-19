package arcjet

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"sync"

	localbot "github.com/arcjet/arcjet-go/internal/local/bot"
	localemail "github.com/arcjet/arcjet-go/internal/local/emailvalidator"
	localfilter "github.com/arcjet/arcjet-go/internal/local/filter"
	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

// Local WebAssembly evaluation.
//
// This package matches the pattern used by the @arcjet/analyze module in
// arcjet-js: a compiled Wasm factory is created once per kind (bot, email,
// filter) and reused across requests, but a fresh module instance is created
// for every evaluation and closed when the call returns. The factory cache
// amortizes compilation; per-call instantiation gives clean isolation between
// concurrent requests at acceptable cost on wazero. See
// https://github.com/arcjet/arcjet-js/tree/main/analyze for the reference
// implementation.

type localDecision struct {
	decision *decidev1.Decision
}

type localKind uint8

const (
	localKindEmail localKind = 1 << iota
	localKindBot
	localKindFilter
)

func (d *localDecision) liveDeny() bool {
	return d != nil && d.decision.GetConclusion() == decidev1.Conclusion_CONCLUSION_DENY
}

type localEvaluator struct {
	emailMu      sync.Mutex
	emailFactory *localemail.EmailValidatorFactory
	emailErr     error

	botMu      sync.Mutex
	botFactory *localbot.BotFactory
	botErr     error

	filterMu      sync.Mutex
	filterFactory *localfilter.FilterFactory
	filterErr     error
}

func newLocalEvaluator(ctx context.Context, rules []Rule) (*localEvaluator, error) {
	evaluator := &localEvaluator{}
	if err := evaluator.warm(ctx, rules); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func (e *localEvaluator) warm(ctx context.Context, rules []Rule) error {
	var kinds localKind
	for _, rule := range rules {
		if rule != nil {
			kinds |= rule.localKind()
		}
	}
	if kinds&localKindEmail != 0 {
		if _, err := e.email(ctx); err != nil {
			return err
		}
	}
	if kinds&localKindBot != 0 {
		if _, err := e.bot(ctx); err != nil {
			return err
		}
	}
	if kinds&localKindFilter != 0 {
		if _, err := e.filter(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (e *localEvaluator) validateEmail(ctx context.Context, opts EmailOptions, details ProtectDetails, protectOpts ProtectOptions) (*localDecision, error) {
	email := details.Email
	if protectOpts.Email != "" {
		email = protectOpts.Email
	}
	if email == "" {
		return nil, nil
	}
	factory, err := e.email(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := factory.Instantiate(ctx)
	if err != nil {
		return nil, err
	}
	defer inst.Close(ctx)

	config := emailConfig(opts)
	result, err := inst.IsValidEmail(ctx, email, config)
	if err != nil {
		return nil, err
	}
	var decision struct {
		Decision string   `json:"decision"`
		Blocked  []string `json:"blocked"`
	}
	if err := json.Unmarshal([]byte(result), &decision); err != nil {
		return nil, err
	}
	if !strings.EqualFold(decision.Decision, "Denied") {
		return nil, nil
	}
	reason := &decidev1.Reason{Reason: &decidev1.Reason_Email{
		Email: &decidev1.EmailReason{EmailTypes: emailTypes(decision.Blocked)},
	}}
	return localDeny("local_email", opts.Mode, 0, reason), nil
}

func (e *localEvaluator) detectBot(ctx context.Context, opts BotOptions, details ProtectDetails) (*localDecision, error) {
	factory, err := e.bot(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := factory.Instantiate(ctx)
	if err != nil {
		return nil, err
	}
	defer inst.Close(ctx)

	request, err := jsonMarshal(localBotRequest(details))
	if err != nil {
		return nil, err
	}
	var config any
	if len(opts.Deny) > 0 {
		config = localbot.DeniedBotConfig{Entities: botEntities(opts.Deny)}
	} else {
		config = localbot.AllowedBotConfig{Entities: botEntities(opts.Allow)}
	}
	result, err := inst.Detect(ctx, string(request), config)
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
	factory, err := e.filter(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := factory.Instantiate(ctx)
	if err != nil {
		return nil, err
	}
	defer inst.Close(ctx)

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

func (e *localEvaluator) email(ctx context.Context) (*localemail.EmailValidatorFactory, error) {
	e.emailMu.Lock()
	defer e.emailMu.Unlock()
	if e.emailFactory != nil || e.emailErr != nil {
		return e.emailFactory, e.emailErr
	}
	e.emailFactory, e.emailErr = localemail.NewEmailValidatorFactory(ctx, failOpenEmailOverrides{})
	return e.emailFactory, e.emailErr
}

func (e *localEvaluator) bot(ctx context.Context) (*localbot.BotFactory, error) {
	e.botMu.Lock()
	defer e.botMu.Unlock()
	if e.botFactory != nil || e.botErr != nil {
		return e.botFactory, e.botErr
	}
	e.botFactory, e.botErr = localbot.NewBotFactory(ctx, noopBotIdentifier{}, noopBotVerifier{})
	return e.botFactory, e.botErr
}

func (e *localEvaluator) filter(ctx context.Context) (*localfilter.FilterFactory, error) {
	e.filterMu.Lock()
	defer e.filterMu.Unlock()
	if e.filterFactory != nil || e.filterErr != nil {
		return e.filterFactory, e.filterErr
	}
	e.filterFactory, e.filterErr = localfilter.NewFilterFactory(ctx, noopFilterOverrides{})
	return e.filterFactory, e.filterErr
}

func (e *localEvaluator) close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.emailMu.Lock()
	if e.emailFactory != nil {
		e.emailFactory.Close(ctx)
		e.emailFactory = nil
	}
	e.emailMu.Unlock()

	e.botMu.Lock()
	if e.botFactory != nil {
		e.botFactory.Close(ctx)
		e.botFactory = nil
	}
	e.botMu.Unlock()

	e.filterMu.Lock()
	if e.filterFactory != nil {
		e.filterFactory.Close(ctx)
		e.filterFactory = nil
	}
	e.filterMu.Unlock()

	return nil
}

type failOpenEmailOverrides struct{}

func (failOpenEmailOverrides) IsFreeEmail(context.Context, string) bool       { return false }
func (failOpenEmailOverrides) IsDisposableEmail(context.Context, string) bool { return false }
func (failOpenEmailOverrides) HasMxRecords(context.Context, string) bool      { return true }
func (failOpenEmailOverrides) HasGravatar(context.Context, string) bool       { return false }

type noopBotIdentifier struct{}

func (noopBotIdentifier) Detect(context.Context, string) (string, bool) { return "", false }

type noopBotVerifier struct{}

func (noopBotVerifier) Verify(context.Context, string, string) localbot.ValidatorResponse {
	return localbot.Unverifiable
}

type noopFilterOverrides struct{}

func (noopFilterOverrides) IpLookup(context.Context, string) (string, bool) { return "", false }

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

func emailConfig(opts EmailOptions) any {
	requireTLD := true
	if opts.RequireTopLevelDomain != nil {
		requireTLD = *opts.RequireTopLevelDomain
	}
	allowDomainLiteral := false
	if opts.AllowDomainLiteral != nil {
		allowDomainLiteral = *opts.AllowDomainLiteral
	}
	if len(opts.Allow) > 0 {
		return localemail.AllowEmailValidationConfig{
			RequireTopLevelDomain: requireTLD,
			AllowDomainLiteral:    allowDomainLiteral,
			Allow:                 emailWire(opts.Allow),
		}
	}
	return localemail.DenyEmailValidationConfig{
		RequireTopLevelDomain: requireTLD,
		AllowDomainLiteral:    allowDomainLiteral,
		Deny:                  emailWire(opts.Deny),
	}
}

func emailWire(values []EmailType) []string {
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
		key := "EMAIL_TYPE_" + strings.ToUpper(value)
		if enum, ok := decidev1.EmailType_value[key]; ok {
			out = append(out, decidev1.EmailType(enum))
		}
	}
	return out
}

func botEntities(values []string) []localbot.BotEntity {
	// localbot.BotEntity is a string alias.
	out := make([]localbot.BotEntity, len(values))
	copy(out, values)
	return out
}
