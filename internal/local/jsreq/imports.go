package jsreq

import "context"

// Callbacks lets callers override the default fail-open import
// implementations. Any nil field uses a built-in default.
//
// Mirrors arcjet-py's `ImportCallbacks` so the user-visible custom-detect
// hook has parity across SDKs.
type Callbacks struct {
	// DetectSensitiveInfo classifies tokens that the native analyzer didn't
	// recognise. Return nil for a token to leave it unclassified.
	DetectSensitiveInfo func(ctx context.Context, tokens []string) []SensitiveInfoEntity
}

// NewFactory compiles the js_req component and wires its host import
// callbacks, applying fail-open defaults for any callback left unset.
//
// Mirrors arcjet-py's wire_imports and arcjet-js's createCoreImports:
// callbacks in, a ready-to-instantiate factory out. Keeping the
// five-interface wiring inside this package means callers never handle
// the import interfaces individually.
func NewFactory(ctx context.Context, cb Callbacks) (*JsReqFactory, error) {
	return NewJsReqFactory(
		ctx,
		defaultEmailOverrides{},
		sensitiveInfoIdentifier{detect: cb.DetectSensitiveInfo},
		defaultBotVerifier{},
		defaultBotIdentifier{},
		defaultFilterOverrides{},
	)
}

// defaultEmailOverrides returns Unknown for every email-validation query.
// The wasm analyzer treats Unknown as "skip", giving fail-open behavior.
type defaultEmailOverrides struct{}

func (defaultEmailOverrides) IsFreeEmail(context.Context, string) EmailValidatorOverridesValidatorResponse {
	return Unknown
}
func (defaultEmailOverrides) IsDisposableEmail(context.Context, string) EmailValidatorOverridesValidatorResponse {
	return Unknown
}
func (defaultEmailOverrides) HasMxRecords(context.Context, string) EmailValidatorOverridesValidatorResponse {
	return Unknown
}
func (defaultEmailOverrides) HasGravatar(context.Context, string) EmailValidatorOverridesValidatorResponse {
	return Unknown
}

type sensitiveInfoIdentifier struct {
	detect func(ctx context.Context, tokens []string) []SensitiveInfoEntity
}

func (s sensitiveInfoIdentifier) Detect(ctx context.Context, tokens []string) []*SensitiveInfoEntity {
	if s.detect == nil {
		return make([]*SensitiveInfoEntity, len(tokens))
	}
	raw := s.detect(ctx, tokens)
	// The wasm callback expects exactly one slot per input token. If a
	// user callback returns the wrong arity we pad/truncate to keep the
	// component happy rather than panicking — the per-slot value can still
	// be nil to mean "unclassified".
	out := make([]*SensitiveInfoEntity, len(tokens))
	for i := 0; i < len(tokens) && i < len(raw); i++ {
		if raw[i] != nil {
			out[i] = &raw[i]
		}
	}
	return out
}

type defaultBotVerifier struct{}

func (defaultBotVerifier) Verify(context.Context, string, string) VerifyBotValidatorResponse {
	return Unverifiable
}

type defaultBotIdentifier struct{}

func (defaultBotIdentifier) Detect(context.Context, string) []BotEntity {
	return nil
}

type defaultFilterOverrides struct{}

func (defaultFilterOverrides) IpLookup(context.Context, string) *string {
	return nil
}
