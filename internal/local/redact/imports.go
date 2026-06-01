package redact

import "context"

// Callbacks lets the public redact package supply custom detection and
// replacement logic to the wasm component. Either field may be nil, in which
// case the corresponding host import is a no-op; callers gate whether the wasm
// invokes it through RedactSensitiveInfoConfig.SkipCustomDetect and
// SkipCustomRedact.
//
// Mirrors the detect/replace hooks @arcjet/redact passes to its wasm module.
type Callbacks struct {
	// Detect classifies a window of tokens. It must return one slot per input
	// token, in order; a nil slot means "not sensitive". The window size is
	// controlled by RedactSensitiveInfoConfig.ContextWindowSize.
	Detect func(ctx context.Context, tokens []string) []*SensitiveInfoEntity
	// Replace returns the replacement text for a detected entity, or nil to
	// fall back to the component's built-in redaction.
	Replace func(ctx context.Context, entity SensitiveInfoEntity, plaintext string) *string
}

// NewFactory compiles the redact component and wires its host import callbacks.
// The compiled module is expensive to build, so create one factory and reuse
// it across Redact calls.
//
// Mirrors jsreq.NewFactory: callbacks in, a ready-to-instantiate factory out.
func NewFactory(ctx context.Context, cb Callbacks) (*RedactFactory, error) {
	return NewRedactFactory(ctx, customRedact{detect: cb.Detect, replace: cb.Replace})
}

// customRedact adapts the public Callbacks to the generated IRedactCustomRedact
// interface, applying fail-open defaults for unset callbacks.
type customRedact struct {
	detect  func(ctx context.Context, tokens []string) []*SensitiveInfoEntity
	replace func(ctx context.Context, entity SensitiveInfoEntity, plaintext string) *string
}

func (c customRedact) DetectSensitiveInfo(ctx context.Context, tokens []string) []*SensitiveInfoEntity {
	if c.detect == nil {
		// One empty slot per token: nothing classified.
		return make([]*SensitiveInfoEntity, len(tokens))
	}
	raw := c.detect(ctx, tokens)
	// The component zips the result against the token window, so normalize to
	// exactly len(tokens): copy pads the tail with nil and truncates any extra.
	out := make([]*SensitiveInfoEntity, len(tokens))
	copy(out, raw)
	return out
}

func (c customRedact) RedactSensitiveInfo(ctx context.Context, entityType any, plaintext string) *string {
	if c.replace == nil {
		return nil
	}
	entity, ok := entityType.(SensitiveInfoEntity)
	if !ok {
		return nil
	}
	return c.replace(ctx, entity, plaintext)
}
