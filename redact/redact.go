// Package redact detects and redacts sensitive information — emails, phone
// numbers, IP addresses, credit card numbers, and custom entities — in
// arbitrary text. It runs the same WebAssembly component as the @arcjet/redact
// (JavaScript) and arcjet.redact (Python) packages, so all three SDKs redact
// identically.
//
// Redaction happens entirely in-process: the text is never sent to the Arcjet
// service. This makes redact suitable for scrubbing prompts and responses
// before they reach a third-party LLM, sanitising logs, and similar tasks.
//
// A Redactor compiles the wasm component once and is safe to reuse across many
// Redact calls. Closing it releases the wasm runtime.
package redact

import (
	"context"
	"fmt"
	"strings"

	wasmredact "github.com/arcjet/arcjet-go/internal/local/redact"
)

// Standard sensitive-information entity names recognised by the component. Any
// other string passed in Options.Entities or returned from Options.Detect is
// treated as a custom entity.
const (
	EntityEmail            = "email"
	EntityPhoneNumber      = "phone-number"
	EntityIPAddress        = "ip-address"
	EntityCreditCardNumber = "credit-card-number"
)

// Options configures a Redactor.
type Options struct {
	// Entities restricts redaction to the named entity types. When empty, every
	// detected entity is redacted. Names not in the standard set (see the Entity
	// constants) are treated as custom entities surfaced by Detect.
	Entities []string

	// ContextWindowSize is the number of adjacent tokens passed to Detect at a
	// time. Defaults to 1 when zero or negative.
	ContextWindowSize int

	// Detect optionally classifies tokens the built-in detectors miss. It is
	// called with a window of tokens (see ContextWindowSize) and must return one
	// entry per input token, in order; an empty string means "not sensitive".
	// Detected names may be custom. When nil, only the built-in detectors run.
	Detect func(tokens []string) []string

	// Replace optionally supplies replacement text for a detected entity, given
	// the entity name and the matched plaintext. Return ok=false to fall back to
	// the component's built-in redaction (e.g. "<Redacted email #0>"). When nil,
	// the built-in redaction is always used.
	Replace func(entity, plaintext string) (replacement string, ok bool)
}

// Unredact reverses a Redact result, restoring the original sensitive values
// in a string derived from the redacted text. This is useful for redacting a
// prompt before sending it to an LLM and then restoring the values in the
// response.
type Unredact func(string) string

// Redactor redacts sensitive information using the Arcjet wasm component.
type Redactor struct {
	factory           *wasmredact.RedactFactory
	entities          *[]wasmredact.SensitiveInfoEntity
	contextWindowSize uint32
	skipDetect        bool
	skipReplace       bool
}

// New compiles the redact component and returns a reusable Redactor. Compiling
// the wasm module is expensive, so create one Redactor and share it; call Close
// when done.
func New(ctx context.Context, opts Options) (*Redactor, error) {
	cb := wasmredact.Callbacks{}

	if opts.Detect != nil {
		detect := opts.Detect
		cb.Detect = func(_ context.Context, tokens []string) []*wasmredact.SensitiveInfoEntity {
			names := detect(tokens)
			out := make([]*wasmredact.SensitiveInfoEntity, len(names))
			for i, name := range names {
				if name != "" {
					e := entityFromName(name)
					out[i] = &e
				}
			}
			return out
		}
	}

	if opts.Replace != nil {
		replace := opts.Replace
		cb.Replace = func(_ context.Context, entity wasmredact.SensitiveInfoEntity, plaintext string) *string {
			if s, ok := replace(entityName(entity), plaintext); ok {
				return &s
			}
			return nil
		}
	}

	factory, err := wasmredact.NewFactory(ctx, cb)
	if err != nil {
		return nil, fmt.Errorf("arcjet/redact: compile component: %w", err)
	}

	r := &Redactor{
		factory:           factory,
		contextWindowSize: 1,
		skipDetect:        opts.Detect == nil,
		skipReplace:       opts.Replace == nil,
	}
	if opts.ContextWindowSize > 0 {
		r.contextWindowSize = uint32(opts.ContextWindowSize)
	}
	if len(opts.Entities) > 0 {
		ents := make([]wasmredact.SensitiveInfoEntity, len(opts.Entities))
		for i, name := range opts.Entities {
			ents[i] = entityFromName(name)
		}
		r.entities = &ents
	}
	return r, nil
}

// Close releases the wasm runtime backing the Redactor. The Redactor must not
// be used after Close returns.
func (r *Redactor) Close(ctx context.Context) error {
	r.factory.Close(ctx)
	return nil
}

// Redact returns candidate with every detected sensitive value replaced, along
// with an Unredact function that restores the original values. When nothing is
// detected, candidate is returned unchanged and Unredact is the identity.
func (r *Redactor) Redact(ctx context.Context, candidate string) (redacted string, unredact Unredact, err error) {
	inst, err := r.factory.Instantiate(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("arcjet/redact: instantiate component: %w", err)
	}
	defer inst.Close(ctx)

	// The generated bindings panic on wasm memory errors; convert that into an
	// error so a malformed input can't crash the caller.
	defer func() {
		if r := recover(); r != nil {
			redacted = ""
			unredact = nil
			err = fmt.Errorf("arcjet/redact: %v", r)
		}
	}()

	cfg := wasmredact.RedactSensitiveInfoConfig{
		Entities:          r.entities,
		ContextWindowSize: &r.contextWindowSize,
		SkipCustomDetect:  r.skipDetect,
		SkipCustomRedact:  r.skipReplace,
	}
	redactions := inst.Redact(ctx, candidate, cfg)

	// Apply replacements from the end so earlier byte offsets stay valid. The
	// component reports start/end as byte offsets into candidate, matching Go's
	// string indexing.
	redacted = candidate
	for i := len(redactions) - 1; i >= 0; i-- {
		e := redactions[i]
		redacted = redacted[:e.Start] + e.Redacted + redacted[e.End:]
	}

	unredact = func(input string) string {
		for _, e := range redactions {
			input = strings.ReplaceAll(input, e.Redacted, e.Original)
		}
		return input
	}
	return redacted, unredact, nil
}

func entityFromName(name string) wasmredact.SensitiveInfoEntity {
	switch name {
	case EntityEmail:
		return wasmredact.SensitiveInfoEntityEmail{}
	case EntityPhoneNumber:
		return wasmredact.SensitiveInfoEntityPhoneNumber{}
	case EntityIPAddress:
		return wasmredact.SensitiveInfoEntityIpAddress{}
	case EntityCreditCardNumber:
		return wasmredact.SensitiveInfoEntityCreditCardNumber{}
	default:
		return wasmredact.SensitiveInfoEntityCustom{Value: name}
	}
}

func entityName(e wasmredact.SensitiveInfoEntity) string {
	switch v := e.(type) {
	case wasmredact.SensitiveInfoEntityEmail:
		return EntityEmail
	case wasmredact.SensitiveInfoEntityPhoneNumber:
		return EntityPhoneNumber
	case wasmredact.SensitiveInfoEntityIpAddress:
		return EntityIPAddress
	case wasmredact.SensitiveInfoEntityCreditCardNumber:
		return EntityCreditCardNumber
	case wasmredact.SensitiveInfoEntityCustom:
		return v.Value
	default:
		return ""
	}
}
