// Package rampart is an optional, on-device sensitive-information detection
// backend for the Arcjet Go SDK. It plugs into the SDK's SensitiveInfo and
// GuardSensitiveInfo rules (via their Backend option) and detects many more
// entity types than the bundled analyzer — names, addresses, SSNs, tax and
// government IDs, and more — using a quantized BERT named-entity-recognition
// model bundled with this package.
//
// Everything runs in-process with the embedded model weights: no data leaves
// your environment and nothing is fetched at runtime. Detection runs on the
// request hot path, so create one backend at startup with [New] and share it.
//
//	backend, err := rampart.New(rampart.Options{})
//	if err != nil { /* ... */ }
//	client, err := arcjet.NewClient(arcjet.Config{
//		Rules: []arcjet.Rule{
//			arcjet.SensitiveInfo(arcjet.SensitiveInfoOptions{
//				Mode:    arcjet.ModeLive,
//				Deny:    []arcjet.EntityType{arcjet.SensitiveInfoGivenName, arcjet.SensitiveInfoEmail},
//				Backend: backend,
//			}),
//		},
//	})
//
// The bundled model (https://huggingface.co/nationaldesignstudio/rampart) is
// licensed CC BY 4.0; see the NOTICE file for attribution.
package rampart

import (
	"context"
	"fmt"
	"unicode/utf8"

	arcjet "github.com/arcjet/arcjet-go"
)

// DefaultThreshold is the minimum confidence a model token needs to count.
const DefaultThreshold = 0.5

// DefaultMaxInputChars bounds how many characters are scanned per call. Model
// inference is synchronous and its cost grows with input length (each ~480-char
// window is a full inference pass, tens of milliseconds each), so unbounded
// input is a denial-of-service vector. Longer input is truncated to this many
// characters before detection.
//
// This is deliberately lower than the 100,000 used by the JavaScript and Python
// SDKs: their ONNX-runtime inference is much faster, whereas this pure-Go engine
// makes a large input expensive enough to matter on the request path. 4096
// characters keeps the worst case to roughly ten windows (well under a second
// on a typical multi-core server) even when the caller sets no timeout. Raise
// it via [Options.MaxInputChars] if you need to scan larger payloads and can
// afford the latency (and prefer to also bound cost with a context deadline).
const DefaultMaxInputChars = 4096

// Options configures the [New] backend.
type Options struct {
	// Threshold is the minimum confidence score (0..1) for a model token to
	// count. Zero uses [DefaultThreshold].
	Threshold float64

	// MaxInputChars caps the characters scanned per call. Zero uses
	// [DefaultMaxInputChars]. Longer input is truncated (a prefix, so offsets
	// stay valid) and a warning is logged.
	MaxInputChars int

	// Recognizers are the deterministic recognizers run alongside the model
	// for structured, validatable types (email, URL, IP, phone, SSN, cards).
	// Nil uses [DefaultRecognizers]; an empty (non-nil) slice runs the model
	// alone. Recognizer results take precedence over the model on overlapping
	// text. This is the supported extension point for custom detection — the
	// rule's token-based Detect callback is ignored by this backend.
	Recognizers []Recognizer
}

// Entities returns every sensitive-info type this backend can detect (from the
// NER model and the deterministic recognizers combined). Handy for denying (or
// allowing) everything Rampart knows about.
func Entities() []arcjet.EntityType {
	return append([]arcjet.EntityType(nil), rampartEntities...)
}

// truncateChars returns the prefix of s holding at most maxChars runes, cut on
// a rune boundary so the bytes remain valid UTF-8 and offsets stay meaningful.
func truncateChars(s string, maxChars int) string {
	count := 0
	for i := range s {
		if count == maxChars {
			return s[:i]
		}
		count++
	}
	return s
}

// backend is the SensitiveInfoBackend returned by New.
type backend struct {
	runner        *modelRunner
	recognizers   []Recognizer
	maxInputChars int
}

// SupportedEntities reports every entity type this backend can detect,
// implementing the SDK's optional entity-declaration interface so a rule that
// lists a type Rampart cannot produce is rejected at evaluation time rather
// than silently ignored.
func (b *backend) SupportedEntities() []arcjet.EntityType {
	return Entities()
}

// New loads the bundled model and returns a ready-to-share backend. Loading
// dequantizes the weights once and is relatively expensive, so create a single
// backend at startup and reuse it across requests; it is safe for concurrent
// use.
func New(opts Options) (arcjet.SensitiveInfoBackend, error) {
	m, err := loadModel()
	if err != nil {
		return nil, err
	}

	threshold := opts.Threshold
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	maxInputChars := opts.MaxInputChars
	if maxInputChars <= 0 {
		maxInputChars = DefaultMaxInputChars
	}
	recognizers := opts.Recognizers
	if recognizers == nil {
		recognizers = DefaultRecognizers
	}

	return &backend{
		runner: &modelRunner{
			model:     m,
			tokenizer: newTokenizer(),
			threshold: threshold,
		},
		recognizers:   recognizers,
		maxInputChars: maxInputChars,
	}, nil
}

// Detect implements [arcjet.SensitiveInfoBackend].
func (b *backend) Detect(
	ctx context.Context,
	bctx arcjet.SensitiveInfoBackendContext,
	value string,
	entities arcjet.SensitiveInfoEntities,
	opts *arcjet.SensitiveInfoBackendOptions,
) (arcjet.SensitiveInfoResult, error) {
	if opts != nil && opts.Detect != nil && bctx.Log != nil {
		bctx.Log.Debug("rampart: the custom Detect callback is ignored; " +
			"use Options.Recognizers instead")
	}

	// Bound synchronous inference cost: scan only the first maxInputChars
	// characters (Unicode code points, not bytes). Truncating on a rune
	// boundary keeps span offsets valid and never splits a multi-byte rune.
	if runeCount := utf8.RuneCountInString(value); runeCount > b.maxInputChars {
		if bctx.Log != nil {
			bctx.Log.Warn(fmt.Sprintf("rampart: input of %d characters exceeds the "+
				"limit of %d; scanning only the first %d (raise Options.MaxInputChars "+
				"to scan more)", runeCount, b.maxInputChars, b.maxInputChars))
		}
		value = truncateChars(value, b.maxInputChars)
	}

	modelSpans, err := b.runner.run(ctx, value)
	if err != nil {
		// Context cancelled/expired mid-scan: surface the error (the SDK fails
		// open) rather than return a result computed from a partial scan.
		return arcjet.SensitiveInfoResult{}, err
	}
	recognizerSpans := RunRecognizers(value, b.recognizers)

	// Recognizers take precedence over the model on overlapping text.
	merged := mergeSpans([][]DetectedSpan{recognizerSpans, modelSpans})

	listed := make(map[arcjet.EntityType]struct{}, len(entities.Entities))
	for _, e := range entities.Entities {
		listed[e] = struct{}{}
	}

	var result arcjet.SensitiveInfoResult
	for _, span := range merged {
		entity := arcjet.DetectedSensitiveInfoEntity{
			Start: span.Start,
			End:   span.End,
			Type:  span.Type,
		}
		_, isListed := listed[span.Type]
		// deny mode: deny the listed types. allow mode: deny everything else.
		deny := isListed
		if !entities.Deny {
			deny = !isListed
		}
		if deny {
			result.Denied = append(result.Denied, entity)
		} else {
			result.Allowed = append(result.Allowed, entity)
		}
	}
	return result, nil
}
