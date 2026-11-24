// Package rampart is the recommended, on-device sensitive-information
// detection backend for the Arcjet Go SDK. It plugs into the SDK's
// SensitiveInfo and GuardSensitiveInfo rules (via their Backend option) and
// detects names, emails, phone numbers, addresses, SSNs, card numbers, tax and
// government IDs, and more, using a quantized BERT named-entity-recognition
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
	"sort"
	"unicode/utf8"

	arcjet "github.com/arcjet/arcjet-go"
)

// DefaultThreshold is the minimum confidence a model token needs to count.
const DefaultThreshold = 0.5

// DefaultMaxInputChars is the default for [Options.MaxInputChars]: the most
// characters (Unicode code points) the backend scans per call. Model inference
// is synchronous and its cost grows with input length (each ~480-char window
// takes one or more full inference passes, tens of milliseconds each), so
// unbounded input is a denial-of-service vector.
//
// The SDK's SensitiveInfo and GuardSensitiveInfo rules deny input longer than
// the limit without scanning it, because the text past the limit would
// otherwise go unscanned while the decision allowed it. Code that calls Detect
// directly gets the first MaxInputChars characters scanned and the rest
// ignored, with a warning logged.
//
// The default is deliberately low because this pure-Go engine makes a large
// input expensive enough to matter on the request path. 4096 characters is at
// most ten windows. Most text takes one inference pass per window; text that
// expands to several tokens per character, such as spaced Korean, takes up to
// four, so a call makes at most forty passes even when the caller sets no
// timeout. Raise it via [Options.MaxInputChars] if you need to accept larger
// payloads and can afford the latency (and prefer to also bound cost with a
// context deadline).
const DefaultMaxInputChars = 4096

// Options configures the [New] backend.
type Options struct {
	// Threshold is the minimum confidence score (0..1) for a model token to
	// count. Zero uses [DefaultThreshold].
	Threshold float64

	// MaxInputChars is the most characters (Unicode code points) scanned per
	// call. Zero uses [DefaultMaxInputChars]. The backend reports it through
	// the SDK's SensitiveInfoBackendLimiter interface, and the SensitiveInfo
	// and GuardSensitiveInfo rules deny longer input without scanning it.
	// When Detect is called directly, longer input is truncated (a prefix, so
	// offsets stay valid) and a warning is logged. For longer text, or to
	// detect PHI, use the server-side sensitive information detector in an
	// agent guard policy, which Rampart does not replace.
	MaxInputChars int

	// Recognizers are the deterministic recognizers run alongside the model
	// for structured, validatable types (email, URL, IP, phone, SSN).
	// Nil uses [DefaultRecognizers]; an empty (non-nil) slice disables them,
	// and the model and card detection still run. Recognizer results take
	// precedence over the model on overlapping text.
	//
	// Card numbers are always detected with [arcjet.DetectCardNumbers],
	// whatever recognizers are configured, and a recognizer's card labels are
	// ignored. This is the supported extension point for custom detection — the
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

// The backend declares its entity set and its scan limit to the SDK.
var (
	_ arcjet.SensitiveInfoBackendEntitySupporter = (*backend)(nil)
	_ arcjet.SensitiveInfoBackendLimiter         = (*backend)(nil)
)

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

// MaxInputChars reports the most characters this backend scans per call,
// implementing the SDK's optional limit-declaration interface so the SDK's
// rules deny longer input instead of letting its tail go unscanned.
func (b *backend) MaxInputChars() int {
	return b.maxInputChars
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
	// The SDK's rules deny longer input before calling Detect (see
	// MaxInputChars), so this applies only to direct callers.
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
	// A card detection failure leaves the result incomplete. A denial found
	// without it still stands; otherwise the failure is returned below.
	cards, cardErr := arcjet.DetectCardNumbers(ctx, value)
	merged := mergeWithCards(cards, recognizerSpans, modelSpans)

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
	if cardErr != nil {
		if len(result.Denied) == 0 {
			return arcjet.SensitiveInfoResult{}, cardErr
		}
		if bctx.Log != nil {
			bctx.Log.Warn("rampart: card detection failed, so card numbers were " +
				"not scanned; denying on the other findings")
		}
	}
	return result, nil
}

// mergeWithCards combines the card numbers from [arcjet.DetectCardNumbers]
// with the recognizer and model spans. Card numbers come from Arcjet's card
// detection alone, the same definition the bundled analyzer and the server
// use, so the model's and the recognizers' own card labels are ignored. Cards are kept apart from
// the merge, where a longer overlapping span would otherwise replace them, and
// a span that lies within a card names the same digits, so it is dropped.
// Recognizers take precedence over the model on overlapping text.
func mergeWithCards(cards []arcjet.DetectedSensitiveInfoEntity, recognizerSpans, modelSpans []DetectedSpan) []DetectedSpan {
	cardSpans := make([]DetectedSpan, 0, len(cards))
	for _, c := range cards {
		cardSpans = append(cardSpans, DetectedSpan{Start: c.Start, End: c.End, Type: c.Type})
	}
	withinCard := func(span DetectedSpan) bool {
		for _, c := range cardSpans {
			if c.Start <= span.Start && span.End <= c.End {
				return true
			}
		}
		return false
	}
	keep := func(spans []DetectedSpan) []DetectedSpan {
		out := make([]DetectedSpan, 0, len(spans))
		for _, span := range spans {
			if span.Type == arcjet.SensitiveInfoCreditCardNumber || withinCard(span) {
				continue
			}
			out = append(out, span)
		}
		return out
	}

	others := mergeSpans([][]DetectedSpan{keep(recognizerSpans), keep(modelSpans)})
	merged := make([]DetectedSpan, 0, len(cardSpans)+len(others))
	merged = append(merged, cardSpans...)
	merged = append(merged, others...)
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Start != merged[j].Start {
			return merged[i].Start < merged[j].Start
		}
		return merged[i].End < merged[j].End
	})
	return merged
}
