package rampart

import (
	"sort"
	"strings"

	arcjet "github.com/arcjet/arcjet-go"
)

// DetectedSpan is a detected span of sensitive information. Start and End are
// byte offsets into the scanned value (End exclusive).
type DetectedSpan struct {
	Start int
	End   int
	Type  arcjet.EntityType
}

// rawToken is a single token classified by the model, with reconstructed
// offsets into the original text.
type rawToken struct {
	// entity is the raw label such as "B-GIVEN_NAME".
	entity string
	// score is the confidence in [0,1].
	score float64
	// start/end are byte offsets into the text (end exclusive).
	start int
	end   int
}

// aggregateTokens aggregates per-token model output into entity spans.
//
// Consecutive tokens of the same type merge into one span when the text
// between them is whitespace only, so sub-word tokens and adjacent words of one
// entity collapse together. Tokens below threshold and outside ("O") tokens
// break the current span. Ported from arcjet-py's _model.aggregate_tokens.
func aggregateTokens(value string, tokens []rawToken, threshold float64) []DetectedSpan {
	var spans []DetectedSpan
	var current *DetectedSpan

	flush := func() {
		if current != nil {
			spans = append(spans, *current)
			current = nil
		}
	}

	for _, tok := range tokens {
		entityType, ok := normalizeLabel(tok.entity)
		if !ok || tok.score < threshold {
			flush()
			continue
		}

		isBegin := len(tok.entity) >= 2 &&
			(tok.entity[0] == 'b' || tok.entity[0] == 'B') && tok.entity[1] == '-'

		if current != nil && current.Type == entityType && !isBegin {
			// Merge into the current span when the tokens abut/overlap or the
			// text between them is whitespace only. Token offsets are not
			// strictly monotonic: a source character that normalizes to more
			// than one rune (e.g. a precomposed Hangul syllable or an Indic
			// vowel sign) yields sub-word tokens that share, or step back
			// into, the same byte span. Guard tok.start < current.End before
			// slicing value[current.End:tok.start], which would otherwise
			// panic (low > high) on such input.
			if tok.start < current.End || isWhitespace(value[current.End:tok.start]) {
				if tok.end > current.End {
					current.End = tok.end
				}
				continue
			}
		}

		flush()
		current = &DetectedSpan{Start: tok.start, End: tok.end, Type: entityType}
	}

	flush()
	return spans
}

// isWhitespace reports whether s is empty or contains only whitespace.
func isWhitespace(s string) bool {
	return strings.TrimSpace(s) == ""
}

// mergeWindowedSpans unions overlapping same-type spans produced by overlapping
// windows, reconstructing an entity split across a window boundary and
// collapsing the duplicate spans the overlap region produces. Distinct from
// mergeSpans, which selects one winner among competing spans. Ported from
// arcjet-py's _model._merge_windowed_spans.
func mergeWindowedSpans(spans []DetectedSpan) []DetectedSpan {
	if len(spans) == 0 {
		return spans
	}
	ordered := append([]DetectedSpan(nil), spans...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Start != ordered[j].Start {
			return ordered[i].Start < ordered[j].Start
		}
		return ordered[i].End < ordered[j].End
	})

	var merged []DetectedSpan
	// Track the running span per type, so two same-type fragments still union
	// even when a different-type span starts between them in sort order.
	running := map[arcjet.EntityType]int{} // type -> index into merged
	for _, span := range ordered {
		if idx, ok := running[span.Type]; ok && span.Start < merged[idx].End {
			if span.End > merged[idx].End {
				merged[idx].End = span.End
			}
			continue
		}
		merged = append(merged, span)
		running[span.Type] = len(merged) - 1
	}
	return merged
}

// mergeSpans merges spans from several sources, resolving overlaps. A
// higher-precedence group wins over any lower-precedence group it overlaps,
// regardless of length (so the deterministic recognizers stay authoritative
// over the model on overlapping text). Within a group the longer span wins,
// then ties break by earliest start. Ported from arcjet-py's
// __init__.merge_spans (whose precedence differs deliberately from arcjet-js).
func mergeSpans(groups [][]DetectedSpan) []DetectedSpan {
	type ranked struct {
		span     DetectedSpan
		priority int
	}
	var all []ranked
	for priority, group := range groups {
		for _, span := range group {
			all = append(all, ranked{span: span, priority: priority})
		}
	}
	if len(all) == 0 {
		return nil
	}

	// Higher-precedence group first, then longest, then earliest start.
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].priority != all[j].priority {
			return all[i].priority < all[j].priority
		}
		li := all[i].span.End - all[i].span.Start
		lj := all[j].span.End - all[j].span.Start
		if li != lj {
			return li > lj
		}
		return all[i].span.Start < all[j].span.Start
	})

	// Accept in rank order, skipping any span overlapping one already kept. The
	// accepted set is held sorted by start and pairwise disjoint, so a candidate
	// can only overlap its immediate neighbours — found via binary search.
	var accepted []DetectedSpan
	starts := []int{}
	for _, r := range all {
		span := r.span
		i := sort.SearchInts(starts, span.Start+1) // bisect_right on start
		leftOverlaps := i > 0 && accepted[i-1].End > span.Start
		rightOverlaps := i < len(accepted) && accepted[i].Start < span.End
		if leftOverlaps || rightOverlaps {
			continue
		}
		accepted = append(accepted, DetectedSpan{})
		copy(accepted[i+1:], accepted[i:])
		accepted[i] = span
		starts = append(starts, 0)
		copy(starts[i+1:], starts[i:])
		starts[i] = span.Start
	}
	return accepted
}
