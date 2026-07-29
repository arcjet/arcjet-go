package rampart

import (
	"context"
	"math"
	"unicode/utf8"
)

// The model has a 512-token window. Inputs are scanned in overlapping windows
// of at most modelMaxInputChars characters (Unicode code points, not bytes),
// leaving headroom for [CLS]/[SEP]. A single character can expand to several
// tokens (NFD decomposition, CJK isolation), so the tokenizer additionally
// caps each window's token count at the model's position budget (see
// tokenizer.encode). The overlap keeps an entity that straddles a boundary
// intact. Matches arcjet-py's _model.py, which windows by code point.
const (
	modelMaxInputChars = 480
	chunkOverlap       = 64
)

// modelRunner runs the Rampart NER model over text and returns detected spans.
// It is safe for concurrent use: the model and tokenizer are read-only.
type modelRunner struct {
	model     *model
	tokenizer *tokenizer
	threshold float64
}

// run scans value and returns detected entity spans, windowing long input.
// Between windows it honors ctx cancellation so a request deadline bounds total
// inference cost regardless of input length; on cancellation it returns the
// spans found so far and ctx.Err().
func (r *modelRunner) run(ctx context.Context, value string) ([]DetectedSpan, error) {
	if utf8.RuneCountInString(value) <= modelMaxInputChars {
		return aggregateTokens(value, r.classifyChunk(value), r.threshold), nil
	}

	// Byte offset of every rune start, plus len(value) as a sentinel end, so
	// window boundaries always fall between runes and never split one.
	runeStarts := make([]int, 0, len(value))
	for i := range value {
		runeStarts = append(runeStarts, i)
	}
	runeStarts = append(runeStarts, len(value))
	numRunes := len(runeStarts) - 1

	var spans []DetectedSpan
	step := modelMaxInputChars - chunkOverlap
	for startRune := 0; ; startRune += step {
		if err := ctx.Err(); err != nil {
			return mergeWindowedSpans(spans), err
		}
		endRune := min(startRune+modelMaxInputChars, numRunes)
		startByte, endByte := runeStarts[startRune], runeStarts[endRune]
		chunk := value[startByte:endByte]
		for _, span := range aggregateTokens(chunk, r.classifyChunk(chunk), r.threshold) {
			spans = append(spans, DetectedSpan{
				Start: span.Start + startByte,
				End:   span.End + startByte,
				Type:  span.Type,
			})
		}
		// Once a window reaches the end the whole input is covered; advancing
		// would only re-scan an already-covered tail.
		if endRune >= numRunes {
			break
		}
	}
	return mergeWindowedSpans(spans), nil
}

// classifyChunk tokenizes and classifies a single chunk into raw tokens with
// offsets. Special ([CLS]/[SEP]) and zero-width tokens are skipped.
func (r *modelRunner) classifyChunk(chunk string) []rawToken {
	enc := r.tokenizer.encode(chunk)
	if len(enc.ids) == 0 {
		return nil
	}
	logits := r.model.forward(enc.ids)

	var tokens []rawToken
	for i := range enc.ids {
		if enc.special[i] {
			continue
		}
		start, end := enc.offsets[i][0], enc.offsets[i][1]
		if end <= start {
			continue
		}
		label, score := argmaxSoftmax(logits[i*numLabels : (i+1)*numLabels])
		tokens = append(tokens, rawToken{
			entity: id2label[label],
			score:  score,
			start:  start,
			end:    end,
		})
	}
	return tokens
}

// argmaxSoftmax returns the argmax label id and its softmax probability (the
// numerically stabilized max over the row).
func argmaxSoftmax(row []float32) (int, float64) {
	maxIdx := 0
	maxLogit := row[0]
	for i, v := range row {
		if v > maxLogit {
			maxLogit = v
			maxIdx = i
		}
	}
	var sum float64
	for _, v := range row {
		sum += math.Exp(float64(v - maxLogit))
	}
	// The max logit's probability is exp(0)/sum = 1/sum.
	return maxIdx, 1.0 / sum
}
