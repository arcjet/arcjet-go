package rampart

import (
	"context"
	"fmt"
	"math"
	"unicode/utf8"
)

// The model has a 512-token window, including [CLS] and [SEP]. Inputs are
// scanned in overlapping windows of at most modelMaxInputChars characters
// (Unicode code points, not bytes), the context the model detects best in: its
// phone recall drops in windows closer to the full 512 tokens. A character can
// expand to several tokens (NFD decomposes a Hangul syllable into three Jamo
// sharing one offset), so a character window that does not fit is itself
// scanned in overlapping token windows that do; no token is dropped. The
// overlaps keep an entity that straddles a boundary intact. Matches arcjet-py's
// _model.py.
const (
	modelMaxInputChars = 480
	chunkOverlap       = 64
	windowTokenBudget  = maxPositions - 2
	chunkOverlapTokens = 64
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
		spans, windows, err := r.scan(ctx, value, 0, nil)
		if err != nil || windows > 1 {
			return mergeWindowedSpans(spans), err
		}
		return spans, nil
	}

	var spans []DetectedSpan
	for _, window := range charWindows(value) {
		if err := ctx.Err(); err != nil {
			return mergeWindowedSpans(spans), err
		}
		var err error
		spans, _, err = r.scan(ctx, value[window[0]:window[1]], window[0], spans)
		if err != nil {
			return mergeWindowedSpans(spans), err
		}
	}
	return mergeWindowedSpans(spans), nil
}

// charWindows returns the byte bounds of the overlapping character windows
// that cover value: modelMaxInputChars runes each, advancing by
// modelMaxInputChars-chunkOverlap, never splitting a rune.
func charWindows(value string) [][2]int {
	// Byte offset of every rune start, plus len(value) as a sentinel end, so
	// window boundaries always fall between runes and never split one.
	runeStarts := make([]int, 0, len(value)+1)
	for i := range value {
		runeStarts = append(runeStarts, i)
	}
	runeStarts = append(runeStarts, len(value))
	numRunes := len(runeStarts) - 1

	var windows [][2]int
	step := modelMaxInputChars - chunkOverlap
	for startRune := 0; ; startRune += step {
		endRune := min(startRune+modelMaxInputChars, numRunes)
		windows = append(windows, [2]int{runeStarts[startRune], runeStarts[endRune]})
		// Once a window reaches the end the whole input is covered; advancing
		// would only re-scan an already-covered tail.
		if endRune >= numRunes {
			break
		}
	}
	return windows
}

// scan classifies one character window, in token windows when it does not fit
// the model, appending its spans to spans rebased by offset. It returns the
// spans and how many model invocations the chunk took, and honors ctx between
// token windows.
func (r *modelRunner) scan(ctx context.Context, chunk string, offset int, spans []DetectedSpan) ([]DetectedSpan, int, error) {
	enc := r.tokenizer.tokenize(chunk)
	windows := planWindows(enc.words, windowTokenBudget, chunkOverlapTokens)
	for i, window := range windows {
		if i > 0 {
			if err := ctx.Err(); err != nil {
				return spans, i, err
			}
		}
		tokens, err := r.classifyWindow(enc, window)
		if err != nil {
			return spans, i, err
		}
		for _, span := range aggregateTokens(chunk, tokens, r.threshold) {
			spans = append(spans, DetectedSpan{
				Start: span.Start + offset,
				End:   span.End + offset,
				Type:  span.Type,
			})
		}
	}
	return spans, len(windows), nil
}

// planWindows splits a token sequence into overlapping [start, end) windows of
// at most budget tokens that together cover every token. Each window after the
// first starts overlap tokens before the previous one ended, moved back to the
// start of the word there so a window does not open on a sub-word
// continuation. It always starts after the previous window's start, so
// planning progresses even when one word spans more tokens than the overlap.
func planWindows(words []int, budget, overlap int) [][2]int {
	var windows [][2]int
	for start := 0; start < len(words); {
		end := min(start+budget, len(words))
		windows = append(windows, [2]int{start, end})
		if end == len(words) {
			break
		}
		next := end - overlap
		for next-1 > start && words[next] == words[next-1] {
			next--
		}
		start = next
	}
	return windows
}

// classifyWindow classifies tokens [window[0], window[1]) of enc, wrapped in
// [CLS] .. [SEP], into raw tokens. Zero-width tokens are skipped.
func (r *modelRunner) classifyWindow(enc encoding, window [2]int) ([]rawToken, error) {
	start, end := window[0], window[1]
	ids := make([]int, 0, end-start+2)
	ids = append(ids, clsID)
	ids = append(ids, enc.ids[start:end]...)
	ids = append(ids, sepID)
	if len(ids) > maxPositions {
		return nil, fmt.Errorf("rampart: window of %d tokens exceeds the model's %d positions", len(ids), maxPositions)
	}
	logits := r.model.forward(ids)

	var tokens []rawToken
	// Position 0 is [CLS]; the window's tokens follow it, then [SEP].
	for i, offset := range enc.offsets[start:end] {
		if offset[1] <= offset[0] {
			continue
		}
		pos := i + 1
		label, score := argmaxSoftmax(logits[pos*numLabels : (pos+1)*numLabels])
		tokens = append(tokens, rawToken{
			entity: id2label[label],
			score:  score,
			start:  offset[0],
			end:    offset[1],
		})
	}
	return tokens, nil
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
