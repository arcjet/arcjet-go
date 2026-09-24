package rampart

import (
	"context"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	arcjet "github.com/arcjet/arcjet-go"
)

// testRunner returns the shared backend's model runner, so a test can scan text
// without the per-request character ceiling or the recognizers.
func testRunner(t *testing.T) *modelRunner {
	t.Helper()
	return testBackend(t).(*backend).runner
}

// found reports each detected span as its text and type.
func found(value string, spans []DetectedSpan) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, value[s.Start:s.End]+"|"+string(s.Type))
	}
	return out
}

// words returns word ids for consecutive words of the given token lengths.
func words(lengths ...int) []int {
	var ids []int
	for word, n := range lengths {
		for range n {
			ids = append(ids, word)
		}
	}
	return ids
}

func assertValidPlan(t *testing.T, wordIDs []int, budget, overlap int, windows [][2]int) {
	t.Helper()
	if len(wordIDs) == 0 {
		if len(windows) != 0 {
			t.Fatalf("planned %v for no tokens", windows)
		}
		return
	}
	if windows[0][0] != 0 || windows[len(windows)-1][1] != len(wordIDs) {
		t.Fatalf("windows %v do not cover [0,%d)", windows, len(wordIDs))
	}
	for i, w := range windows {
		if w[1] <= w[0] || w[1]-w[0] > budget {
			t.Fatalf("window %d %v is empty or over the %d-token budget", i, w, budget)
		}
		if i == 0 {
			continue
		}
		prev := windows[i-1]
		if w[0] <= prev[0] || w[1] <= prev[1] {
			t.Fatalf("window %d %v does not progress past %v", i, w, prev)
		}
		if prev[1]-w[0] < min(overlap, prev[1]-prev[0]-1) {
			t.Fatalf("window %d %v overlaps %v by less than %d", i, w, prev, overlap)
		}
	}
}

func TestPlanWindowsEmpty(t *testing.T) {
	if got := planWindows(nil, windowTokenBudget, chunkOverlapTokens); len(got) != 0 {
		t.Fatalf("planWindows(nil) = %v", got)
	}
}

func TestPlanWindowsBudgetBoundary(t *testing.T) {
	at := make([]int, windowTokenBudget)
	for i := range at {
		at[i] = i
	}
	if got := planWindows(at, windowTokenBudget, chunkOverlapTokens); len(got) != 1 || got[0] != [2]int{0, windowTokenBudget} {
		t.Fatalf("exactly the budget planned %v, want one window", got)
	}
	over := append(slices.Clone(at), windowTokenBudget)
	got := planWindows(over, windowTokenBudget, chunkOverlapTokens)
	want := [][2]int{{0, windowTokenBudget}, {windowTokenBudget - chunkOverlapTokens, windowTokenBudget + 1}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("one over the budget planned %v, want %v", got, want)
	}
}

func TestPlanWindowsStartOnWords(t *testing.T) {
	ids := words(slices.Repeat([]int{3}, 400)...)
	windows := planWindows(ids, windowTokenBudget, chunkOverlapTokens)
	assertValidPlan(t, ids, windowTokenBudget, chunkOverlapTokens, windows)
	for _, w := range windows[1:] {
		if ids[w[0]] == ids[w[0]-1] {
			t.Fatalf("window %v opens mid-word", w)
		}
	}
}

func TestPlanWindowsProgressThroughOneWord(t *testing.T) {
	// Every token shares one word (and so one offset); planning must still
	// advance rather than snapping back to the same start.
	ids := make([]int, 2000)
	assertValidPlan(t, ids, windowTokenBudget, chunkOverlapTokens,
		planWindows(ids, windowTokenBudget, chunkOverlapTokens))
}

// TestPlanWindowsCapsAnOverlapAtTheBudget passes an overlap that would start
// each window at or before the previous one. Uncapped, planning never ends.
func TestPlanWindowsCapsAnOverlapAtTheBudget(t *testing.T) {
	ids := words(slices.Repeat([]int{3}, 50)...)
	for _, overlap := range []int{9, 10, 50} {
		done := make(chan [][2]int, 1)
		go func() { done <- planWindows(ids, 10, overlap) }()
		select {
		case windows := <-done:
			assertValidPlan(t, ids, 10, 9, windows)
		case <-time.After(5 * time.Second):
			t.Fatalf("planWindows did not finish with overlap %d and budget 10", overlap)
		}
	}
}

func TestPlanWindowsProperties(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for range 500 {
		lengths := make([]int, rng.Intn(60))
		for i := range lengths {
			lengths[i] = 1 + rng.Intn(120)
		}
		budget := 2 + rng.Intn(600)
		overlap := min(rng.Intn(200), budget-1)
		ids := words(lengths...)
		assertValidPlan(t, ids, budget, overlap, planWindows(ids, budget, overlap))
	}
}

// TestRunnerHangulReproduction is the reported input: 341 characters that
// BertNormalizer expands to 511 content tokens (513 with [CLS]/[SEP]), since
// each Hangul syllable decomposes into three Jamo sharing one offset.
func TestRunnerHangulReproduction(t *testing.T) {
	r := testRunner(t)
	value := strings.Repeat("각 ", 170) + "x"
	if n := len(r.tokenizer.tokenize(value).ids); n != 511 {
		t.Fatalf("tokenize produced %d tokens, want 511", n)
	}
	if _, err := r.run(context.Background(), value); err != nil {
		t.Fatalf("run: %v", err)
	}
}

// TestRunnerScansPastTheTokenCap places a phone number beyond the 512th token
// of input shorter than a character window. Capping the tokens of a window
// dropped it without an error.
func TestRunnerScansPastTheTokenCap(t *testing.T) {
	r := testRunner(t)
	phone := "415-555-2671"
	value := strings.Repeat("각 ", 175) + "Call Maria Garcia on " + phone + " tomorrow."
	if n := len(r.tokenizer.tokenize(value).ids); n <= maxPositions {
		t.Fatalf("fixture has %d tokens; it must exceed %d", n, maxPositions)
	}
	spans, err := r.run(context.Background(), value)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := found(value, spans); !slices.Contains(got, phone+"|"+string(arcjet.SensitiveInfoPhoneNumber)) {
		t.Fatalf("phone number past the token cap was not detected: %v", got)
	}
}

func TestRunnerLongMultilingualInputScansToTheEnd(t *testing.T) {
	r := testRunner(t)
	filler := strings.Repeat("회의록 정리했습니다. 会议记录已经整理好了。議事録をまとめました。 Notes are done. ", 200)
	value := filler + "Contact Maria Garcia at 415-555-2671."
	if n := len(r.tokenizer.tokenize(value).ids); n <= 10*maxPositions {
		t.Fatalf("fixture has only %d tokens", n)
	}
	spans, err := r.run(context.Background(), value)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := found(value, spans)
	for _, want := range []string{
		"Maria|" + string(arcjet.SensitiveInfoGivenName),
		"Garcia|" + string(arcjet.SensitiveInfoSurname),
		"415-555-2671|" + string(arcjet.SensitiveInfoPhoneNumber),
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q near the end of the input; tail: %v", want, got[max(0, len(got)-5):])
		}
	}
}

func TestRunnerDetectionCrossingAWindowBoundary(t *testing.T) {
	r := testRunner(t)
	phone := "415-555-2671"
	prefix := "Please call Maria Garcia on "
	// Hangul filler costs three tokens per syllable; pad so the phone number's
	// tokens straddle the end of the first window.
	prefixTokens := len(r.tokenizer.tokenize(prefix).ids)
	filler := strings.Repeat("각 ", (windowTokenBudget-prefixTokens-2)/3)
	value := filler + prefix + phone + " tomorrow."
	before := len(r.tokenizer.tokenize(filler + prefix).ids)
	if before >= windowTokenBudget || windowTokenBudget >= before+len(r.tokenizer.tokenize(phone).ids) {
		t.Fatalf("phone does not straddle the first window: starts at token %d", before)
	}
	spans, err := r.run(context.Background(), value)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := found(value, spans); !slices.Contains(got, phone+"|"+string(arcjet.SensitiveInfoPhoneNumber)) {
		t.Fatalf("phone across the window boundary was not reported whole: %v", got)
	}
}

// TestCharWindowsMatchThePreFixWindows pins the character windows the model is
// given: 480 runes, advancing by 416. The model's phone recall drops in windows
// closer to the full 512 tokens, so a window that fits is scanned whole.
func TestCharWindowsMatchThePreFixWindows(t *testing.T) {
	value := strings.Repeat("Please call the office about the invoice. ", 40)
	var want [][2]int
	for start := 0; ; start += 416 {
		end := min(start+480, len(value))
		want = append(want, [2]int{start, end})
		if end == len(value) {
			break
		}
	}
	got := charWindows(value)
	if !slices.Equal(got, want) {
		t.Fatalf("charWindows = %v, want %v", got, want)
	}

	tok := newTokenizer()
	for _, w := range got {
		words := tok.tokenize(value[w[0]:w[1]]).words
		if n := len(planWindows(words, windowTokenBudget, chunkOverlapTokens)); n != 1 {
			t.Fatalf("English window %v was split into %d token windows", w, n)
		}
	}
}

// TestCharWindowsNeverSplitARune checks multibyte windows land on rune
// boundaries and count runes, not bytes.
func TestCharWindowsNeverSplitARune(t *testing.T) {
	value := strings.Repeat("각", 1000)
	for _, w := range charWindows(value) {
		chunk := value[w[0]:w[1]]
		if !utf8.ValidString(chunk) || utf8.RuneCountInString(chunk) > 480 {
			t.Fatalf("window %v is not at most 480 whole runes", w)
		}
	}
}

// TestOnlyWindowsOverTheBudgetAreSplit mixes English with dense Hangul: the
// English windows are scanned whole, the Hangul ones in token windows that fit.
func TestOnlyWindowsOverTheBudgetAreSplit(t *testing.T) {
	english := strings.Repeat("Please call the office about the invoice. ", 12)
	value := english + strings.Repeat("각 ", 400) + english
	tok := newTokenizer()
	split := 0
	for _, w := range charWindows(value) {
		enc := tok.tokenize(value[w[0]:w[1]])
		windows := planWindows(enc.words, windowTokenBudget, chunkOverlapTokens)
		if len(enc.ids) <= windowTokenBudget && len(windows) != 1 {
			t.Fatalf("window %v fits but was split", w)
		}
		if len(windows) > 1 {
			split++
		}
		for _, tw := range windows {
			if tw[1]-tw[0]+2 > maxPositions {
				t.Fatalf("token window %v exceeds %d positions", tw, maxPositions)
			}
		}
	}
	if split == 0 {
		t.Fatal("no window needed splitting; the fixture is not dense enough")
	}
}
