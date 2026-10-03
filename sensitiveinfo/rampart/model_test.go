package rampart

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// goldenRecord is one entry of testdata/golden.json: the input text, the token
// ids the tokenizer produced, and the per-token argmax label id and softmax
// score the reference ONNX Runtime produced for those ids. Regenerate with
// internal/modelgen's golden helper (see testdata/README).
type goldenRecord struct {
	Text   string    `json:"text"`
	IDs    []int     `json:"ids"`
	Labels []int     `json:"labels"`
	Scores []float64 `json:"scores"`
}

func loadGolden(t *testing.T) []goldenRecord {
	t.Helper()
	data, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var recs []goldenRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return recs
}

// TestGoldenTokenizer asserts the tokenizer reproduces the exact token ids the
// golden vectors were built from, guarding against accidental tokenizer drift.
func TestGoldenTokenizer(t *testing.T) {
	tok := newTokenizer()
	for _, rec := range loadGolden(t) {
		enc := tok.encode(rec.Text)
		if len(enc.ids) != len(rec.IDs) {
			t.Fatalf("%q: got %d ids, want %d", rec.Text, len(enc.ids), len(rec.IDs))
		}
		for i := range enc.ids {
			if enc.ids[i] != rec.IDs[i] {
				t.Fatalf("%q: id[%d]=%d, want %d", rec.Text, i, enc.ids[i], rec.IDs[i])
			}
		}
	}
}

// TestGoldenForward asserts the pure-Go BERT forward pass reproduces the
// reference ONNX Runtime per-token argmax labels exactly and the softmax scores
// within a small tolerance. This is the numerical correctness gate: the golden
// values were captured from onnxruntime running the same int4 model.
func TestGoldenForward(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	const scoreTol = 1e-3
	for _, rec := range loadGolden(t) {
		logits := m.forward(rec.IDs)
		if len(rec.Labels) != len(rec.IDs) {
			t.Fatalf("%q: golden has %d labels for %d ids", rec.Text, len(rec.Labels), len(rec.IDs))
		}
		for i := range rec.IDs {
			gotLabel, gotScore := argmaxSoftmax(logits[i*numLabels : (i+1)*numLabels])
			if gotLabel != rec.Labels[i] {
				t.Errorf("%q tok %d: label=%d (%s), want %d (%s)",
					rec.Text, i, gotLabel, id2label[gotLabel], rec.Labels[i], id2label[rec.Labels[i]])
			}
			if diff := gotScore - rec.Scores[i]; diff > scoreTol || diff < -scoreTol {
				t.Errorf("%q tok %d: score=%.5f, want %.5f (diff %.5f)",
					rec.Text, i, gotScore, rec.Scores[i], diff)
			}
		}
	}
}

// TestGoldenRunnerPath runs each golden text through the path the runner uses
// (tokenize, planWindows, classifyWindow) and checks every token against the
// reference ONNX Runtime output. classifyWindow adds [CLS] and [SEP] itself
// and reads the logits for content token i at position i+1, so a mistake in
// either shifts or perturbs every label and score.
func TestGoldenRunnerPath(t *testing.T) {
	r := testRunner(t)
	const scoreTol = 1e-3
	for _, rec := range loadGolden(t) {
		enc := r.tokenizer.tokenize(rec.Text)
		if !slices.Equal(enc.ids, rec.IDs[1:len(rec.IDs)-1]) {
			t.Fatalf("%q: content ids %v, want %v", rec.Text, enc.ids, rec.IDs[1:len(rec.IDs)-1])
		}
		windows := planWindows(enc.words, windowTokenBudget, chunkOverlapTokens)
		if len(windows) != 1 {
			t.Fatalf("%q: planned %d windows, want 1", rec.Text, len(windows))
		}
		tokens, err := r.classifyWindow(enc, windows[0])
		if err != nil {
			t.Fatalf("%q: %v", rec.Text, err)
		}
		k := 0
		for i, offset := range enc.offsets {
			if offset[1] <= offset[0] {
				continue
			}
			if k >= len(tokens) {
				t.Fatalf("%q: %d tokens returned, want more", rec.Text, len(tokens))
			}
			got := tokens[k]
			k++
			want := rec.Labels[i+1]
			if got.entity != id2label[want] || got.start != offset[0] || got.end != offset[1] {
				t.Errorf("%q tok %d: %s at [%d,%d), want %s at [%d,%d)",
					rec.Text, i, got.entity, got.start, got.end, id2label[want], offset[0], offset[1])
			}
			if diff := got.score - rec.Scores[i+1]; diff > scoreTol || diff < -scoreTol {
				t.Errorf("%q tok %d: score=%.5f, want %.5f", rec.Text, i, got.score, rec.Scores[i+1])
			}
		}
		if k != len(tokens) {
			t.Fatalf("%q: %d tokens returned, want %d", rec.Text, len(tokens), k)
		}
	}
}
