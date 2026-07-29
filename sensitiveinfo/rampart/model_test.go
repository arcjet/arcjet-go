package rampart

import (
	"encoding/json"
	"os"
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
