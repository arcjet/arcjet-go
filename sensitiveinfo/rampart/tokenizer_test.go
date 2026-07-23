package rampart

import (
	"strings"
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// reverseVocab maps token id back to its surface string, for offset checks.
func reverseVocab(t *testing.T) map[int]string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(vocabTxt, "\n"), "\n")
	m := make(map[int]string, len(lines))
	for i, line := range lines {
		m[i] = strings.TrimRight(line, "\r")
	}
	return m
}

// normalizeSurface applies the tokenizer's char normalization (lowercase, NFD
// accent strip) without pre-tokenization, so a token's reconstructed span can
// be compared to its vocabulary surface.
func normalizeSurface(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(strings.ToLower(s)) {
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TestTokenizerOffsets checks that every non-special, non-[UNK] token's
// reconstructed byte span, when normalized, equals its vocabulary surface
// (with the "##" continuation prefix stripped). This validates both the
// WordPiece segmentation and the original-text offset reconstruction.
func TestTokenizerOffsets(t *testing.T) {
	tok := newTokenizer()
	rev := reverseVocab(t)
	inputs := []string{
		"My name is Wolfgang and I live in Berlin",
		"Contact john.doe@example.com now!",
		"Café Málaga, España",
		"Send $100 to 123 Main Street.",
	}
	for _, text := range inputs {
		enc := tok.encode(text)
		prevEnd := -1
		for i := range enc.ids {
			if enc.special[i] {
				continue
			}
			start, end := enc.offsets[i][0], enc.offsets[i][1]
			if start < 0 || end > len(text) || start >= end {
				t.Fatalf("%q tok %d: bad offsets [%d,%d)", text, i, start, end)
			}
			if start < prevEnd {
				t.Fatalf("%q tok %d: offsets go backwards ([%d,%d) after end %d)", text, i, start, end, prevEnd)
			}
			prevEnd = end
			if enc.ids[i] == unkID {
				continue
			}
			surface := strings.TrimPrefix(rev[enc.ids[i]], "##")
			if got := normalizeSurface(text[start:end]); got != surface {
				t.Errorf("%q tok %d id=%d: span %q normalizes to %q, want surface %q",
					text, i, enc.ids[i], text[start:end], got, surface)
			}
		}
	}
}

func TestTokenizerLowercase(t *testing.T) {
	tok := newTokenizer()
	upper := tok.encode("HELLO WORLD")
	lower := tok.encode("hello world")
	if len(upper.ids) != len(lower.ids) {
		t.Fatalf("case changed token count: %d vs %d", len(upper.ids), len(lower.ids))
	}
	for i := range upper.ids {
		if upper.ids[i] != lower.ids[i] {
			t.Fatalf("case-sensitive tokenization at %d: %d vs %d", i, upper.ids[i], lower.ids[i])
		}
	}
}

func TestTokenizerAccentsStripped(t *testing.T) {
	tok := newTokenizer()
	accented := tok.encode("café")
	plain := tok.encode("cafe")
	if len(accented.ids) != len(plain.ids) {
		t.Fatalf("accent changed token count: %d vs %d", len(accented.ids), len(plain.ids))
	}
	for i := range accented.ids {
		if accented.ids[i] != plain.ids[i] {
			t.Fatalf("accent affected token %d: %d vs %d", i, accented.ids[i], plain.ids[i])
		}
	}
	// The accented word's final token must still span the 2-byte é.
	last := len(accented.offsets) - 2 // before [SEP]
	if accented.offsets[last][1] != len("café") {
		t.Fatalf("accented span end=%d, want %d", accented.offsets[last][1], len("café"))
	}
}

func TestTokenizerSpecialTokensWrap(t *testing.T) {
	tok := newTokenizer()
	enc := tok.encode("hello")
	if len(enc.ids) < 2 || enc.ids[0] != clsID || enc.ids[len(enc.ids)-1] != sepID {
		t.Fatalf("expected [CLS]..[SEP] wrapping, got %v", enc.ids)
	}
	if !enc.special[0] || !enc.special[len(enc.special)-1] {
		t.Fatal("CLS/SEP not marked special")
	}
}

func TestTokenizerPunctuationSplit(t *testing.T) {
	tok := newTokenizer()
	enc := tok.encode("a.b")
	// Expect [CLS] a . b [SEP] — the period is isolated as its own token.
	var surfaces []string
	rev := reverseVocab(t)
	for i := range enc.ids {
		if enc.special[i] {
			continue
		}
		surfaces = append(surfaces, rev[enc.ids[i]])
	}
	if strings.Join(surfaces, " ") != "a . b" {
		t.Fatalf("punctuation split = %q, want \"a . b\"", strings.Join(surfaces, " "))
	}
}

func TestTokenizerEmptyAndWhitespace(t *testing.T) {
	tok := newTokenizer()
	for _, in := range []string{"", "   ", "\t\n"} {
		enc := tok.encode(in)
		// Only [CLS] and [SEP].
		if len(enc.ids) != 2 {
			t.Fatalf("%q: expected 2 special tokens, got %v", in, enc.ids)
		}
	}
}
