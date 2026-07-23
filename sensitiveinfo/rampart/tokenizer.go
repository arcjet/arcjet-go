package rampart

import (
	_ "embed"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// vocabTxt is the model's WordPiece vocabulary (one token per line, id = line
// index). Redistributed unmodified from the CC BY 4.0 Rampart model; see
// NOTICE.
//
//go:embed vocab.txt
var vocabTxt string

// Special token ids, fixed by the model's vocab.txt / special_tokens_map.json.
const (
	padID = 0
	unkID = 1
	clsID = 2
	sepID = 3
)

const maxInputCharsPerWord = 100

// tokenizer is a BERT WordPiece tokenizer with the uncased BertNormalizer
// (clean text, lowercase, NFD accent stripping, CJK spacing) matching the
// model's tokenizer_config.json. It reconstructs original-text byte offsets
// for every token so detected spans point back into the input.
type tokenizer struct {
	vocab map[string]int
}

// newTokenizer builds the tokenizer from the embedded vocabulary.
func newTokenizer() *tokenizer {
	lines := strings.Split(strings.TrimRight(vocabTxt, "\n"), "\n")
	vocab := make(map[string]int, len(lines))
	for i, line := range lines {
		vocab[strings.TrimRight(line, "\r")] = i
	}
	return &tokenizer{vocab: vocab}
}

// encoding is a tokenized sequence with per-token original-text byte offsets.
type encoding struct {
	ids     []int
	offsets [][2]int // byte [start,end) into the original text; {0,0} for specials
	special []bool
}

// encode tokenizes text into ids wrapped with [CLS] .. [SEP], tracking the
// original byte span of every non-special token.
func (t *tokenizer) encode(text string) encoding {
	words := normalizePretokenize(text)

	enc := encoding{
		ids:     []int{clsID},
		offsets: [][2]int{{0, 0}},
		special: []bool{true},
	}
	for _, w := range words {
		t.wordpiece(w, &enc)
		// Stop once the position budget (less the trailing [SEP]) is full.
		// One character can expand to several tokens (NFD decomposition, CJK
		// isolation), so a fixed character window does not bound the token
		// count; the model has only maxPositions positions.
		if len(enc.ids) >= maxPositions-1 {
			break
		}
	}
	// Truncate to the model's position budget, mirroring the reference
	// tokenizer's truncation=True/max_length=maxPositions. A word can push the
	// count past the budget in one step, so clamp before appending [SEP].
	if len(enc.ids) > maxPositions-1 {
		enc.ids = enc.ids[:maxPositions-1]
		enc.offsets = enc.offsets[:maxPositions-1]
		enc.special = enc.special[:maxPositions-1]
	}
	enc.ids = append(enc.ids, sepID)
	enc.offsets = append(enc.offsets, [2]int{0, 0})
	enc.special = append(enc.special, true)
	return enc
}

// pretoken is a normalized word (whitespace/punctuation split) with the
// original byte offset of each of its runes.
type pretoken struct {
	runes   []rune
	offsets [][2]int // per-rune original byte [start,end)
}

// normChar is a single normalized rune tagged with the original byte span it
// derived from.
type normChar struct {
	r     rune
	start int
	end   int
}

// normalizePretokenize applies the uncased BertNormalizer and BERT
// pre-tokenization (split on whitespace, isolate punctuation and CJK), tracking
// original byte offsets, and returns the resulting words.
func normalizePretokenize(text string) []pretoken {
	var chars []normChar
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		start, end := i, i+size
		i += size

		// clean_text: drop null, replacement, and control chars; map any
		// whitespace to a single space.
		if r == 0 || r == 0xFFFD || isControl(r) {
			continue
		}
		if isWhitespaceRune(r) {
			chars = append(chars, normChar{r: ' ', start: start, end: end})
			continue
		}
		// handle_chinese_chars: surround CJK with spaces so each becomes its
		// own token.
		if isChinese(r) {
			chars = append(chars,
				normChar{r: ' ', start: start, end: start},
				normChar{r: r, start: start, end: end},
				normChar{r: ' ', start: end, end: end})
			continue
		}
		// lowercase then strip accents (NFD, drop nonspacing marks).
		lower := strings.ToLower(string(r))
		for _, c := range norm.NFD.String(lower) {
			if unicode.Is(unicode.Mn, c) {
				continue
			}
			chars = append(chars, normChar{r: c, start: start, end: end})
		}
	}

	// Pre-tokenize: split on spaces; isolate punctuation runes.
	var words []pretoken
	var cur pretoken
	flush := func() {
		if len(cur.runes) > 0 {
			words = append(words, cur)
			cur = pretoken{}
		}
	}
	for _, c := range chars {
		switch {
		case c.r == ' ':
			flush()
		case isPunctuation(c.r):
			flush()
			words = append(words, pretoken{
				runes:   []rune{c.r},
				offsets: [][2]int{{c.start, c.end}},
			})
		default:
			cur.runes = append(cur.runes, c.r)
			cur.offsets = append(cur.offsets, [2]int{c.start, c.end})
		}
	}
	flush()
	return words
}

// wordpiece greedily splits one pre-token into WordPiece subtokens, appending
// each to enc with its reconstructed byte offset. Unknown words (or words that
// fail to segment) become a single [UNK] spanning the whole word.
func (t *tokenizer) wordpiece(w pretoken, enc *encoding) {
	if len(w.runes) == 0 {
		return
	}
	if len(w.runes) > maxInputCharsPerWord {
		enc.append(unkID, w.offsets[0][0], w.offsets[len(w.offsets)-1][1])
		return
	}

	start := 0
	var subtokens []int
	var subOffsets [][2]int
	for start < len(w.runes) {
		end := len(w.runes)
		curID := -1
		var curStart, curEnd int
		for end > start {
			sub := string(w.runes[start:end])
			if start > 0 {
				sub = "##" + sub
			}
			if id, ok := t.vocab[sub]; ok {
				curID = id
				curStart = w.offsets[start][0]
				curEnd = w.offsets[end-1][1]
				break
			}
			end--
		}
		if curID < 0 {
			// Unmatchable: the whole word is [UNK].
			enc.append(unkID, w.offsets[0][0], w.offsets[len(w.offsets)-1][1])
			return
		}
		subtokens = append(subtokens, curID)
		subOffsets = append(subOffsets, [2]int{curStart, curEnd})
		start = end
	}
	for i, id := range subtokens {
		enc.append(id, subOffsets[i][0], subOffsets[i][1])
	}
}

func (e *encoding) append(id, start, end int) {
	e.ids = append(e.ids, id)
	e.offsets = append(e.offsets, [2]int{start, end})
	e.special = append(e.special, false)
}

// isWhitespaceRune mirrors BERT's _is_whitespace: space/tab/newline/carriage
// return, or a Unicode space separator.
func isWhitespaceRune(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r':
		return true
	}
	return unicode.Is(unicode.Zs, r)
}

// isControl mirrors BERT's _is_control: tab/newline/return are treated as
// whitespace (not control); other C-category runes are control.
func isControl(r rune) bool {
	switch r {
	case '\t', '\n', '\r':
		return false
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// isPunctuation mirrors BERT's _is_punctuation: the ASCII punctuation ranges
// plus any Unicode punctuation category.
func isPunctuation(r rune) bool {
	if (r >= 33 && r <= 47) || (r >= 58 && r <= 64) ||
		(r >= 91 && r <= 96) || (r >= 123 && r <= 126) {
		return true
	}
	return unicode.IsPunct(r)
}

// isChinese mirrors BERT's _is_chinese_char CJK ranges.
func isChinese(r rune) bool {
	return (r >= 0x4E00 && r <= 0x9FFF) ||
		(r >= 0x3400 && r <= 0x4DBF) ||
		(r >= 0x20000 && r <= 0x2A6DF) ||
		(r >= 0x2A700 && r <= 0x2B73F) ||
		(r >= 0x2B740 && r <= 0x2B81F) ||
		(r >= 0x2B820 && r <= 0x2CEAF) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0x2F800 && r <= 0x2FA1F)
}
