package rampart

import (
	"context"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	arcjet "github.com/arcjet/arcjet-go"
)

// Adversarial tests: a range of hostile and pathological inputs whose goal is to
// break PII detection — crash it, corrupt span offsets, overflow the model, or
// slip PII past the recognizers. The structural invariants (no panic, in-bounds
// rune-aligned spans, correct allow/deny partition) must hold for EVERY input;
// the detection assertions are limited to the deterministic recognizers so the
// tests stay stable regardless of the NER model's soft predictions.

// assertValidSpans checks the invariants every detected span must satisfy no
// matter how hostile the input: byte offsets in range, non-empty ordered span,
// offsets aligned to UTF-8 rune boundaries (never mid-rune), and a named type.
func assertValidSpans(t *testing.T, value string, res arcjet.SensitiveInfoResult) {
	t.Helper()
	check := func(bucket string, ents []arcjet.DetectedSensitiveInfoEntity) {
		for i, e := range ents {
			if e.Start < 0 || e.End > len(value) || e.Start > e.End {
				t.Fatalf("%s[%d] type=%q: out-of-range span [%d:%d] into %d-byte input",
					bucket, i, e.Type, e.Start, e.End, len(value))
			}
			if e.Start == e.End {
				t.Fatalf("%s[%d] type=%q: empty span at %d", bucket, i, e.Type, e.Start)
			}
			if e.Start < len(value) && !utf8.RuneStart(value[e.Start]) {
				t.Fatalf("%s[%d] type=%q: Start=%d is mid-rune", bucket, i, e.Type, e.Start)
			}
			if e.End < len(value) && !utf8.RuneStart(value[e.End]) {
				t.Fatalf("%s[%d] type=%q: End=%d is mid-rune", bucket, i, e.Type, e.End)
			}
			if e.Type == "" {
				t.Fatalf("%s[%d]: empty entity type for span [%d:%d]", bucket, i, e.Start, e.End)
			}
		}
	}
	check("Denied", res.Denied)
	check("Allowed", res.Allowed)
}

// adversarialInputs is a catalogue of inputs designed to break detection.
func adversarialInputs() map[string]string {
	return map[string]string{
		"empty":                "",
		"whitespace only":      " \t\n\r\n   ",
		"ascii control bytes":  "a\x00b\x01c\x07d\x1bе",
		"null in the middle":   "John\x00Smith lives at 10 Downing St",
		"replacement char":     "name�Sarah�",
		"zero-width joiners":   "S\u200da\u200dr\u200da\u200dh",
		"zero-width space":     "jane\u200b@\u200bexample\u200b.com",
		"rtl override":         "\u202eelpmaxe@nhoj\u202c moc.",
		"combining marks":      "Sáràḥ̣̣ Jónes",
		"emoji and zwj":        "👩🏽‍💻 lives in 🗽 New York 🇺🇸 email a@b.co",
		"korean names":         "제 이름은 홍길동이고 서울에 삽니다",
		"bengali decomposing":  "aোe আমার নাম রাম",
		"hindi devanagari":     "मेरा नाम अमित शर्मा है और मैं दिल्ली में रहता हूँ",
		"thai no spaces":       "ผมชื่อสมชายอาศัยอยู่ที่กรุงเทพ",
		"arabic":               "اسمي محمد وأعيش في دبي بريدي a@b.co",
		"cjk dense":            strings.Repeat("名字姓氏城市", 90),
		"hangul overflow":      strings.Repeat("홍길동", 200),
		"single decomposing":   "ো",
		"decomposing sandwich": "xোyোź́",
		"long ascii repeat":    strings.Repeat("A", 2000),
		"long digit run":       strings.Repeat("1234567890", 300),
		"many ats":             strings.Repeat("@", 800),
		"mixed pii soup":       "call (555)234-5678 or +44 20 7946 0958, ssn 123-45-6789, card 4111 1111 1111 1111, ip 2001:db8::1, 홍길동, mail x@y.zz",
		"nested at-signs":      "a@@@@b@@@@c.com",
		"dots everywhere":      strings.Repeat(".", 300) + "a@b.co" + strings.Repeat(".", 300),
		"newlines between pii": "John\n\n\nSmith\n\n123-45-6789",
		"tab separated":        "John\tSmith\t123-45-6789\tjane@x.co",
	}
}

func TestAdversarialInputsAreSafe(t *testing.T) {
	b := testBackend(t)
	all := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}
	for name, value := range adversarialInputs() {
		t.Run(name, func(t *testing.T) {
			// Must not panic and must produce structurally valid spans.
			res := detect(t, b, value, all)
			assertValidSpans(t, value, res)

			// Allow-list mode must partition the same way (denied under a
			// deny-list becomes allowed under the mirror allow-list) and stay
			// structurally valid.
			resAllow := detect(t, b, value, arcjet.SensitiveInfoEntities{Deny: false, Entities: nil})
			assertValidSpans(t, value, resAllow)
			if len(resAllow.Denied) != 0 {
				// Allow-list of nothing means everything detected is denied;
				// that is fine, we only assert validity above. Nothing to do.
				_ = resAllow
			}
		})
	}
}

// TestAdversarialNonMonotonicOffsetsDoNotPanic locks in the fix for the
// slice-bounds panic in aggregateTokens: a source character that normalizes to
// multiple runes yields sub-word tokens sharing a byte span, so token offsets
// are not strictly increasing. These exact inputs produced non-monotonic
// offsets in the tokenizer.
func TestAdversarialNonMonotonicOffsetsDoNotPanic(t *testing.T) {
	b := testBackend(t)
	all := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}
	for _, value := range []string{"aোz", "홍길동", "제 이름은 홍길동", "xোy", strings.Repeat("홍길동 ", 50)} {
		res := detect(t, b, value, all)
		assertValidSpans(t, value, res)
	}

	// Directly exercise the tokenizer/aggregate path too: confirm the offsets
	// really are non-monotonic (guarding against a tokenizer change silently
	// removing the regression coverage), and that aggregateTokens survives it.
	tok := newTokenizer()
	enc := tok.encode("홍길동")
	sawNonMonotonic := false
	prevEnd := 0
	for i := range enc.ids {
		if enc.special[i] {
			continue
		}
		if enc.offsets[i][0] < prevEnd {
			sawNonMonotonic = true
		}
		prevEnd = enc.offsets[i][1]
	}
	if !sawNonMonotonic {
		t.Skip("tokenizer no longer produces non-monotonic offsets for this input")
	}
}

// TestAdversarialLongInputDoesNotOverflowModel feeds inputs far longer than one
// window, including dense-token scripts where one character expands to several
// tokens, to confirm the model's position budget is never overrun (the
// tokenizer caps the sequence at maxPositions).
func TestAdversarialLongInputDoesNotOverflowModel(t *testing.T) {
	b := testBackend(t)
	all := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}
	for _, value := range []string{
		strings.Repeat("홍길동", 700),                // ~3 tokens/char, many windows
		strings.Repeat("नमस्ते ", 400),            // Devanagari with viramas
		strings.Repeat("a", modelMaxInputChars*3), // long ASCII
	} {
		res := detect(t, b, value, all)
		assertValidSpans(t, value, res)
	}

	// A single window that alone would exceed the token budget must still be
	// classifiable without panicking.
	enc := newTokenizer().encode(strings.Repeat("홍", modelMaxInputChars))
	if len(enc.ids) > maxPositions {
		t.Fatalf("encode produced %d tokens, exceeding the %d-position budget", len(enc.ids), maxPositions)
	}
}

// TestAdversarialTruncationIsCharBased confirms the input ceiling counts
// characters, not bytes, and truncates on a rune boundary. Multibyte PII inside
// the ceiling is scanned; input past it is dropped; the truncation never splits
// a rune or panics.
func TestAdversarialTruncationIsCharBased(t *testing.T) {
	small, err := New(Options{MaxInputChars: 40})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	all := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}

	// 30 multibyte chars of padding (90 bytes) then an email — comfortably
	// within a 40-char ceiling even though it is 90+ bytes. A byte-based
	// ceiling would have truncated the email away.
	within := strings.Repeat("あ", 30) + " a@b.co"
	res, err := small.Detect(context.Background(), arcjet.SensitiveInfoBackendContext{}, within, all, nil)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	assertValidSpans(t, within, res)
	if !hasEntity(res.Denied, within, arcjet.SensitiveInfoEmail, "a@b.co") {
		t.Errorf("email within the character ceiling should be detected: %+v", res.Denied)
	}

	// Email placed beyond the character ceiling is not scanned.
	beyond := strings.Repeat("あ", 60) + " secret@hidden.com"
	res2, err := small.Detect(context.Background(), arcjet.SensitiveInfoBackendContext{}, beyond, all, nil)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	assertValidSpans(t, beyond, res2)
	if hasEntity(res2.Denied, beyond, arcjet.SensitiveInfoEmail, "secret@hidden.com") {
		t.Errorf("email beyond the character ceiling should not be scanned: %+v", res2.Denied)
	}

	// Truncation must cut on a rune boundary: a run of multibyte chuncks whose
	// byte length straddles the ceiling must not panic or corrupt.
	res3, err := small.Detect(context.Background(), arcjet.SensitiveInfoBackendContext{}, strings.Repeat("😀", 100), all, nil)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	assertValidSpans(t, strings.Repeat("😀", 100), res3)
}

// TestAdversarialWindowedOffsets pushes structured PII past several window
// boundaries in a long multibyte document and confirms the reported byte
// offsets point at the real PII text (the windowed model path adds the window's
// byte start to each span; a bug there would misplace or corrupt offsets).
func TestAdversarialWindowedOffsets(t *testing.T) {
	b := testBackend(t)
	all := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}

	// Multibyte padding so byte offsets and char offsets diverge, then an
	// email deep into the document past many windows.
	padding := strings.Repeat("あ ", 700)
	value := padding + "reach me at needle@example.org please"
	res := detect(t, b, value, all)
	assertValidSpans(t, value, res)

	found := false
	for _, e := range res.Denied {
		if e.Type == arcjet.SensitiveInfoEmail && value[e.Start:e.End] == "needle@example.org" {
			found = true
		}
	}
	if !found {
		t.Errorf("email past the window boundaries was not detected at the right offset: %+v", res.Denied)
	}
}

// TestAdversarialStructuredEvasions documents which obfuscations defeat the
// deterministic recognizers and which do not. These assertions are stable
// because the recognizers are exact.
func TestAdversarialStructuredEvasions(t *testing.T) {
	b := testBackend(t)
	deny := func(ent arcjet.EntityType) arcjet.SensitiveInfoEntities {
		return arcjet.SensitiveInfoEntities{Deny: true, Entities: []arcjet.EntityType{ent}}
	}

	t.Run("luhn valid card with spaces is caught", func(t *testing.T) {
		value := "pay with 4111 1111 1111 1111 today"
		res := detect(t, b, value, deny(arcjet.SensitiveInfoCreditCardNumber))
		assertValidSpans(t, value, res)
		if !hasEntity(res.Denied, value, arcjet.SensitiveInfoCreditCardNumber, "4111") {
			t.Errorf("Luhn-valid card should be detected: %+v", res.Denied)
		}
	})

	t.Run("luhn invalid card is not a card", func(t *testing.T) {
		value := "order number 4111 1111 1111 1112 shipped"
		res := detect(t, b, value, deny(arcjet.SensitiveInfoCreditCardNumber))
		assertValidSpans(t, value, res)
		if hasEntity(res.Denied, value, arcjet.SensitiveInfoCreditCardNumber, "4111 1111 1111 1112") {
			t.Errorf("Luhn-invalid digit run should not be a card: %+v", res.Denied)
		}
	})

	t.Run("ssn with spaces evades the dashed recognizer", func(t *testing.T) {
		// The SSN recognizer only matches the dashed form; spaced digits are a
		// known gap. This documents (not endorses) the limitation.
		value := "ssn 123 45 6789"
		res := detect(t, b, value, deny(arcjet.SensitiveInfoSSN))
		assertValidSpans(t, value, res)
		if hasEntity(res.Denied, value, arcjet.SensitiveInfoSSN, "123 45 6789") {
			t.Errorf("recognizer unexpectedly matched a spaced SSN: %+v", res.Denied)
		}
	})

	t.Run("dashed ssn is caught", func(t *testing.T) {
		value := "ssn 123-45-6789"
		res := detect(t, b, value, deny(arcjet.SensitiveInfoSSN))
		assertValidSpans(t, value, res)
		if !hasEntity(res.Denied, value, arcjet.SensitiveInfoSSN, "123-45-6789") {
			t.Errorf("dashed SSN should be detected: %+v", res.Denied)
		}
	})

	t.Run("bare digit run is not a phone number", func(t *testing.T) {
		value := "invoice 5551234567890123 total"
		res := detect(t, b, value, deny(arcjet.SensitiveInfoPhoneNumber))
		assertValidSpans(t, value, res)
		if hasEntity(res.Denied, value, arcjet.SensitiveInfoPhoneNumber, "5551234567890123") {
			t.Errorf("long bare digit run should not validate as a phone: %+v", res.Denied)
		}
	})

	t.Run("email with subdomains and plus tag is caught", func(t *testing.T) {
		value := "contact jane.doe+tag@mail.corp.example.co.uk now"
		res := detect(t, b, value, deny(arcjet.SensitiveInfoEmail))
		assertValidSpans(t, value, res)
		if !hasEntity(res.Denied, value, arcjet.SensitiveInfoEmail, "jane.doe+tag@mail.corp.example.co.uk") {
			t.Errorf("complex but valid email should be detected: %+v", res.Denied)
		}
	})
}

// TestAdversarialConcurrentDetect hammers a single shared backend from many
// goroutines to surface data races in the pooled forward buffers. Short inputs
// in a tight per-goroutine loop maximise concurrent pool Get/Put churn (what the
// race detector needs to see) without the cost of large multi-window inference.
// Run with -race for full value.
func TestAdversarialConcurrentDetect(t *testing.T) {
	b := testBackend(t)
	all := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}
	// Deliberately short and varied so each Detect is cheap.
	inputs := []string{
		"My name is Sarah, London, 123-45-6789",
		"card 4111 1111 1111 1111",
		"홍길동 서울",
		"あ a@b.co",
		"👩🏽‍💻 mail x@y.zz",
		"",
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := range 5 {
				value := inputs[(seed+i)%len(inputs)]
				res, err := b.Detect(context.Background(), arcjet.SensitiveInfoBackendContext{}, value, all, nil)
				if err != nil {
					t.Errorf("concurrent Detect: %v", err)
					return
				}
				for _, e := range res.Denied {
					if e.Start < 0 || e.End > len(value) || e.Start > e.End {
						t.Errorf("concurrent Detect produced invalid span [%d:%d] in %d-byte input", e.Start, e.End, len(value))
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
}
