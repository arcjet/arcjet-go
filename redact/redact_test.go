package redact

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestRedactDetectsStandardEntities(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	const input = "Contact me at test@example.com about the issue."
	redacted, unredact, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted, "test@example.com") {
		t.Fatalf("email not redacted: %q", redacted)
	}
	if !strings.Contains(redacted, "Contact me at") || !strings.Contains(redacted, "about the issue.") {
		t.Fatalf("surrounding text was altered: %q", redacted)
	}
	if got := unredact(redacted); got != input {
		t.Fatalf("unredact round-trip = %q, want %q", got, input)
	}
}

func TestRedactRestrictsToEntities(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{Entities: []string{EntityEmail}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	// Only the email should be redacted; the IP address must survive because it
	// isn't in the entity allow-list.
	const input = "from 198.51.100.23 mail user@example.org"
	redacted, _, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted, "user@example.org") {
		t.Fatalf("email not redacted: %q", redacted)
	}
	if !strings.Contains(redacted, "198.51.100.23") {
		t.Fatalf("ip address should not have been redacted: %q", redacted)
	}
}

func TestRedactCustomReplace(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{
		Replace: func(entity, plaintext string) (string, bool) {
			if entity == EntityEmail {
				return "[EMAIL]", true
			}
			return "", false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	redacted, _, err := r.Redact(ctx, "ping a@b.com now")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(redacted, "[EMAIL]") {
		t.Fatalf("custom replacement not applied: %q", redacted)
	}
}

func TestRedactCustomDetect(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{
		Entities: []string{"api-key"},
		Detect: func(tokens []string) []string {
			out := make([]string, len(tokens))
			for i, tok := range tokens {
				if strings.HasPrefix(tok, "sk-") {
					out[i] = "api-key"
				}
			}
			return out
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	const input = "key sk-abc123 here"
	redacted, unredact, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted, "sk-abc123") {
		t.Fatalf("custom entity not redacted: %q", redacted)
	}
	if got := unredact(redacted); got != input {
		t.Fatalf("unredact round-trip = %q, want %q", got, input)
	}
}

func TestRedactEmptyReplacementDoesNotCorruptUnredact(t *testing.T) {
	ctx := context.Background()
	// A custom Replace that drops the entity entirely (empty replacement). The
	// empty marker must not make unredact splice the original between every byte.
	r, err := New(ctx, Options{
		Replace: func(entity, plaintext string) (string, bool) {
			return "", true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	redacted, unredact, err := r.Redact(ctx, "ping a@b.com now")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted, "a@b.com") {
		t.Fatalf("email not redacted: %q", redacted)
	}
	// unredact must be a safe no-op for the empty marker, not corrupt the input.
	const probe = "an unrelated response"
	if got := unredact(probe); got != probe {
		t.Fatalf("unredact corrupted input: got %q, want %q", got, probe)
	}
}

func TestRedactorConcurrentRedactAndClose(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				// Each call must either succeed or report ErrClosed — never race
				// the runtime teardown or return some other error.
				if _, _, err := r.Redact(ctx, "reach me at test@example.com"); err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("unexpected Redact error: %v", err)
					return
				}
			}
		})
	}
	// Close while calls are in flight; the guard must serialize teardown.
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestRedactAfterCloseReturnsErrClosed(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Redact(ctx, "test@example.com"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Redact after Close = %v, want ErrClosed", err)
	}
	// Close is idempotent.
	if err := r.Close(ctx); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

func TestRedactNoMatchesReturnsInput(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	const input = "nothing sensitive here"
	redacted, unredact, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if redacted != input {
		t.Fatalf("expected unchanged input, got %q", redacted)
	}
	if unredact(redacted) != input {
		t.Fatalf("unredact changed input: %q", unredact(redacted))
	}
}

// The component used to report a token's `+`-separated alternates as spans
// overlapping the token they came from, and in the wrong order. Redact rebuilds
// the string in one forward pass, so that panicked on the slice and every
// plus-addressed email failed outright. Reserved test data only (RFC 2606).
func TestRedactPlusAddressedEmail(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{Entities: []string{"email"}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	const input = "mail a+victim@example.com end"
	redacted, unredact, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if strings.Contains(redacted, "victim@example.com") {
		t.Fatalf("email not redacted: %q", redacted)
	}
	if !strings.HasPrefix(redacted, "mail ") || !strings.HasSuffix(redacted, " end") {
		t.Fatalf("surrounding text was altered: %q", redacted)
	}
	if got := unredact(redacted); got != input {
		t.Fatalf("round trip: got %q, want %q", got, input)
	}
}

// Offsets are byte offsets into the original text. Trimmed leading characters
// and percent-escapes both used to shift them, leaving part of the entity —
// with enough of a prefix, all of it — outside its own redaction.
func TestRedactOffsetsSurviveShiftingPrefixes(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	const pan = "4111111111111111"
	for _, input := range []string{
		"Card " + pan + " end",
		"Card ." + pan + " end",
		"Card " + strings.Repeat(".", 16) + pan + " end",
		"Hello%20world Card " + pan + " end",
		"a%2Bb%2Bc Card " + pan + " end",
		"Здравствуйте, карта " + pan + " end",
		"mail .victim@example.com end",
	} {
		redacted, unredact, err := r.Redact(ctx, input)
		if err != nil {
			t.Errorf("input %q: %v", input, err)
			continue
		}
		if strings.Contains(redacted, pan) {
			t.Errorf("input %q: card number survived: %q", input, redacted)
		}
		if strings.Contains(redacted, "victim@example.com") {
			t.Errorf("input %q: email survived: %q", input, redacted)
		}
		if got := unredact(redacted); got != input {
			t.Errorf("input %q: round trip got %q", input, got)
		}
	}
}

// Separator-only tokens were skipped by recursing once each, so a few thousand
// spaces aborted the wasm instead of returning a result.
func TestRedactLongSeparatorRun(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	input := strings.Repeat("  ", 20000) + "4111111111111111"
	redacted, _, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if strings.Contains(redacted, "4111111111111111") {
		t.Fatal("card number survived redaction")
	}
}

// Two detected spans can cross rather than nest: U+FDFA expands to several
// words under NFKC, so a custom detector matching a token either side of it
// yields spans that partly overlap. Resolving that by dropping the later span
// left the part of it past the first span in the output. Unredact still
// restores the original, so this asserts on the redacted text.
func TestRedactCrossingOverlap(t *testing.T) {
	ctx := context.Background()
	r, err := New(ctx, Options{
		Entities: []string{"secret"},
		Detect: func(tokens []string) []string {
			out := make([]string, len(tokens))
			for i, token := range tokens {
				if strings.Contains(token, "AAA") || strings.Contains(token, "SECRET") {
					out[i] = "secret"
				}
			}
			return out
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)

	const input = "AAAﷺSECRET"
	redacted, unredact, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if strings.Contains(redacted, "SECRET") || strings.Contains(redacted, "AAA") {
		t.Fatalf("detected value survived redaction: %q", redacted)
	}
	if got := unredact(redacted); got != input {
		t.Fatalf("round trip: got %q, want %q", got, input)
	}
}
