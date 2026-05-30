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
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				// Each call must either succeed or report ErrClosed — never race
				// the runtime teardown or return some other error.
				if _, _, err := r.Redact(ctx, "reach me at test@example.com"); err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("unexpected Redact error: %v", err)
					return
				}
			}
		}()
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
