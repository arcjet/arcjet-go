package jsreq

import (
	"context"
	"testing"
)

func TestImportDefaults(t *testing.T) {
	ctx := context.Background()

	email := defaultEmailOverrides{}
	if got := email.IsFreeEmail(ctx, "example.com"); got != Unknown {
		t.Errorf("IsFreeEmail default = %v, want Unknown", got)
	}
	if got := email.IsDisposableEmail(ctx, "example.com"); got != Unknown {
		t.Errorf("IsDisposableEmail default = %v, want Unknown", got)
	}
	if got := email.HasMxRecords(ctx, "example.com"); got != Unknown {
		t.Errorf("HasMxRecords default = %v, want Unknown", got)
	}
	if got := email.HasGravatar(ctx, "user@example.com"); got != Unknown {
		t.Errorf("HasGravatar default = %v, want Unknown", got)
	}
	if got := (defaultBotIdentifier{}).Detect(ctx, "{}"); got != nil {
		t.Errorf("bot identifier default = %v, want nil", got)
	}
	if got := (defaultBotVerifier{}).Verify(ctx, "CURL", "192.0.2.1"); got != Unverifiable {
		t.Errorf("bot verifier default = %v, want Unverifiable", got)
	}
	if got := (defaultFilterOverrides{}).IpLookup(ctx, "192.0.2.1"); got != nil {
		t.Errorf("ip-lookup default = %v, want nil", got)
	}

	// With no custom callback, detect returns one nil slot per token.
	tokens := []string{"a", "b", "c"}
	out := sensitiveInfoIdentifier{}.Detect(ctx, tokens)
	if len(out) != len(tokens) {
		t.Fatalf("sensitive default arity = %d, want %d", len(out), len(tokens))
	}
	for i, v := range out {
		if v != nil {
			t.Errorf("sensitive default slot[%d] = %v, want nil", i, v)
		}
	}
}

func TestSensitiveInfoCustomCallback(t *testing.T) {
	ctx := context.Background()
	var receivedTokens []string
	identifier := sensitiveInfoIdentifier{
		detect: func(_ context.Context, tokens []string) []SensitiveInfoEntity {
			receivedTokens = tokens
			out := make([]SensitiveInfoEntity, len(tokens))
			for i, tok := range tokens {
				if tok == "secret" {
					out[i] = SensitiveInfoEntityCustom{Value: "MY_LABEL"}
				}
			}
			return out
		},
	}

	tokens := []string{"public", "secret", "more"}
	out := identifier.Detect(ctx, tokens)
	if len(receivedTokens) != len(tokens) {
		t.Fatalf("callback got %d tokens, want %d", len(receivedTokens), len(tokens))
	}
	if out[0] != nil || out[2] != nil {
		t.Fatalf("non-matching tokens should stay nil, got %#v", out)
	}
	if out[1] == nil {
		t.Fatal("expected slot 1 to be set")
	}
	custom, ok := (*out[1]).(SensitiveInfoEntityCustom)
	if !ok || custom.Value != "MY_LABEL" {
		t.Fatalf("slot 1 = %#v, want SensitiveInfoEntityCustom{Value: \"MY_LABEL\"}", *out[1])
	}
}

// TestCustomCallbackArityMismatch covers the pad/truncate guard: a callback
// returning the wrong number of slots must not panic and must produce
// exactly len(tokens) results.
func TestCustomCallbackArityMismatch(t *testing.T) {
	ctx := context.Background()
	identifier := sensitiveInfoIdentifier{
		detect: func(_ context.Context, _ []string) []SensitiveInfoEntity {
			return []SensitiveInfoEntity{SensitiveInfoEntityEmail{}} // too few
		},
	}
	out := identifier.Detect(ctx, []string{"a", "b", "c"})
	if len(out) != 3 {
		t.Fatalf("arity = %d, want 3", len(out))
	}
	if out[0] == nil || out[1] != nil || out[2] != nil {
		t.Fatalf("expected only slot 0 set, got %#v", out)
	}
}
