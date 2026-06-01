package redact

import (
	"context"
	"testing"
)

func TestDetectSensitiveInfoNilCallbackReturnsOneSlotPerToken(t *testing.T) {
	c := customRedact{}
	got := c.DetectSensitiveInfo(context.Background(), []string{"a", "b", "c"})
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i, e := range got {
		if e != nil {
			t.Fatalf("slot %d = %v, want nil", i, e)
		}
	}
}

func TestDetectSensitiveInfoPadsAndTruncatesToTokenCount(t *testing.T) {
	email := SensitiveInfoEntity(SensitiveInfoEntityEmail{})

	// Callback returns fewer entries than tokens: the tail is padded with nil.
	short := customRedact{detect: func(_ context.Context, _ []string) []*SensitiveInfoEntity {
		return []*SensitiveInfoEntity{&email}
	}}
	got := short.DetectSensitiveInfo(context.Background(), []string{"a", "b"})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0] == nil || got[1] != nil {
		t.Fatalf("padding mismatch: %v", got)
	}

	// Callback returns more entries than tokens: the extra is dropped.
	long := customRedact{detect: func(_ context.Context, _ []string) []*SensitiveInfoEntity {
		return []*SensitiveInfoEntity{&email, &email, &email}
	}}
	got = long.DetectSensitiveInfo(context.Background(), []string{"only-one"})
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
}

func TestRedactSensitiveInfoNilCallbackFallsBack(t *testing.T) {
	c := customRedact{}
	if got := c.RedactSensitiveInfo(context.Background(), SensitiveInfoEntityEmail{}, "x"); got != nil {
		t.Fatalf("got %v, want nil (fall back to built-in)", *got)
	}
}

func TestRedactSensitiveInfoDelegatesToCallback(t *testing.T) {
	want := "[REDACTED]"
	c := customRedact{replace: func(_ context.Context, entity SensitiveInfoEntity, _ string) *string {
		if _, ok := entity.(SensitiveInfoEntityEmail); !ok {
			t.Fatalf("unexpected entity type %T", entity)
		}
		return &want
	}}
	got := c.RedactSensitiveInfo(context.Background(), SensitiveInfoEntityEmail{}, "a@b.com")
	if got == nil || *got != want {
		t.Fatalf("got %v, want %q", got, want)
	}
}
