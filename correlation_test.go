package arcjet

import (
	"context"
	"testing"
)

func TestCorrelationIdContextRoundTrip(t *testing.T) {
	if _, ok := CorrelationIDFromContext(context.Background()); ok {
		t.Fatal("empty context must report no ID")
	}
	ctx := ContextWithCorrelationID(context.Background(), "req_123")
	got, ok := CorrelationIDFromContext(ctx)
	if !ok || got != "req_123" {
		t.Fatalf("got %q, %v", got, ok)
	}
	if _, ok := CorrelationIDFromContext(ContextWithCorrelationID(context.Background(), "")); ok {
		t.Fatal("empty string must report no ID")
	}
	var nilCtx context.Context
	if _, ok := CorrelationIDFromContext(nilCtx); ok {
		t.Fatal("nil context must report no ID")
	}
}
