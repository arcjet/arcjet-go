package arcjet

import (
	"context"
	"testing"
)

func TestCorrelationIdContextRoundTrip(t *testing.T) {
	if _, ok := CorrelationIdFromContext(context.Background()); ok {
		t.Fatal("empty context must report no ID")
	}
	ctx := ContextWithCorrelationId(context.Background(), "req_123")
	got, ok := CorrelationIdFromContext(ctx)
	if !ok || got != "req_123" {
		t.Fatalf("got %q, %v", got, ok)
	}
	if _, ok := CorrelationIdFromContext(ContextWithCorrelationId(context.Background(), "")); ok {
		t.Fatal("empty string must report no ID")
	}
	var nilCtx context.Context
	if _, ok := CorrelationIdFromContext(nilCtx); ok {
		t.Fatal("nil context must report no ID")
	}
}
