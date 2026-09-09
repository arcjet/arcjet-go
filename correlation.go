package arcjet

import "context"

type correlationIDContextKey struct{}

// ContextWithCorrelationID returns a context carrying a correlation ID for
// the agent helpers. GuardAction reads it when a policy sets no explicit
// CorrelationID. Guard and Capture never read it: pass the ID to them
// explicitly.
func ContextWithCorrelationID(ctx context.Context, id string) context.Context {
	if id == "" {
		// Storing an empty ID would shadow one an outer layer already set,
		// and every decision below here would silently join no Sequence.
		// A caller passing through a missing header should change nothing.
		return ctx
	}
	return context.WithValue(ctx, correlationIDContextKey{}, id)
}

// CorrelationIDFromContext returns the correlation ID set by
// ContextWithCorrelationID. It reports false for a nil context, a context
// without an ID, or an empty ID.
func CorrelationIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	id, ok := ctx.Value(correlationIDContextKey{}).(string)
	return id, ok && id != ""
}
