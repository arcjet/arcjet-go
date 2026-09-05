package arcjet

import "context"

type correlationIDContextKey struct{}

// ContextWithCorrelationId returns a context carrying a correlation ID for
// the agent helpers. GuardAction reads it when a policy sets no explicit
// CorrelationId. Guard and Capture never read it: pass the ID to them
// explicitly.
func ContextWithCorrelationId(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDContextKey{}, id)
}

// CorrelationIdFromContext returns the correlation ID set by
// ContextWithCorrelationId. It reports false for a nil context, a context
// without an ID, or an empty ID.
func CorrelationIdFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	id, ok := ctx.Value(correlationIDContextKey{}).(string)
	return id, ok && id != ""
}
