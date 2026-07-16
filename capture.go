package arcjet

import (
	"context"
	"time"

	"connectrpc.com/connect"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

// CaptureOptions are the options for [GuardClient.ExperimentalCapture].
//
// Experimental. Dogfooding only — the shape of this API may change.
type CaptureOptions struct {
	// Action is the fact itself: what the application did, in customer
	// vocabulary. Convention: "resource.verb", past tense (e.g.
	// "refund.issued"). Required — events without an action are dropped
	// server-side.
	Action string
	// CorrelationId is an optional, caller-supplied opaque identifier used to
	// correlate this event with other Guard and Capture calls that belong to
	// the same workflow, agent run, or multi-step task. Unlike ambient
	// tracing, it is never inherited automatically — pass it explicitly when
	// you want events linked together.
	CorrelationId string
	// DecisionId is an optional join key referencing the decision (e.g. a
	// GuardDecision.ID) that this event's action relates to.
	DecisionId string
	// OccurredAt is when the action occurred. The zero value means the time
	// of the call; set it explicitly when emission is deferred (e.g. from a
	// queue or background worker). Informational and untrusted like every
	// client-supplied timestamp — the server records its own authoritative
	// receive time.
	OccurredAt time.Time
	// Metadata is arbitrary key-value metadata. Customer-supplied and
	// untrusted, same size caps as GuardRequest.Metadata.
	Metadata map[string]string
}

// captureTimeout bounds the background Capture RPC.
const captureTimeout = time.Second

// ExperimentalCapture records a fact about what the application did — never
// a judgment.
//
// Experimental. Dogfooding only: the API shape may change and there is no
// delivery guarantee. Fire-and-forget: the RPC runs in a background
// goroutine and a failure of any kind (invalid input, transport error,
// server rejection) drops the event silently. Returning means the send has
// been initiated, not that the event was durably recorded: an ack from the
// server means "received," not "stored."
//
// The send is detached from ctx's cancellation (values such as trace context
// are preserved) so returning from the surrounding request handler does not
// drop the event; the RPC is bounded by its own internal timeout instead.
//
// Event identifiers are authored by the server when the event is received;
// the SDK does not mint or expose them.
func (c *GuardClient) ExperimentalCapture(ctx context.Context, opts CaptureOptions) {
	if c == nil {
		return
	}

	sentAt := safeUint64FromInt64(time.Now().UnixMilli())
	occurredAt := sentAt
	if !opts.OccurredAt.IsZero() {
		occurredAt = safeUint64FromInt64(opts.OccurredAt.UnixMilli())
	}

	wireReq := &decidev2.CaptureRequest{
		UserAgent:    c.userAgent,
		SentAtUnixMs: &sentAt,
		Events: []*decidev2.CaptureEvent{{
			OccurredAtUnixMs: occurredAt,
			CorrelationId:    opts.CorrelationId,
			DecisionId:       opts.DecisionId,
			Action:           opts.Action,
			Metadata:         cloneMap(opts.Metadata),
		}},
	}

	connectReq := connect.NewRequest(wireReq)
	connectReq.Header().Set("Authorization", "Bearer "+c.key)
	connectReq.Header().Set("User-Agent", c.userAgent)

	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), captureTimeout)
	go func() {
		defer cancel()
		//nolint:errcheck // Capture is best-effort by contract; a failed send
		// drops the event silently and the SDK has no logger to report drops
		// through while experimental.
		c.guardClient.Capture(sendCtx, connectReq)
	}()
}
