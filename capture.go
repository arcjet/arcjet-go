package arcjet

import (
	"context"
	"time"

	"connectrpc.com/connect"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

// CaptureSourceSDK is the CaptureEvent.Source set on every event produced by
// an explicit [GuardClient.Capture] call.
//
// The producer decides this, not the caller, which is why it is not a field
// on [CaptureEvent]. A future span-conversion path would set "otlp" instead.
// The server never substitutes a default — it stores an absent source as
// unknown — so sending nothing would leave the origin unknown rather than
// merely unstated.
const CaptureSourceSDK = "sdk"

const (
	// captureInputInvalidCode is reported when a capture call's input could
	// not be normalized and the event was dropped (AJ3000).
	captureInputInvalidCode = "AJ3000"
	// captureQueueFullCode is reported when the send queue was full and the
	// newest event was dropped (AJ3001).
	captureQueueFullCode = "AJ3001"
	// captureSendFailedCode is reported when a batch send failed and its
	// events were dropped without retry (AJ3002).
	captureSendFailedCode = "AJ3002"
	// captureFlushExpiredCode is reported when a Flush deadline expired and
	// the remaining events were dropped (AJ3003).
	captureFlushExpiredCode = "AJ3003"
	// captureOptionDroppedCode is the warning code for a capture field that
	// was dropped during normalization. Shared with arcjet-js and arcjet-py
	// (AJ1001) so a support answer about that code holds for every SDK.
	captureOptionDroppedCode = "AJ1001"
)

const (
	captureSendTimeout      = time.Second
	defaultCaptureFlush     = time.Second
	defaultCaptureQueue     = 1000
	defaultCaptureBatch     = 50
	defaultCaptureDelay     = 100 * time.Millisecond
	captureWorkerIdleWait   = 500 * time.Millisecond
	captureMetadataPrefix   = "capture: "
	captureOptionOccurredAt = "OccurredAt"
)

// CaptureEvent is a fact the application reports about what it did.
//
// Captures are visibility data, never security decisions. They do not affect
// [GuardClient.Guard] or [Client.Protect] conclusions, and they never set
// [GuardDecision.HasFailedOpen].
type CaptureEvent struct {
	// Action is what the application did. Convention: "resource.verb", past
	// tense (for example "refund.issued"). Required; an empty action drops
	// the event, since it records nothing.
	Action string
	// CorrelationId is an optional opaque identifier correlating this event
	// with other Guard, Protect, and Capture calls in the same workflow.
	// Never inherited from ambient context.
	CorrelationId string
	// DecisionId is an optional join key referencing the decision this
	// action relates to (for example a [GuardDecision.ID]).
	DecisionId string
	// Metadata is optional nested-JSON metadata. The same shape and limits
	// as [GuardRequest.Metadata] apply. Encoding failures drop individual
	// keys and travel with the event as local_warnings.
	Metadata Metadata
	// OccurredAt is when the action happened. The zero value means the time
	// of the Capture call. Informational and untrusted; the server records
	// its own authoritative receive time.
	//
	// Must be at or after the Unix epoch. The wire field is unsigned, so a
	// pre-1970 time cannot be represented — it is dropped and reported as a
	// warning on the event rather than sent as a negative or wrapped value.
	OccurredAt time.Time
}

// Capture records a fact about what the application did.
//
// Capture is best-effort visibility data. It validates and enqueues
// synchronously, never returns an error, never blocks the caller, and does
// not imply that the event was durably stored. A missing or empty Action
// drops the event. Under sustained load the newest event is dropped when
// the bounded queue is full. Failed batches are never retried.
//
// Call [GuardClient.Flush] during graceful shutdown so the final batch is
// not lost.
func (c *GuardClient) Capture(event CaptureEvent) {
	if c == nil {
		return
	}
	wire := normalizeCaptureEvent(event, c.reportCaptureDiagnostic)
	if wire == nil {
		return
	}
	c.ensureDelivery().capture(wire)
}

// Flush drains buffered capture events.
//
// If ctx is nil or has no deadline, a one-second default is applied. On
// expiry, queued events that already belonged to this flush are dropped.
// Events captured while Flush is waiting stay queued so one caller's
// deadline cannot discard another request's telemetry.
//
// In-flight POSTs are not cancelled. Each send uses its own one-second
// timeout from [context.Background], so a flush deadline can expire while
// a request is still in flight and later succeed. AJ3003 counts only the
// queued events actually discarded.
//
// Flush is optional, repeatable, and does not close the client. A nil
// client or a client that has never captured is a no-op.
func (c *GuardClient) Flush(ctx context.Context) { //nolint:contextcheck // nil ctx has no parent; apply the default deadline
	if c == nil {
		return
	}
	c.deliveryMu.Lock()
	delivery := c.delivery
	c.deliveryMu.Unlock()
	if delivery == nil {
		return
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), defaultCaptureFlush)
		defer cancel()
	} else if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCaptureFlush)
		defer cancel()
	}
	delivery.flush(ctx)
}

func (c *GuardClient) ensureDelivery() *captureDelivery {
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	if c.delivery != nil {
		return c.delivery
	}
	delay := c.captureBatchDelay
	if delay == 0 {
		delay = defaultCaptureDelay
	}
	c.delivery = newCaptureDelivery(captureDeliveryOptions{
		send:       c.sendCapture,
		diagnose:   c.reportCaptureDiagnostic,
		queueSize:  c.captureQueueSize,
		batchSize:  c.captureBatchSize,
		batchDelay: delay,
	})
	return c.delivery
}

func (c *GuardClient) sendCapture(events []*decidev2.CaptureEvent) error {
	if len(events) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), captureSendTimeout)
	defer cancel()
	sentAt := safeUint64FromInt64(time.Now().UnixMilli())
	req := connect.NewRequest(&decidev2.CaptureRequest{
		UserAgent:    c.userAgent,
		SentAtUnixMs: &sentAt,
		Events:       events,
	})
	req.Header().Set("Authorization", "Bearer "+c.key)
	req.Header().Set("User-Agent", c.userAgent)
	_, err := c.guardClient.Capture(ctx, req)
	return err
}

func (c *GuardClient) reportCaptureDiagnostic(code string, count int) {
	if c == nil || c.diagnose == nil {
		return
	}
	c.diagnose(code, count)
}

// normalizeCaptureEvent builds a wire CaptureEvent, or nil if the event must
// be dropped. Only an unusable Action drops the whole event. A bad optional
// field costs that field, not the call.
func normalizeCaptureEvent(event CaptureEvent, diagnose captureDiagnose) *decidev2.CaptureEvent {
	if event.Action == "" {
		diagnose(captureInputInvalidCode, 1)
		return nil
	}

	var warnings []Warning
	occurredAtUnixMs, occurredWarning := captureOccurredAtUnixMs(event.OccurredAt)
	if occurredWarning != nil {
		warnings = append(warnings, *occurredWarning)
	}

	encoded, metadataWarnings := encodeMetadata(event.Metadata, captureMetadataPrefix)
	warnings = append(warnings, metadataWarnings...)
	warnings = append(warnings, enforceMetadataBudget([]map[string]string{encoded})...)

	for _, warning := range warnings {
		diagnose(warning.Code, 1)
	}

	return &decidev2.CaptureEvent{
		OccurredAtUnixMs: occurredAtUnixMs,
		CorrelationId:    event.CorrelationId,
		DecisionId:       event.DecisionId,
		Action:           event.Action,
		MetadataJson:     encoded,
		LocalWarnings:    warningsToProtoV2(warnings),
		Source:           CaptureSourceSDK,
	}
}

func captureOccurredAtUnixMs(occurredAt time.Time) (uint64, *Warning) {
	if occurredAt.IsZero() {
		return safeUint64FromInt64(time.Now().UnixMilli()), nil
	}
	millis := occurredAt.UnixMilli()
	if millis < 0 {
		return safeUint64FromInt64(time.Now().UnixMilli()), &Warning{
			Code:    captureOptionDroppedCode,
			Message: "capture." + captureOptionOccurredAt + " was invalid and was dropped by the SDK",
		}
	}
	return safeUint64FromInt64(millis), nil
}

func nopCaptureDiagnose(string, int) {}

// captureDiagnose reports one local diagnostic. Never used to change a
// decision. Tests inject a recorder; production clients leave it nil.
type captureDiagnose func(code string, count int)
