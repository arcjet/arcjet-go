package arcjet

import (
	"log/slog"
	"sync"
	"time"
)

// Local diagnostic codes.
//
// Most SDK-side validation problems reach the caller as decision warnings: the
// SDK reports them to Arcjet in local_warnings and they come back attached to
// the decision. Capture has no such channel. It is fire-and-forget, so an event
// dropped before it was sent has no response to carry a warning back on — if it
// is not reported locally, nobody ever finds out.
//
// AJ1000-AJ1999 is the server-side registry and travels on the wire. AJ3000+ is
// SDK-local, reported only here, and allocated append-only across every Arcjet
// SDK: a code means the same thing in all of them, so a new meaning takes a new
// number. Numbers already spent elsewhere — do not reuse them for something
// else in Go: AJ3004 (a second client tried to register), AJ3005 (retired; it
// briefly meant "no client is registered" in JavaScript and was withdrawn
// before release), AJ3006 and AJ3007 (registration diagnostics in arcjet-js and
// arcjet-py respectively). Go has no client registration yet, so it emits none
// of those.
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

// diagnosticMessages is the static text reported for each code.
//
// Messages are static text plus counts. They never contain metadata values,
// capture actions, credentials, headers, or request bodies — only the escaped
// and length-bounded key names that metadata.go already sanitizes. The text
// matches arcjet-js and arcjet-py so one support answer covers every SDK.
var diagnosticMessages = map[string]string{
	captureInputInvalidCode:  "Capture input was invalid; the event was dropped",
	captureQueueFullCode:     "Capture queue is full; newest events were dropped",
	captureSendFailedCode:    "Capture batch send failed; events were dropped without retry",
	captureFlushExpiredCode:  "Capture flush deadline expired; remaining events were dropped",
	captureOptionDroppedCode: "A capture field was invalid and was dropped",
	MetadataEncodeFailedCode: "Metadata keys could not be encoded and were dropped",
}

// defaultDiagnosticMessage is reported for a code with no entry above. Reaching
// it means a code was added without a message; the code itself still identifies
// the condition.
const defaultDiagnosticMessage = "Arcjet SDK diagnostic"

// defaultDiagnosticCoalesce is how long a code stays quiet after being
// reported on the default sink, while counts accumulate.
//
// Capture is called on a request path, so a persistent problem — a full queue
// under sustained load, an unreachable API — would otherwise emit one line per
// event and turn a best-effort telemetry drop into a logging incident.
const defaultDiagnosticCoalesce = time.Minute

// captureDiagnose reports one local diagnostic. Never used to change a
// decision, and never panics: a diagnostics sink is observational and must not
// break application control flow or the background delivery worker.
type captureDiagnose func(code string, count int)

func nopCaptureDiagnose(string, int) {}

// diagnostics reports local diagnostics to a slog sink, coalescing repeats of
// the same code so a burst costs one log line rather than thousands.
//
// Coalescing reports a code at most once per quiet period and accumulates the
// counts in between, releasing them with the next line for that code or from
// [diagnostics.drain], which [GuardClient.Flush] calls. Suppressing without
// accumulating is the trap: reporting only the first event of a thousand-drop
// burst understates it by three orders of magnitude.
//
// A burst that ends with neither a later drop nor a Flush still under-reports.
// That is the residual cost of bounding log volume, and it is why the reported
// figure is a count of events seen rather than a guaranteed total.
type diagnostics struct {
	// sink is where diagnostics go. Nil means [slog.Default], resolved at
	// report time rather than construction time so a client built before
	// slog.SetDefault still reports to the logger the application installed.
	sink *slog.Logger
	// now is the clock for the quiet period. Injectable so tests need not sleep.
	now func() time.Time
	// coalesce is the quiet period per code. Zero reports everything.
	coalesce time.Duration

	// Unlike arcjet-js and arcjet-py, which deliberately skip locking here,
	// Go's race detector runs in CI and these maps are written from both the
	// caller's goroutine (Capture) and the delivery worker. The lock is held
	// only around two map operations and never across the sink write.
	mu         sync.Mutex
	suppressed map[string]int
	lastLogged map[string]time.Time
}

// newDiagnostics builds the diagnostics channel for one client.
//
// A caller-supplied logger receives every diagnostic, because the caller
// already controls filtering — anything keeping a metric of dropped events
// needs all of them. Without one, diagnostics go to [slog.Default] and
// coalesce.
func newDiagnostics(logger *slog.Logger) *diagnostics {
	coalesce := defaultDiagnosticCoalesce
	if logger != nil {
		coalesce = 0
	}
	return &diagnostics{
		sink:       logger,
		now:        time.Now,
		coalesce:   coalesce,
		suppressed: make(map[string]int),
		lastLogged: make(map[string]time.Time),
	}
}

// report records count occurrences of code, emitting a log line unless the
// code is inside its quiet period.
func (d *diagnostics) report(code string, count int) {
	if d == nil || count <= 0 {
		return
	}
	// A logging handler is application code and may panic. Swallowing that is
	// the same choice arcjet-js and arcjet-py make: losing a diagnostic is
	// strictly better than taking down the delivery worker or the caller.
	defer func() { _ = recover() }() //nolint:errcheck // observational sink; nothing to report a failure to

	d.mu.Lock()
	total := d.suppressed[code] + count
	delete(d.suppressed, code)
	at := d.now()
	previous, seen := d.lastLogged[code]
	if d.coalesce > 0 && seen && at.Sub(previous) < d.coalesce {
		d.suppressed[code] = total
		d.mu.Unlock()
		return
	}
	d.lastLogged[code] = at
	d.mu.Unlock()

	d.emit(code, total)
}

// drain reports every count still held back, ignoring the quiet period.
func (d *diagnostics) drain() {
	if d == nil {
		return
	}
	defer func() { _ = recover() }() //nolint:errcheck // observational sink; nothing to report a failure to

	d.mu.Lock()
	held := d.suppressed
	d.suppressed = make(map[string]int)
	at := d.now()
	for code := range held {
		d.lastLogged[code] = at
	}
	d.mu.Unlock()

	for code, count := range held {
		if count > 0 {
			d.emit(code, count)
		}
	}
}

func (d *diagnostics) emit(code string, count int) {
	message, ok := diagnosticMessages[code]
	if !ok {
		message = defaultDiagnosticMessage
	}
	sink := d.sink
	if sink == nil {
		sink = slog.Default()
	}
	sink.Warn(message,
		slog.String("event", "capture_diagnostic"),
		slog.String("code", code),
		slog.Int("count", count),
	)
}
