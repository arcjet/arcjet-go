package arcjet

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"
)

// recordingHandler captures the records written to a slog.Logger so tests can
// assert on what a sink actually received.
type recordingHandler struct {
	mu      sync.Mutex
	records []recordedLog
}

type recordedLog struct {
	level   slog.Level
	message string
	code    string
	count   int
	event   string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	entry := recordedLog{level: record.Level, message: record.Message}
	record.Attrs(func(attr slog.Attr) bool {
		switch attr.Key {
		case "code":
			entry.code = attr.Value.String()
		case "count":
			entry.count = int(attr.Value.Int64())
		case "event":
			entry.event = attr.Value.String()
		}
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, entry)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

func (h *recordingHandler) snapshot() []recordedLog {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]recordedLog(nil), h.records...)
}

func newRecordingLogger() (*slog.Logger, *recordingHandler) {
	handler := &recordingHandler{}
	return slog.New(handler), handler
}

// panickingHandler stands in for a logging handler that is application code and
// may fault. A diagnostics sink is observational, so this must not propagate.
type panickingHandler struct{}

func (panickingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (panickingHandler) Handle(context.Context, slog.Record) error { panic("handler exploded") }

func (h panickingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h panickingHandler) WithGroup(string) slog.Handler { return h }

// TestNewGuardClientWiresDiagnostics is the regression test for the diagnose
// field being declared but never assigned outside tests, which silently
// discarded every capture diagnostic in production.
func TestNewGuardClientWiresDiagnostics(t *testing.T) {
	logger, handler := newRecordingLogger()
	client, err := NewGuardClient(GuardConfig{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: http.NewServeMux()}},
		Logger:     logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.diagnose == nil {
		t.Fatal("diagnose is nil; capture diagnostics would be discarded")
	}

	// An empty Action is unusable, so the event is dropped and reported.
	client.Capture(CaptureEvent{})

	records := handler.snapshot()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1: %+v", len(records), records)
	}
	got := records[0]
	if got.code != captureInputInvalidCode {
		t.Errorf("code = %q, want %q", got.code, captureInputInvalidCode)
	}
	if got.count != 1 {
		t.Errorf("count = %d, want 1", got.count)
	}
	if got.level != slog.LevelWarn {
		t.Errorf("level = %v, want warn", got.level)
	}
	if got.event != "capture_diagnostic" {
		t.Errorf("event = %q, want capture_diagnostic", got.event)
	}
	if got.message != diagnosticMessages[captureInputInvalidCode] {
		t.Errorf("message = %q", got.message)
	}
}

func TestDiagnosticsSuppliedLoggerIsNotCoalesced(t *testing.T) {
	logger, handler := newRecordingLogger()
	d := newDiagnostics(logger)
	if d.coalesce != 0 {
		t.Fatalf("coalesce = %v, want 0 for a supplied logger", d.coalesce)
	}

	// A caller who supplies a logger is filtering and counting themselves, so
	// every diagnostic must arrive.
	for range 3 {
		d.report(captureQueueFullCode, 1)
	}

	records := handler.snapshot()
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3: %+v", len(records), records)
	}
	for i, record := range records {
		if record.code != captureQueueFullCode || record.count != 1 {
			t.Errorf("record %d = %+v", i, record)
		}
	}
}

func TestDiagnosticsDefaultSinkCoalescesAndAccumulates(t *testing.T) {
	logger, handler := newRecordingLogger()
	d := newDiagnostics(nil)
	d.sink = logger // stand in for slog.Default without mutating global state
	now := time.Unix(0, 0)
	d.now = func() time.Time { return now }
	if d.coalesce != defaultDiagnosticCoalesce {
		t.Fatalf("coalesce = %v, want %v", d.coalesce, defaultDiagnosticCoalesce)
	}

	d.report(captureSendFailedCode, 5) // first one is reported immediately
	now = now.Add(time.Second)
	d.report(captureSendFailedCode, 7) // inside the quiet period: held
	d.report(captureSendFailedCode, 9) // still held, accumulating

	records := handler.snapshot()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1: %+v", len(records), records)
	}
	if records[0].count != 5 {
		t.Fatalf("count = %d, want 5", records[0].count)
	}

	// Suppressing without accumulating would report 1 of a 21-event burst. The
	// next line for the code carries everything held back.
	now = now.Add(defaultDiagnosticCoalesce)
	d.report(captureSendFailedCode, 1)

	records = handler.snapshot()
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(records), records)
	}
	if records[1].count != 17 {
		t.Errorf("count = %d, want 17 (7+9+1)", records[1].count)
	}
}

func TestDiagnosticsCoalescingIsPerCode(t *testing.T) {
	logger, handler := newRecordingLogger()
	d := newDiagnostics(nil)
	d.sink = logger
	now := time.Unix(0, 0)
	d.now = func() time.Time { return now }

	// A quiet period on one code must not silence a different condition.
	d.report(captureQueueFullCode, 1)
	d.report(captureSendFailedCode, 1)
	d.report(captureFlushExpiredCode, 1)

	if records := handler.snapshot(); len(records) != 3 {
		t.Fatalf("records = %d, want 3: %+v", len(records), records)
	}
}

func TestDiagnosticsDrainReleasesHeldCounts(t *testing.T) {
	logger, handler := newRecordingLogger()
	d := newDiagnostics(nil)
	d.sink = logger
	now := time.Unix(0, 0)
	d.now = func() time.Time { return now }

	d.report(captureQueueFullCode, 1) // reported
	d.report(captureQueueFullCode, 4) // held
	d.report(captureSendFailedCode, 2)
	d.report(captureSendFailedCode, 3) // held

	d.drain()

	byCode := map[string]int{}
	for _, record := range handler.snapshot() {
		byCode[record.code] += record.count
	}
	if byCode[captureQueueFullCode] != 5 {
		t.Errorf("queue-full total = %d, want 5", byCode[captureQueueFullCode])
	}
	if byCode[captureSendFailedCode] != 5 {
		t.Errorf("send-failed total = %d, want 5", byCode[captureSendFailedCode])
	}

	// Draining twice must not double-report.
	before := len(handler.snapshot())
	d.drain()
	if after := len(handler.snapshot()); after != before {
		t.Errorf("records after second drain = %d, want %d", after, before)
	}
}

func TestDiagnosticsIgnoresNonPositiveCounts(t *testing.T) {
	logger, handler := newRecordingLogger()
	d := newDiagnostics(logger)
	d.report(captureQueueFullCode, 0)
	d.report(captureQueueFullCode, -1)
	if records := handler.snapshot(); len(records) != 0 {
		t.Fatalf("records = %+v, want none", records)
	}
}

func TestDiagnosticsResolvesDefaultSinkAtReportTime(t *testing.T) {
	// Applications commonly call slog.SetDefault after constructing clients, so
	// a nil sink must resolve slog.Default() when it reports, not when it is built.
	d := newDiagnostics(nil)
	if d.sink != nil {
		t.Fatal("sink should stay nil until report time")
	}

	logger, handler := newRecordingLogger()
	previous := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })

	d.report(captureInputInvalidCode, 1)

	if records := handler.snapshot(); len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
}

func TestDiagnosticsUnknownCodeStillReports(t *testing.T) {
	logger, handler := newRecordingLogger()
	d := newDiagnostics(logger)
	d.report("AJ9999", 2)

	records := handler.snapshot()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if records[0].message != defaultDiagnosticMessage {
		t.Errorf("message = %q, want %q", records[0].message, defaultDiagnosticMessage)
	}
	if records[0].code != "AJ9999" {
		t.Errorf("code = %q", records[0].code)
	}
}

func TestDiagnosticMessagesCoverEveryEmittedCode(t *testing.T) {
	// Every code the SDK can emit needs text a support answer can quote.
	for _, code := range []string{
		captureInputInvalidCode,
		captureQueueFullCode,
		captureSendFailedCode,
		captureFlushExpiredCode,
		captureOptionDroppedCode,
		MetadataEncodeFailedCode,
	} {
		if diagnosticMessages[code] == "" {
			t.Errorf("code %s has no message", code)
		}
	}
}

func TestDiagnosticsSinkPanicDoesNotPropagate(t *testing.T) {
	d := newDiagnostics(slog.New(panickingHandler{}))
	d.report(captureQueueFullCode, 1) // must not panic

	coalescing := newDiagnostics(nil)
	coalescing.sink = slog.New(panickingHandler{})
	now := time.Unix(0, 0)
	coalescing.now = func() time.Time { return now }
	coalescing.report(captureQueueFullCode, 1)
	coalescing.report(captureQueueFullCode, 1)
	coalescing.drain() // must not panic either
}

func TestDiagnosticsNilReceiverIsNoOp(t *testing.T) {
	var d *diagnostics
	d.report(captureQueueFullCode, 1)
	d.drain()
}

func TestDiagnosticsConcurrentReportAndDrain(t *testing.T) {
	logger, handler := newRecordingLogger()
	d := newDiagnostics(nil)
	d.sink = logger

	// Capture runs on the caller's goroutine and delivery on the worker, so
	// both write these maps. Exercised under -race in CI.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				d.report(captureQueueFullCode, 1)
				d.report(captureSendFailedCode, 1)
			}
		})
	}
	for range 2 {
		wg.Go(func() {
			for range 50 {
				d.drain()
			}
		})
	}
	wg.Wait()
	d.drain()

	// Totals are not asserted: coalescing plus concurrent drains makes the
	// split between lines nondeterministic. What matters is that nothing raced
	// and nothing reported more events than occurred.
	total := 0
	for _, record := range handler.snapshot() {
		total += record.count
	}
	if total > 800 {
		t.Errorf("reported %d events, more than the 800 that occurred", total)
	}
}

func TestFlushDrainsHeldDiagnosticsWithoutDelivery(t *testing.T) {
	logger, handler := newRecordingLogger()
	client, err := NewGuardClient(GuardConfig{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: http.NewServeMux()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.diagnostics.sink = logger
	now := time.Unix(0, 0)
	client.diagnostics.now = func() time.Time { return now }

	// Invalid events are dropped during normalization, so they never reach
	// delivery — Flush must still release what coalescing held back.
	for range 4 {
		client.Capture(CaptureEvent{})
	}
	if records := handler.snapshot(); len(records) != 1 {
		t.Fatalf("records before flush = %d, want 1 (rest coalesced)", len(records))
	}

	client.Flush(context.Background())

	total := 0
	for _, record := range handler.snapshot() {
		if record.code != captureInputInvalidCode {
			t.Errorf("unexpected code %q", record.code)
		}
		total += record.count
	}
	if total != 4 {
		t.Errorf("reported %d events, want 4", total)
	}
}

func TestCloseDrainsHeldDiagnostics(t *testing.T) {
	logger, handler := newRecordingLogger()
	client, err := NewGuardClient(GuardConfig{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: http.NewServeMux()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.diagnostics.sink = logger
	now := time.Unix(0, 0)
	client.diagnostics.now = func() time.Time { return now }

	client.Capture(CaptureEvent{})
	client.Capture(CaptureEvent{})

	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	total := 0
	for _, record := range handler.snapshot() {
		total += record.count
	}
	if total != 2 {
		t.Errorf("reported %d events, want 2", total)
	}
}
