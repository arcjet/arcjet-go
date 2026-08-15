package arcjet

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

type recordingDiagnose struct {
	mu    sync.Mutex
	codes []string
}

func (r *recordingDiagnose) report(code string, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for range count {
		r.codes = append(r.codes, code)
	}
}

func (r *recordingDiagnose) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.codes...)
}

func TestNormalizeCaptureMinimalEvent(t *testing.T) {
	before := time.Now().UnixMilli()
	event := normalizeCaptureEvent(CaptureEvent{Action: "refund.issued"}, nopCaptureDiagnose)
	after := time.Now().UnixMilli()
	if event == nil {
		t.Fatal("expected event")
	}
	if event.GetAction() != "refund.issued" {
		t.Fatalf("action = %q", event.GetAction())
	}
	if event.GetSource() != CaptureSourceSDK {
		t.Fatalf("source = %q", event.GetSource())
	}
	if event.GetCorrelationId() != "" || event.GetDecisionId() != "" {
		t.Fatalf("optional fields = %#v", event)
	}
	if got := event.GetOccurredAtUnixMs(); got < uint64(before) || got > uint64(after) {
		t.Fatalf("occurred_at_unix_ms = %d, want in [%d, %d]", got, before, after)
	}
	if len(event.GetLocalWarnings()) != 0 {
		t.Fatalf("local_warnings = %#v", event.GetLocalWarnings())
	}
	// New SDKs send metadata_json only.
	//nolint:staticcheck // asserting the deprecated field stays empty is the point
	if len(event.GetMetadata()) != 0 {
		t.Fatalf("legacy metadata = %#v", event.GetMetadata())
	}
}

func TestNormalizeCaptureDropsEmptyAction(t *testing.T) {
	diag := &recordingDiagnose{}
	if event := normalizeCaptureEvent(CaptureEvent{}, diag.report); event != nil {
		t.Fatalf("expected drop, got %#v", event)
	}
	if got := diag.snapshot(); len(got) != 1 || got[0] != captureInputInvalidCode {
		t.Fatalf("diagnostics = %v", got)
	}
}

func TestNormalizeCaptureOptionalFields(t *testing.T) {
	occurred := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	event := normalizeCaptureEvent(CaptureEvent{
		Action:        "refund.issued",
		CorrelationId: "workflow_123",
		DecisionId:    "gdec_abc",
		OccurredAt:    occurred,
		Metadata: Metadata{
			"invoice":  map[string]any{"id": "inv_123"},
			"refunded": true,
		},
	}, nopCaptureDiagnose)
	if event == nil {
		t.Fatal("expected event")
	}
	if event.GetCorrelationId() != "workflow_123" {
		t.Fatalf("correlation_id = %q", event.GetCorrelationId())
	}
	if event.GetDecisionId() != "gdec_abc" {
		t.Fatalf("decision_id = %q", event.GetDecisionId())
	}
	if event.GetOccurredAtUnixMs() != uint64(occurred.UnixMilli()) {
		t.Fatalf("occurred_at_unix_ms = %d", event.GetOccurredAtUnixMs())
	}
	if got := event.GetMetadataJson()["invoice"]; got != `{"id":"inv_123"}` {
		t.Fatalf("metadata_json[invoice] = %q", got)
	}
	if got := event.GetMetadataJson()["refunded"]; got != "true" {
		t.Fatalf("metadata_json[refunded] = %q", got)
	}
}

func TestNormalizeCapturePreEpochOccurredAtDropped(t *testing.T) {
	diag := &recordingDiagnose{}
	event := normalizeCaptureEvent(CaptureEvent{
		Action:     "refund.issued",
		OccurredAt: time.Unix(-1, 0),
	}, diag.report)
	if event == nil {
		t.Fatal("expected event to survive")
	}
	if event.GetOccurredAtUnixMs() == 0 {
		t.Fatal("expected fallback to now, not epoch 0")
	}
	warnings := event.GetLocalWarnings()
	if len(warnings) != 1 || warnings[0].GetCode() != captureOptionDroppedCode {
		t.Fatalf("local_warnings = %#v", warnings)
	}
	if !strings.Contains(warnings[0].GetMessage(), "OccurredAt") {
		t.Fatalf("message = %q", warnings[0].GetMessage())
	}
	if got := diag.snapshot(); len(got) != 1 || got[0] != captureOptionDroppedCode {
		t.Fatalf("diagnostics = %v", got)
	}
}

func TestNormalizeCaptureEpochOccurredAtAllowed(t *testing.T) {
	event := normalizeCaptureEvent(CaptureEvent{
		Action:     "refund.issued",
		OccurredAt: time.Unix(0, 0),
	}, nopCaptureDiagnose)
	if event == nil {
		t.Fatal("expected event")
	}
	if event.GetOccurredAtUnixMs() != 0 {
		t.Fatalf("occurred_at_unix_ms = %d", event.GetOccurredAtUnixMs())
	}
	if len(event.GetLocalWarnings()) != 0 {
		t.Fatalf("local_warnings = %#v", event.GetLocalWarnings())
	}
}

func TestNormalizeCaptureMetadataBudgetWarning(t *testing.T) {
	diag := &recordingDiagnose{}
	// A JSON string is quoted, so MaxMetadataBytes of payload exceeds the budget.
	event := normalizeCaptureEvent(CaptureEvent{
		Action:   "refund.issued",
		Metadata: Metadata{"big": strings.Repeat("x", MaxMetadataBytes)},
	}, diag.report)
	if event == nil {
		t.Fatal("expected event to survive")
	}
	if len(event.GetMetadataJson()) != 0 {
		t.Fatalf("metadata_json = %#v", event.GetMetadataJson())
	}
	warnings := event.GetLocalWarnings()
	if len(warnings) != 1 || warnings[0].GetCode() != MetadataEncodeFailedCode {
		t.Fatalf("local_warnings = %#v", warnings)
	}
	if !strings.Contains(warnings[0].GetMessage(), "budget") {
		t.Fatalf("message = %q", warnings[0].GetMessage())
	}
	if got := diag.snapshot(); len(got) != 1 || got[0] != MetadataEncodeFailedCode {
		t.Fatalf("diagnostics = %v", got)
	}
}

func TestNormalizeCaptureUnencodableMetadataKey(t *testing.T) {
	event := normalizeCaptureEvent(CaptureEvent{
		Action:   "refund.issued",
		Metadata: Metadata{"good": 1, "bad": make(chan int)},
	}, nopCaptureDiagnose)
	if event == nil {
		t.Fatal("expected event")
	}
	if got := event.GetMetadataJson(); len(got) != 1 || got["good"] != "1" {
		t.Fatalf("metadata_json = %#v", event.GetMetadataJson())
	}
	if len(event.GetLocalWarnings()) != 1 || event.GetLocalWarnings()[0].GetCode() != MetadataEncodeFailedCode {
		t.Fatalf("local_warnings = %#v", event.GetLocalWarnings())
	}
}

func TestCaptureDeliveryQueuesAndFlushes(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:    10,
		batchSize:    50,
		noBatchDelay: true,
		send: func(events []*decidev2.CaptureEvent) error {
			mu.Lock()
			defer mu.Unlock()
			for _, event := range events {
				sent = append(sent, event.GetAction())
			}
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "refund.issued"}, nopCaptureDiagnose))
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "email.sent"}, nopCaptureDiagnose))
	d.flush(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 2 || sent[0] != "refund.issued" || sent[1] != "email.sent" {
		t.Fatalf("sent = %v", sent)
	}
}

func TestCaptureDeliveryDropsNewestWhenFull(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var sent []string
	diag := &recordingDiagnose{}
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:    2,
		batchSize:    1,
		noBatchDelay: true,
		diagnose:     diag.report,
		send: func(events []*decidev2.CaptureEvent) error {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			mu.Lock()
			defer mu.Unlock()
			for _, event := range events {
				sent = append(sent, event.GetAction())
			}
			return nil
		},
	})

	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "one"}, nopCaptureDiagnose))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first send did not start")
	}
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "two"}, nopCaptureDiagnose))
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "three"}, nopCaptureDiagnose))
	if got := diag.snapshot(); len(got) != 1 || got[0] != captureQueueFullCode {
		t.Fatalf("diagnostics = %v", got)
	}
	close(release)
	d.flush(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 2 || sent[0] != "one" || sent[1] != "two" {
		t.Fatalf("sent = %v, want [one two] (newest dropped)", sent)
	}
}

func TestCaptureDeliveryFlushExpiryDropsQueued(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	diag := &recordingDiagnose{}
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:  10,
		batchSize:  1,
		batchDelay: time.Hour,
		diagnose:   diag.report,
		send: func([]*decidev2.CaptureEvent) error {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "in-flight"}, nopCaptureDiagnose))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("send did not start")
	}
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "queued"}, nopCaptureDiagnose))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	d.flush(ctx)

	if got := diag.snapshot(); len(got) == 0 || got[0] != captureFlushExpiredCode {
		t.Fatalf("diagnostics = %v, want AJ3003", got)
	}
}

func TestCaptureDeliveryFlushExpiryKeepsLaterEvents(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var sent []string
	diag := &recordingDiagnose{}
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:  10,
		batchSize:  1,
		batchDelay: time.Hour,
		diagnose:   diag.report,
		send: func(events []*decidev2.CaptureEvent) error {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			mu.Lock()
			defer mu.Unlock()
			for _, event := range events {
				sent = append(sent, event.GetAction())
			}
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "in-flight"}, nopCaptureDiagnose))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("send did not start")
	}
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "before"}, nopCaptureDiagnose))

	ctx, cancel := context.WithCancel(context.Background())
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		d.flush(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		d.mu.Lock()
		ready := d.flushNow
		d.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("flush did not start waiting")
		}
		time.Sleep(time.Millisecond)
	}

	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "after"}, nopCaptureDiagnose))
	cancel()
	select {
	case <-flushDone:
	case <-time.After(2 * time.Second):
		t.Fatal("flush did not return")
	}

	if got := diag.snapshot(); len(got) != 1 || got[0] != captureFlushExpiredCode {
		t.Fatalf("diagnostics = %v, want one AJ3003 for the pre-flush queued event", got)
	}

	close(release)
	d.flush(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 2 || sent[0] != "in-flight" || sent[1] != "after" {
		t.Fatalf("sent = %v, want [in-flight after] (before dropped, after kept)", sent)
	}
}

func TestCaptureDeliverySendFailureIsNotRetried(t *testing.T) {
	diag := &recordingDiagnose{}
	var calls int
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:    10,
		batchSize:    50,
		noBatchDelay: true,
		diagnose:     diag.report,
		send: func([]*decidev2.CaptureEvent) error {
			calls++
			return errors.New("upstream down")
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "refund.issued"}, nopCaptureDiagnose))
	d.flush(context.Background())
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1 (no retry)", calls)
	}
	if got := diag.snapshot(); len(got) != 1 || got[0] != captureSendFailedCode {
		t.Fatalf("diagnostics = %v", got)
	}
}

func TestCaptureInvalidActionNeverPosted(t *testing.T) {
	handler := &testGuardHandler{}
	client, _ := newGuardTestClient(t, handler)
	client.Capture(CaptureEvent{})
	client.Flush(context.Background())
	if events := handler.capturedEvents(); len(events) != 0 {
		t.Fatalf("posted %d events, want 0", len(events))
	}
}

func TestGuardClientCaptureFlushDrains(t *testing.T) {
	handler := &testGuardHandler{}
	client, _ := newGuardTestClient(t, handler)
	client.captureBatchDelay = time.Hour // would otherwise sit until Flush
	client.Capture(CaptureEvent{
		Action:        "refund.issued",
		CorrelationId: "wf_1",
		DecisionId:    "gdec_1",
		Metadata:      Metadata{"invoice": "inv_123"},
	})
	if events := handler.capturedEvents(); len(events) != 0 {
		t.Fatal("expected capture to enqueue, not send immediately")
	}
	client.Flush(context.Background())
	events := handler.capturedEvents()
	if len(events) != 1 {
		t.Fatalf("captured events = %d", len(events))
	}
	if events[0].GetAction() != "refund.issued" {
		t.Fatalf("action = %q", events[0].GetAction())
	}
	if events[0].GetSource() != CaptureSourceSDK {
		t.Fatalf("source = %q", events[0].GetSource())
	}
	if events[0].GetCorrelationId() != "wf_1" || events[0].GetDecisionId() != "gdec_1" {
		t.Fatalf("ids = %#v", events[0])
	}
	if got := events[0].GetMetadataJson()["invoice"]; got != `"inv_123"` {
		t.Fatalf("metadata_json[invoice] = %q", got)
	}
	if handler.captureHeader.Get("Authorization") != "Bearer ajkey_test" {
		t.Fatalf("authorization = %q", handler.captureHeader.Get("Authorization"))
	}
	if ua := handler.captureSeen[0].GetUserAgent(); !strings.Contains(ua, "arcjet-guard-go") {
		t.Fatalf("user_agent = %q", ua)
	}
	if handler.captureSeen[0].GetSentAtUnixMs() == 0 {
		t.Fatal("expected sent_at_unix_ms")
	}
}

func TestCapturePostsToCanonicalRoute(t *testing.T) {
	handler := &testGuardHandler{}
	path, h := decidev2connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	var mu sync.Mutex
	var seen []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		seen = append(seen, req.URL.Path)
		mu.Unlock()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Result(), nil
	})
	client, err := NewGuardClient(GuardConfig{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.captureBatchDelay = time.Hour
	client.Capture(CaptureEvent{Action: "refund.issued"})
	client.Flush(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != decidev2connect.DecideServiceCaptureProcedure {
		t.Fatalf("paths = %v, want [%q]", seen, decidev2connect.DecideServiceCaptureProcedure)
	}
	if decidev2connect.DecideServiceCaptureProcedure != "/proto.decide.v2.DecideService/Capture" {
		t.Fatalf("procedure = %q", decidev2connect.DecideServiceCaptureProcedure)
	}
}

func TestCaptureDoesNotAffectGuardDecision(t *testing.T) {
	handler := &testGuardHandler{captureErr: connect.NewError(connect.CodeUnavailable, errors.New("capture down"))}
	client, _ := newGuardTestClient(t, handler)
	client.captureBatchDelay = time.Hour
	client.Capture(CaptureEvent{Action: "refund.issued"})
	client.Flush(context.Background())

	tb, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := client.Guard(context.Background(), GuardRequest{
		Label: "tools.test",
		Rules: []GuardRuleInput{tb.Key("user_1", 1)},
	})
	if err != nil {
		t.Fatalf("Guard after failed Capture: %v", err)
	}
	if !d.IsAllowed() {
		t.Fatalf("conclusion = %s", d.Conclusion)
	}
	if d.HasFailedOpen() {
		t.Fatal("Capture failure must not mark the Guard decision failed-open")
	}
}

func TestCaptureNilClientIsNoop(t *testing.T) {
	var client *GuardClient
	client.Capture(CaptureEvent{Action: "refund.issued"})
	client.Flush(context.Background())
}

func TestFlushAndCloseNilContext(t *testing.T) {
	handler := &testGuardHandler{}
	client, _ := newGuardTestClient(t, handler)
	client.captureBatchDelay = time.Hour
	client.Capture(CaptureEvent{Action: "refund.issued"})
	client.Flush(nil) //nolint:staticcheck // nil ctx is the contract under test
	if events := handler.capturedEvents(); len(events) != 1 {
		t.Fatalf("Flush(nil) events = %d", len(events))
	}
	if err := client.Close(nil); err != nil { //nolint:staticcheck // nil ctx is the contract under test
		t.Fatal(err)
	}
}

func TestEnsureDeliveryReusesAndAppliesDefaultDelay(t *testing.T) {
	handler := &testGuardHandler{}
	client, _ := newGuardTestClient(t, handler)
	client.Capture(CaptureEvent{Action: "refund.issued"})
	first := client.delivery
	if first == nil {
		t.Fatal("expected delivery after first Capture")
	}
	if first.batchDelay != defaultCaptureDelay {
		t.Fatalf("batchDelay = %s, want default %s", first.batchDelay, defaultCaptureDelay)
	}
	client.Capture(CaptureEvent{Action: "email.sent"})
	if client.delivery != first {
		t.Fatal("second Capture must reuse the same delivery")
	}
	client.Flush(context.Background())
	if events := handler.capturedEvents(); len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
}

func TestSendCaptureEmptyIsNoop(t *testing.T) {
	client, _ := newGuardTestClient(t, &testGuardHandler{})
	if err := client.sendCapture(nil); err != nil {
		t.Fatal(err)
	}
	if err := client.sendCapture([]*decidev2.CaptureEvent{}); err != nil {
		t.Fatal(err)
	}
}

func TestReportCaptureDiagnostic(t *testing.T) {
	var client *GuardClient
	client.reportCaptureDiagnostic(captureInputInvalidCode, 1)

	live, _ := newGuardTestClient(t, &testGuardHandler{})
	diag := &recordingDiagnose{}
	live.diagnose = diag.report
	live.Capture(CaptureEvent{})
	if got := diag.snapshot(); len(got) != 1 || got[0] != captureInputInvalidCode {
		t.Fatalf("diagnostics = %v", got)
	}
}

func TestNewCaptureDeliveryDefaults(t *testing.T) {
	d := newCaptureDelivery(captureDeliveryOptions{})
	if d.batchDelay != defaultCaptureDelay {
		t.Fatalf("batchDelay = %s", d.batchDelay)
	}
	if d.queueSize != defaultCaptureQueue || d.batchSize != defaultCaptureBatch {
		t.Fatalf("queue/batch = %d/%d", d.queueSize, d.batchSize)
	}
	nopCaptureDiagnose(captureQueueFullCode, 1)
	d.capture(nil)
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "refund.issued"}, nopCaptureDiagnose))
	d.flush(context.Background())
}

func TestFlushEmptyDeliveryIsNoop(t *testing.T) {
	d := newCaptureDelivery(captureDeliveryOptions{noBatchDelay: true})
	d.flush(context.Background())
}

type pastDeadlineCtx struct{ context.Context }

func (pastDeadlineCtx) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

func TestFlushAlreadyExpiredDeadline(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	diag := &recordingDiagnose{}
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:  10,
		batchSize:  1,
		batchDelay: time.Hour,
		diagnose:   diag.report,
		send: func([]*decidev2.CaptureEvent) error {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "in-flight"}, nopCaptureDiagnose))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("send did not start")
	}
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "queued"}, nopCaptureDiagnose))
	d.flush(pastDeadlineCtx{context.Background()})
	if got := diag.snapshot(); len(got) != 1 || got[0] != captureFlushExpiredCode {
		t.Fatalf("diagnostics = %v, want AJ3003", got)
	}
}

func TestAbandonLockedClampsOutstanding(t *testing.T) {
	d := newCaptureDelivery(captureDeliveryOptions{noBatchDelay: true})
	d.mu.Lock()
	d.queue = []queuedCapture{{
		event: normalizeCaptureEvent(CaptureEvent{Action: "stale"}, nopCaptureDiagnose),
		seq:   1,
	}}
	d.outstanding = 0
	d.abandonLocked(1)
	if d.outstanding != 0 {
		t.Fatalf("outstanding = %d", d.outstanding)
	}
	if len(d.queue) != 0 {
		t.Fatalf("queue = %d", len(d.queue))
	}
	d.mu.Unlock()
}

func TestCaptureDeliveryNopDiagnoseOnQueueFull(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:    1,
		batchSize:    1,
		noBatchDelay: true,
		send: func([]*decidev2.CaptureEvent) error {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "one"}, nopCaptureDiagnose))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("send did not start")
	}
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "two"}, nopCaptureDiagnose))
	close(release)
	d.flush(context.Background())
}

func TestCollectBatchDelayGathersCompany(t *testing.T) {
	sent := make(chan []string, 1)
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:  10,
		batchSize:  3,
		batchDelay: 200 * time.Millisecond,
		send: func(events []*decidev2.CaptureEvent) error {
			actions := make([]string, len(events))
			for i, event := range events {
				actions[i] = event.GetAction()
			}
			sent <- actions
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "one"}, nopCaptureDiagnose))
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.mu.Lock()
		waiting := d.worker && len(d.queue) == 0 && !d.flushNow
		d.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not enter the batch window")
		}
		time.Sleep(time.Millisecond)
	}
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "two"}, nopCaptureDiagnose))
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "three"}, nopCaptureDiagnose))
	select {
	case got := <-sent:
		if len(got) != 3 || got[0] != "one" || got[1] != "two" || got[2] != "three" {
			t.Fatalf("batch = %v, want [one two three]", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch was not gathered")
	}
}

func TestCollectBatchDelayExpiresWithOne(t *testing.T) {
	sent := make(chan string, 1)
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:  10,
		batchSize:  10,
		batchDelay: time.Nanosecond,
		send: func(events []*decidev2.CaptureEvent) error {
			sent <- events[0].GetAction()
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "solo"}, nopCaptureDiagnose))
	select {
	case got := <-sent:
		if got != "solo" {
			t.Fatalf("action = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch delay did not fire")
	}
}

func TestCollectBatchDelayWaitsThenExpires(t *testing.T) {
	sent := make(chan string, 1)
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:  10,
		batchSize:  10,
		batchDelay: 15 * time.Millisecond,
		send: func(events []*decidev2.CaptureEvent) error {
			sent <- events[0].GetAction()
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "solo"}, nopCaptureDiagnose))
	select {
	case got := <-sent:
		if got != "solo" {
			t.Fatalf("action = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch delay did not fire")
	}
}

func TestCollectBatchDelayFlushCutsWait(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	d := newCaptureDelivery(captureDeliveryOptions{
		queueSize:  10,
		batchSize:  10,
		batchDelay: time.Hour,
		send: func(events []*decidev2.CaptureEvent) error {
			mu.Lock()
			defer mu.Unlock()
			for _, event := range events {
				sent = append(sent, event.GetAction())
			}
			return nil
		},
	})
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "first"}, nopCaptureDiagnose))
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.mu.Lock()
		waiting := d.worker && len(d.queue) == 0 && !d.flushNow
		d.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not enter the batch window")
		}
		time.Sleep(time.Millisecond)
	}
	d.capture(normalizeCaptureEvent(CaptureEvent{Action: "second"}, nopCaptureDiagnose))
	d.flush(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 2 || sent[0] != "first" || sent[1] != "second" {
		t.Fatalf("sent = %v", sent)
	}
}

func TestUnimplementedCapture(t *testing.T) {
	_, err := decidev2connect.UnimplementedDecideServiceHandler{}.Capture(
		context.Background(),
		connect.NewRequest(&decidev2.CaptureRequest{}),
	)
	if err == nil {
		t.Fatal("expected unimplemented")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
