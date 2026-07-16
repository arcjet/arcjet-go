package arcjet

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

// testCaptureHandler records the Capture request it receives and signals on
// got, since ExperimentalCapture is fire-and-forget and cannot be awaited.
type testCaptureHandler struct {
	// Guard is served as unimplemented; capture tests never call it.
	decidev2connect.UnimplementedDecideServiceHandler

	mu     sync.Mutex
	seen   *decidev2.CaptureRequest
	header http.Header
	got    chan struct{}
}

func newTestCaptureHandler() *testCaptureHandler {
	return &testCaptureHandler{got: make(chan struct{}, 1)}
}

func (h *testCaptureHandler) Capture(ctx context.Context, req *connect.Request[decidev2.CaptureRequest]) (*connect.Response[decidev2.CaptureResponse], error) {
	h.mu.Lock()
	h.seen = req.Msg
	h.header = req.Header()
	h.mu.Unlock()
	h.got <- struct{}{}
	return connect.NewResponse(&decidev2.CaptureResponse{}), nil
}

func (h *testCaptureHandler) await(t *testing.T) *decidev2.CaptureRequest {
	t.Helper()
	select {
	case <-h.got:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Capture RPC")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seen
}

func newCaptureTestClient(t *testing.T, handler *testCaptureHandler) *GuardClient {
	t.Helper()
	path, h := decidev2connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	client, err := NewGuardClient(GuardConfig{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestExperimentalCaptureSendsEventWithAuth(t *testing.T) {
	handler := newTestCaptureHandler()
	client := newCaptureTestClient(t, handler)

	occurredAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	client.ExperimentalCapture(context.Background(), CaptureOptions{
		Action:        "refund.issued",
		CorrelationId: "wf_abcdef",
		DecisionId:    "gdec_abc",
		OccurredAt:    occurredAt,
		Metadata:      map[string]string{"invoice": "inv_123"},
	})

	req := handler.await(t)
	if got := len(req.GetEvents()); got != 1 {
		t.Fatalf("event count = %d", got)
	}
	event := req.GetEvents()[0]
	if got := event.GetAction(); got != "refund.issued" {
		t.Fatalf("action = %q", got)
	}
	if got := event.GetCorrelationId(); got != "wf_abcdef" {
		t.Fatalf("correlation id = %q", got)
	}
	if got := event.GetDecisionId(); got != "gdec_abc" {
		t.Fatalf("decision id = %q", got)
	}
	if got := event.GetOccurredAtUnixMs(); got != uint64(occurredAt.UnixMilli()) {
		t.Fatalf("occurred at = %d, want %d", got, occurredAt.UnixMilli())
	}
	if got := event.GetMetadata()["invoice"]; got != "inv_123" {
		t.Fatalf("metadata invoice = %q", got)
	}
	if req.SentAtUnixMs == nil || req.GetSentAtUnixMs() == 0 {
		t.Fatal("sent_at_unix_ms missing")
	}
	if got := req.GetUserAgent(); got == "" {
		t.Fatal("user agent missing")
	}
	if got := handler.header.Get("Authorization"); got != "Bearer ajkey_test" {
		t.Fatalf("authorization header = %q", got)
	}
}

func TestExperimentalCaptureOccurredAtDefaultsToSentAt(t *testing.T) {
	handler := newTestCaptureHandler()
	client := newCaptureTestClient(t, handler)

	client.ExperimentalCapture(context.Background(), CaptureOptions{
		Action: "refund.issued",
	})

	req := handler.await(t)
	event := req.GetEvents()[0]
	if event.GetOccurredAtUnixMs() != req.GetSentAtUnixMs() {
		t.Fatalf("occurred at = %d, want sent at %d",
			event.GetOccurredAtUnixMs(), req.GetSentAtUnixMs())
	}
}

func TestExperimentalCaptureSurvivesCallerCancellation(t *testing.T) {
	handler := newTestCaptureHandler()
	client := newCaptureTestClient(t, handler)

	// A request handler typically cancels its context on return; the
	// fire-and-forget send must be detached from that cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client.ExperimentalCapture(ctx, CaptureOptions{Action: "refund.issued"})

	req := handler.await(t)
	if got := req.GetEvents()[0].GetAction(); got != "refund.issued" {
		t.Fatalf("action = %q", got)
	}
}

func TestExperimentalCaptureNilClientDoesNotPanic(t *testing.T) {
	var client *GuardClient
	client.ExperimentalCapture(context.Background(), CaptureOptions{Action: "refund.issued"})
}
