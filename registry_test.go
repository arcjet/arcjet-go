package arcjet

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

// withCleanRegistry makes the process-wide slot safe to use from a test: it
// asserts nothing is registered on entry and clears it on exit. Every test that
// registers must use it, because `just test` runs with -shuffle=on and a leaked
// registration would make an unrelated test's outcome depend on ordering.
func withCleanRegistry(t *testing.T) {
	t.Helper()
	if registeredClient() != nil {
		t.Fatal("a previous test leaked a registered client")
	}
	t.Cleanup(UnregisterArcjet)
}

// newLoggedGuardClient builds a Guard client wired to handler whose diagnostics
// land in a recorder, so a test can assert on what the client reported.
func newLoggedGuardClient(t *testing.T, handler *testGuardHandler) (*GuardClient, *recordingHandler) {
	t.Helper()
	client, _ := newGuardTestClient(t, handler)
	logger, records := newRecordingLogger()
	client.diagnostics = newDiagnostics(logger)
	client.diagnose = client.diagnostics.report
	return client, records
}

// allowResponseHandler returns a handler with a canned ALLOW that references no
// rule submissions, so these tests can call Guard with an empty rule set. The
// shared default response in guard_test.go indexes RuleSubmissions()[0] and
// would panic. An empty set is a legitimate call: it still reaches Arcjet and
// returns a real decision.
func allowResponseHandler() *testGuardHandler {
	return &testGuardHandler{
		resp: &decidev2.GuardResponse{
			Decision: &decidev2.GuardDecision{
				Id:         "gdec_registry",
				Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
			},
		},
	}
}

func TestRegisterArcjetEnablesPackageLevelCalls(t *testing.T) {
	withCleanRegistry(t)
	handler := allowResponseHandler()
	client, _ := newGuardTestClient(t, handler)

	RegisterArcjet(client)

	decision, err := Guard(context.Background(), GuardRequest{Label: "tools.weather"})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if handler.guardCalls != 1 {
		t.Errorf("guardCalls = %d, want 1", handler.guardCalls)
	}
	if decision.HasFailedOpen() {
		t.Error("decision failed open through a registered client")
	}

	Capture(CaptureEvent{Action: "refund.issued"})
	Flush(context.Background())

	events := handler.capturedEvents()
	if len(events) != 1 || events[0].GetAction() != "refund.issued" {
		t.Fatalf("captured events = %+v", events)
	}
}

func TestRegisterArcjetRefusesNilClient(t *testing.T) {
	withCleanRegistry(t)

	RegisterArcjet(nil)

	if registeredClient() != nil {
		t.Fatal("a nil client was registered")
	}
	// The package-level calls must still be safe.
	Capture(CaptureEvent{Action: "refund.issued"})
	Flush(context.Background())
}

func TestRegisterArcjetKeepsIncumbentAndReportsOnItsChannel(t *testing.T) {
	withCleanRegistry(t)
	firstHandler := allowResponseHandler()
	first, firstRecords := newLoggedGuardClient(t, firstHandler)
	secondHandler := allowResponseHandler()
	second, secondRecords := newLoggedGuardClient(t, secondHandler)

	RegisterArcjet(first)
	RegisterArcjet(second)

	if registeredClient() != first {
		t.Fatal("the second client displaced the first")
	}

	// The warning belongs to the application that registered first, on the
	// logger it configured — it is the one whose telemetry would have been
	// silently redirected.
	records := firstRecords.snapshot()
	if len(records) != 1 {
		t.Fatalf("incumbent records = %d, want 1: %+v", len(records), records)
	}
	if records[0].code != clientAlreadyRegisteredCode {
		t.Errorf("code = %q, want %q", records[0].code, clientAlreadyRegisteredCode)
	}
	if got := secondRecords.snapshot(); len(got) != 0 {
		t.Errorf("late registrant records = %+v, want none", got)
	}

	// Traffic keeps going to the incumbent.
	if _, err := Guard(context.Background(), GuardRequest{Label: "tools.weather"}); err != nil {
		t.Fatal(err)
	}
	if firstHandler.guardCalls != 1 || secondHandler.guardCalls != 0 {
		t.Errorf("guardCalls first = %d, second = %d", firstHandler.guardCalls, secondHandler.guardCalls)
	}
}

func TestRegisterArcjetSameClientTwiceIsSilent(t *testing.T) {
	withCleanRegistry(t)
	client, records := newLoggedGuardClient(t, &testGuardHandler{})

	// A package initialized twice must not look like a misconfiguration.
	RegisterArcjet(client)
	RegisterArcjet(client)

	if got := records.snapshot(); len(got) != 0 {
		t.Errorf("records = %+v, want none", got)
	}
	if registeredClient() != client {
		t.Error("client is no longer registered")
	}
}

func TestUnregisterArcjetClearsTheSlot(t *testing.T) {
	withCleanRegistry(t)
	client, _ := newGuardTestClient(t, &testGuardHandler{})

	RegisterArcjet(client)
	UnregisterArcjet()

	if registeredClient() != nil {
		t.Fatal("slot still holds a client")
	}
	// Clearing then registering again is allowed and silent — that is what
	// makes a test able to swap clients.
	RegisterArcjet(client)
	if registeredClient() != client {
		t.Fatal("re-registration after unregister failed")
	}
	UnregisterArcjet()
}

func TestGuardWithNothingRegisteredFailsOpen(t *testing.T) {
	withCleanRegistry(t)

	decision, err := Guard(context.Background(), GuardRequest{Label: "tools.weather"})

	if !errors.Is(err, ErrNoRegisteredClient) {
		t.Fatalf("err = %v, want ErrNoRegisteredClient", err)
	}
	// A caller that ignores the error must still get an inspectable decision:
	// ALLOW, but visibly one where no rule ran.
	if !decision.IsAllowed() {
		t.Error("decision is not ALLOW")
	}
	if !decision.HasFailedOpen() {
		t.Error("HasFailedOpen() = false; a fail-closed caller could not tell")
	}
	errored := decision.ErrorResults()
	if len(errored) != 1 {
		t.Fatalf("error results = %d, want 1", len(errored))
	}
	if errored[0].Error.Code != "TRANSPORT_ERROR" {
		t.Errorf("code = %q", errored[0].Error.Code)
	}
	if errored[0].Error.Message != noRegisteredClientMessage {
		t.Errorf("message = %q", errored[0].Error.Message)
	}
	if decision.Err() == nil {
		t.Error("decision.Err() = nil")
	}
}

func TestCaptureAndFlushWithNothingRegisteredAreSilent(t *testing.T) {
	withCleanRegistry(t)

	// Capture is best-effort telemetry and there is no client to carry a
	// logger, so this drops without reporting anywhere. The contract being
	// tested is that it neither panics nor blocks.
	previous := slog.Default()
	logger, records := newRecordingLogger()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })

	Capture(CaptureEvent{Action: "refund.issued"})
	Capture(CaptureEvent{}) // invalid, and still nowhere to report it
	Flush(context.Background())
	Flush(nil) //nolint:staticcheck // nil ctx is the contract under test

	if got := records.snapshot(); len(got) != 0 {
		t.Errorf("records = %+v, want none — there is no configured sink", got)
	}
}

func TestRegistryConcurrentRegisterAndCall(t *testing.T) {
	withCleanRegistry(t)
	handler := &testGuardHandler{}
	client, _ := newGuardTestClient(t, handler)

	// Registration races with the package-level readers. Exercised under -race
	// in CI; what matters is that no call observes a torn slot.
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 25 {
				RegisterArcjet(client)
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for range 25 {
				Capture(CaptureEvent{Action: "refund.issued"})
				_ = registeredClient()
			}
		})
	}
	wg.Wait()

	if registeredClient() != client {
		t.Fatal("client is not registered after concurrent registration")
	}
	Flush(context.Background())
}
