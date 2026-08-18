package arcjet

import (
	"context"
	"fmt"
	"sync"
)

// Optional process-wide registration for a Guard client.
//
// Registering exists for one reason: so code that cannot reach a *GuardClient
// can still call [Guard], [Capture], and [Flush]. Passing a client explicitly
// always works and is the recommended path — this is the shortcut, not the
// default. Nothing here takes effect until an application calls
// [RegisterArcjet]; [NewGuardClient] touches no global state.
//
// A registered client rather than a context value is deliberate. The call sites
// this serves — a queue worker, a background job, a domain function issuing a
// refund — were handed nothing, and a client read out of a context.Context
// would still have to be threaded to reach them, which is the problem
// registration exists to avoid. Context stays what it is in the rest of this
// package: cancellation and deadlines.
var (
	registryMu sync.RWMutex
	registered *GuardClient
)

// noRegisteredClientMessage is the message carried by the fail-open decision the
// package-level Guard returns when nothing is registered. Text matches
// arcjet-js so one support answer covers both.
const noRegisteredClientMessage = "guard() was called with no registered Arcjet client"

// RegisterArcjet registers client for the package-level [Guard], [Capture],
// and [Flush] functions.
//
// Guarded on purpose. If a second, different client tries to register, the
// first one stays and the attempt is reported on the incumbent's diagnostics
// channel, so a library — or a stray second [NewGuardClient] — cannot quietly
// redirect an application's telemetry to a different site key. Registering the
// client that is already registered is a no-op rather than a warning, so a
// package initialized twice stays silent. A nil client is refused, since the
// package-level functions could not call it.
//
// Call it once at startup:
//
//	client, err := arcjet.NewGuardClient(arcjet.GuardConfig{Key: os.Getenv("ARCJET_KEY")})
//	if err != nil {
//		return err
//	}
//	arcjet.RegisterArcjet(client)
//	defer arcjet.UnregisterArcjet()
func RegisterArcjet(client *GuardClient) {
	if client == nil {
		return
	}

	registryMu.Lock()
	existing := registered
	if existing == nil {
		registered = client
		registryMu.Unlock()
		return
	}
	registryMu.Unlock()

	if existing == client {
		return
	}

	// Reported on the incumbent's channel, not the late registrant's: the
	// application that registered first configured that logger, and it is the
	// one whose telemetry an unnoticed second registration would have
	// redirected. Reported outside the lock so a slow handler cannot stall
	// another goroutine's Guard call.
	existing.reportCaptureDiagnostic(clientAlreadyRegisteredCode, 1)
}

// UnregisterArcjet clears the registered client, if any.
//
// It takes no argument and clears whatever is there. That asymmetry with
// [RegisterArcjet] is deliberate: requiring the client back would mean every
// teardown has to keep hold of it, which is the exact problem registration
// exists to avoid.
//
// The cost is that anything calling this clears the application's client, and
// every package-level call after it fails open. Libraries should not call it —
// they take a client explicitly. That is a convention, not something enforced
// here.
func UnregisterArcjet() {
	registryMu.Lock()
	registered = nil
	registryMu.Unlock()
}

// registeredClient returns the registered client, or nil when there is none.
func registeredClient() *GuardClient {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registered
}

// Guard evaluates bound guard rule inputs through the registered client.
//
// With nothing registered it returns a usable fail-open ALLOW carrying a
// synthetic errored result, so [GuardDecision.HasFailedOpen] reports true and a
// caller that only inspects the decision still sees that no rule ran. It also
// returns ErrNoRegisteredClient, because a Go caller checking the error is the
// idiomatic way to learn about a misconfiguration — the same decision-plus-error
// shape [GuardClient.Guard] uses for a transport failure.
//
// See [GuardClient.Guard] for the behavior once a client is registered.
func Guard(ctx context.Context, req GuardRequest) (GuardDecision, error) {
	client := registeredClient()
	if client == nil {
		return guardErrorDecision("TRANSPORT_ERROR", noRegisteredClientMessage),
			fmt.Errorf("arcjet: %w", ErrNoRegisteredClient)
	}
	return client.Guard(ctx, req)
}

// Capture records a fact about what the application did, through the registered
// client.
//
// With nothing registered the event is dropped silently. Capture is best-effort
// telemetry, which is what makes dropping acceptable, and this path has no
// configured logger to report to — the client that would have carried one is the
// thing that is missing. Silence is the deliberate choice over an
// unconfigurable warning, which would be noise on a request path with no way to
// turn it off.
//
// See [GuardClient.Capture] for the behavior once a client is registered.
func Capture(event CaptureEvent) {
	if client := registeredClient(); client != nil {
		client.Capture(event)
	}
}

// Flush drains the registered client's buffered capture events.
//
// Returns immediately with nothing registered — there is no queue to drain.
//
// See [GuardClient.Flush] for the behavior once a client is registered.
func Flush(ctx context.Context) {
	if client := registeredClient(); client != nil {
		client.Flush(ctx)
	}
}
