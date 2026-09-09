package arcjet

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"
)

// OnGuardError selects what a helper does when policy could not be
// evaluated: Guard returned an error, the decision failed open, or a Resolve
// hook failed. The zero value is deny, so a policy literal that omits the
// field fails closed. OnGuardErrorAllow covers availability only; a
// misconfigured policy denies whatever it is set to. A DENY decision always
// blocks regardless of this
// setting.
type OnGuardError int

const (
	// OnGuardErrorDeny blocks the action when policy was not evaluated.
	OnGuardErrorDeny OnGuardError = iota
	// OnGuardErrorAllow runs the action when policy was not evaluated and
	// records the capture outcome as degraded.
	OnGuardErrorAllow
)

// String returns "deny" or "allow".
func (o OnGuardError) String() string {
	switch o {
	case OnGuardErrorDeny:
		return "deny"
	case OnGuardErrorAllow:
		return "allow"
	}
	// A value outside the two constants, which a caller can produce by
	// converting an integer.
	return fmt.Sprintf("OnGuardError(%d)", int(o))
}

// GuardActionInputs are the per-call values a GuardActionPolicy.Resolve hook
// computes from runtime input.
type GuardActionInputs struct {
	// Actor is the resolved actor identity available to remote policies.
	Actor string
	// Inputs are the resolved typed values exposed to remote policies.
	Inputs map[string]GuardPolicyInput
	// Rules are the resolved bound rule inputs.
	Rules []GuardRuleInput
}

// GuardActionPolicy describes one guarded action.
type GuardActionPolicy struct {
	// Action names the action. It is sent as the Guard label, so it must be a
	// valid label slug, and it names the capture event.
	Action string
	// Actor is an optional actor identity available to remote policies. An
	// empty string means unset.
	Actor string
	// Inputs are typed values exposed to remote policies.
	Inputs map[string]GuardPolicyInput
	// Rules are bound rule inputs. Guard is called even when Rules is empty,
	// because the server selects remote policy by label.
	Rules []GuardRuleInput
	// Resolve, when set, computes Actor, Inputs, and Rules at call time and
	// replaces the static fields above. An error counts as unevaluated
	// policy.
	Resolve func(ctx context.Context) (GuardActionInputs, error)
	// Metadata is attached to the Guard call and to the capture event. The
	// capture event's "outcome" key is written by GuardAction and overrides
	// any caller value of that name.
	Metadata Metadata
	// CorrelationID, when set, wins over the ID carried by the context.
	CorrelationID string
	// OnGuardError selects fail closed (the zero value) or fail open.
	OnGuardError OnGuardError
}

// GuardDeniedError is returned by GuardAction when policy evaluated and
// denied the action. It is returned regardless of OnGuardError.
type GuardDeniedError struct {
	Action   string
	Decision GuardDecision
	// Err is set when the decision was reached but something around it
	// failed, such as a locally enforced denial whose report to the server
	// did not send. The denial stands; Err says what else went wrong, so a
	// caller can alert on the lost telemetry rather than never learning of
	// it. Nil in the ordinary case.
	Err error
}

// Unwrap returns [GuardDeniedError.Err], so errors.Is and errors.As reach a
// failure that accompanied the denial.
func (e *GuardDeniedError) Unwrap() error { return e.Err }

// Error implements error.
func (e *GuardDeniedError) Error() string {
	return fmt.Sprintf("arcjet: denied action %q (%s)", e.Action, e.Decision.Reason)
}

// GuardUnavailableError is returned by GuardAction when policy could not be
// evaluated and the policy fails closed. Err holds the error Guard or Resolve
// returned, when there was one. Decision holds the fail-open decision Guard
// returned, when there was one. The Go client returns both on a transport
// failure, so both fields can be set.
type GuardUnavailableError struct {
	Action   string
	Decision *GuardDecision
	Err      error
}

// Error implements error.
func (e *GuardUnavailableError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("arcjet: policy for action %q could not be evaluated: %v", e.Action, e.Err)
	}
	return fmt.Sprintf("arcjet: policy for action %q could not be evaluated", e.Action)
}

// Unwrap returns Err so errors.Is and errors.As see the underlying error.
func (e *GuardUnavailableError) Unwrap() error { return e.Err }

const (
	guardOutcomeSuccess     = "success"
	guardOutcomeDegraded    = "degraded"
	guardOutcomeDenied      = "denied"
	guardOutcomeError       = "error"
	guardOutcomeUnavailable = "unavailable"
)

// defaultGuardTimeout bounds the Guard call GuardAction makes when the
// caller's context carries no deadline. Without it a Decide service that
// accepts a connection and then stops responding would hang the action
// forever rather than failing closed. It matches the Protect default.
const defaultGuardTimeout = 2 * time.Second

func captureGuardOutcome(client *GuardClient, policy GuardActionPolicy, correlationID, decisionID, outcome string) {
	md := make(Metadata, len(policy.Metadata)+1)
	maps.Copy(md, policy.Metadata)
	md["outcome"] = outcome
	client.Capture(CaptureEvent{
		Action:        policy.Action,
		CorrelationID: correlationID,
		DecisionID:    decisionID,
		Metadata:      md,
	})
}

// GuardAction evaluates policy for one action and runs fn only if the policy
// allows it. It is the fail-closed helper for consequential effects: tool
// calls, jobs, and workers.
//
// A nil fn returns *GuardUnavailableError wrapping ErrNilAction; Guard is not
// called and no capture event is recorded. Otherwise, every call reaches
// Guard, including with no rules, because the server selects remote policy
// by the action label. A DENY decision returns a *GuardDeniedError without
// running fn, regardless of policy.OnGuardError. An unevaluated policy
// (Guard returned an error, the decision failed open, or Resolve failed)
// returns a *GuardUnavailableError under the default OnGuardErrorDeny, or
// runs fn under OnGuardErrorAllow.
//
// Each call records one capture event named policy.Action whose metadata
// "outcome" is "success", "degraded", "denied", "error", or "unavailable".
// A decision ID is attached when the decision has one. Capture is
// best-effort and never affects the returned values.
//
// The correlation ID is policy.CorrelationID when set, otherwise the ID
// carried by ctx via ContextWithCorrelationID, otherwise none.
func GuardAction[T any](ctx context.Context, client *GuardClient, policy GuardActionPolicy, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if fn == nil {
		return zero, &GuardUnavailableError{Action: policy.Action, Err: ErrNilAction}
	}
	correlationID := policy.CorrelationID
	if correlationID == "" {
		correlationID, _ = CorrelationIDFromContext(ctx)
	}

	inputs := GuardActionInputs{Actor: policy.Actor, Inputs: policy.Inputs, Rules: policy.Rules}
	var decision GuardDecision
	var guardErr error
	var guardCalled bool
	if policy.Resolve != nil {
		inputs, guardErr = policy.Resolve(ctx)
	}
	if guardErr == nil {
		req := GuardRequest{
			Label:         policy.Action,
			Inputs:        inputs.Inputs,
			Metadata:      policy.Metadata,
			CorrelationID: correlationID,
			Rules:         inputs.Rules,
		}
		if inputs.Actor != "" {
			actor := inputs.Actor
			req.Actor = &actor
		}
		guardCalled = true
		guardCtx, cancel := withDefaultDeadline(ctx, defaultGuardTimeout)
		decision, guardErr = client.Guard(guardCtx, req)
		cancel()
	}

	// A DENY is a completed decision even when Guard also returned an error
	// (a locally enforced denial whose reporting failed), so it wins.
	if decision.IsDenied() {
		captureGuardOutcome(client, policy, correlationID, decision.ID, guardOutcomeDenied)
		return zero, &GuardDeniedError{Action: policy.Action, Decision: decision, Err: guardErr}
	}

	// Guard marks a request it could not use with ErrGuardMisconfigured, and
	// that class is not an availability problem, so OnGuardErrorAllow does
	// not cover it: allowing there would run the action under policy that was
	// never evaluated. A Resolve hook that fails never reaches Guard and
	// stays governed by OnGuardError.
	hasDecision := decision.ID != "" || decision.Conclusion != ""
	misconfigured := guardCalled && errors.Is(guardErr, ErrGuardMisconfigured)

	degraded := false
	if guardErr != nil || !decision.IsAllowed() || decision.HasFailedOpen() {
		if misconfigured || policy.OnGuardError != OnGuardErrorAllow {
			captureGuardOutcome(client, policy, correlationID, decision.ID, guardOutcomeUnavailable)
			unavailable := &GuardUnavailableError{Action: policy.Action, Err: guardErr}
			// guardCalled alone is not enough: a programmer error (nil client,
			// invalid label) also reaches client.Guard but returns the
			// zero-value decision, which is not a decision to report. Require
			// the decision to carry an ID or a conclusion too.
			if guardCalled && hasDecision {
				d := decision
				unavailable.Decision = &d
			}
			return zero, unavailable
		}
		degraded = true
	}

	out, err := fn(ctx)
	if err != nil {
		captureGuardOutcome(client, policy, correlationID, decision.ID, guardOutcomeError)
		return out, err
	}
	outcome := guardOutcomeSuccess
	if degraded {
		outcome = guardOutcomeDegraded
	}
	captureGuardOutcome(client, policy, correlationID, decision.ID, outcome)
	return out, nil
}
