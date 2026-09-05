package arcjet

import (
	"context"
	"fmt"
)

// OnGuardError selects what a helper does when policy could not be
// evaluated: Guard returned an error, the decision failed open, or a Resolve
// hook failed. The zero value is deny, so a policy literal that omits the
// field fails closed. A DENY decision always blocks regardless of this
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
	return fmt.Sprintf("OnGuardError(%d)", int(o))
}

// GuardActionInputs are the per-call values a GuardActionPolicy.Resolve hook
// computes from runtime input.
type GuardActionInputs struct {
	Actor  string
	Inputs map[string]GuardPolicyInput
	Rules  []GuardRuleInput
}

// GuardActionPolicy describes one guarded action.
type GuardActionPolicy struct {
	// Action names the action. It is sent as the Guard label, so it must be a
	// valid label slug, and it names the capture event.
	Action string
	// Actor is an optional actor identity available to remote policies.
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
	// CorrelationId, when set, wins over the ID carried by the context.
	CorrelationId string
	// OnGuardError selects fail closed (the zero value) or fail open.
	OnGuardError OnGuardError
}

// GuardDeniedError is returned by GuardAction when policy evaluated and
// denied the action. It is returned regardless of OnGuardError.
type GuardDeniedError struct {
	Action   string
	Decision GuardDecision
}

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
