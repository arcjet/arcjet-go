package arcjet

import "errors"

// Sentinel errors returned by configuration and validation paths. Wrap them
// with fmt.Errorf("...: %w", Err...) when adding context so callers can detect
// the underlying cause via errors.Is.
//
// Remote errors and per-rule errors are surfaced as ArcjetError values.
var (
	// ErrMissingKey is returned when no Arcjet site key is configured.
	ErrMissingKey = errors.New("site key required (set Config.Key or ARCJET_KEY)")
	// ErrNilClient is returned when a method is called on a nil Client or
	// GuardClient.
	ErrNilClient = errors.New("client is nil")
	// ErrNilRequest is returned when Client.Protect is called with a nil
	// *http.Request.
	ErrNilRequest = errors.New("request is nil")
	// ErrNilRule is returned when a rule input is nil.
	ErrNilRule = errors.New("rule is nil")
	// ErrInvalidPolicyInput is returned when a Guard policy input is nil or
	// cannot be represented by the remote-policy wire protocol.
	ErrInvalidPolicyInput = errors.New("invalid guard policy input")
	// ErrInvalidMode is returned when a Mode value is unrecognized.
	ErrInvalidMode = errors.New("invalid mode")
	// ErrAllowDenyConflict is returned when a rule sets both Allow and Deny.
	ErrAllowDenyConflict = errors.New("allow and deny are mutually exclusive")
	// ErrUnsupportedEntityType is returned when a sensitive-info rule lists an
	// entity type that neither the bundled analyzer nor a configured backend
	// can detect.
	ErrUnsupportedEntityType = errors.New("unsupported sensitive info entity type")
	// ErrInvalidProxy is returned when a trusted proxy IP or CIDR is invalid.
	ErrInvalidProxy = errors.New("invalid trusted proxy")
	// ErrInvalidIP is returned when an explicit client IP is invalid.
	ErrInvalidIP = errors.New("invalid client IP")
	// ErrInvalidPlatform is returned when Config.Platform is not a recognized
	// Platform value.
	ErrInvalidPlatform = errors.New("invalid platform")
	// ErrGuardMisconfigured marks a Guard call that failed because the
	// request itself is not usable: a nil client, an invalid label, a nil or
	// unbindable rule, an invalid policy input, or a request that cannot be
	// encoded. It is joined to the specific cause, so errors.Is still finds
	// that cause as well.
	//
	// The distinction is load bearing. Guard's other failure mode is runtime
	// degradation, which is fail-open and carries a usable decision, whereas
	// a misconfigured request was never evaluated at all. [GuardAction] denies
	// on this class regardless of OnGuardError, because OnGuardErrorAllow is
	// a statement about availability rather than a licence to run an action
	// under policy that never ran.
	ErrGuardMisconfigured = errors.New("guard request is not usable")
	// ErrInvalidLabel is returned when a Guard label fails validation.
	ErrInvalidLabel = errors.New("invalid guard label")
	// ErrInvalidRateLimit is returned when rate-limit options are invalid.
	ErrInvalidRateLimit = errors.New("invalid rate limit configuration")
	// ErrEmptyKey is returned when a Guard rate-limit key is empty.
	ErrEmptyKey = errors.New("rate limit key required")
	// ErrMissingFunc is returned when a custom rule has no evaluation
	// function.
	ErrMissingFunc = errors.New("custom rule function required")
	// ErrNilAction is returned by GuardAction when fn is nil.
	ErrNilAction = errors.New("guard action function required")
	// ErrInvalidWasm is returned when a Wasm module is empty or invalid.
	ErrInvalidWasm = errors.New("invalid wasm module")
	// ErrWasmClosed is returned when a Wasm module method is called after
	// Close.
	ErrWasmClosed = errors.New("wasm module is closed")
	// ErrWasmExportNotFound is returned when a Wasm function export is
	// missing.
	ErrWasmExportNotFound = errors.New("wasm export not found")
	// ErrEmptyResponse is returned when Arcjet returns an empty decision
	// response.
	ErrEmptyResponse = errors.New("empty response")
)
