package arcjet

import (
	"context"
	"fmt"
	"log/slog"
)

// SensitiveInfoBackend is a pluggable engine for sensitive-information
// detection. When a backend is supplied to a [SensitiveInfo] rule (via
// [SensitiveInfoOptions.Backend]) or a Guard sensitive-info rule (via
// [GuardSensitiveInfoOptions.Backend]), detection is dispatched to it instead
// of the bundled WebAssembly analyzer.
//
// A backend runs entirely in-process: the scanned text is never sent to the
// Arcjet service. The optional module
// github.com/arcjet/arcjet-go/sensitiveinfo/rampart implements this interface
// with an on-device NER model that detects many more entity types than the four
// the bundled analyzer recognises.
//
// Implementations must be safe for concurrent use; a single backend is shared
// across every request the rule evaluates.
type SensitiveInfoBackend interface {
	// Detect scans value and buckets every entity it finds into Allowed or
	// Denied according to entities. It must not send value anywhere off-process.
	Detect(
		ctx context.Context,
		bctx SensitiveInfoBackendContext,
		value string,
		entities SensitiveInfoEntities,
		opts *SensitiveInfoBackendOptions,
	) (SensitiveInfoResult, error)
}

// SensitiveInfoEntities describes the entity types a detection call is
// configured with. It mirrors the Allow/Deny options of the rule: when Deny is
// true, Entities is a deny-list (those types are denied, everything else
// allowed); when Deny is false, Entities is an allow-list (those types are
// allowed, everything else denied).
type SensitiveInfoEntities struct {
	// Deny reports whether Entities is a deny-list (true) or an allow-list
	// (false).
	Deny bool
	// Entities is the configured list of entity types.
	Entities []EntityType
}

// DetectedSensitiveInfoEntity is a single entity a backend located in the
// scanned text. Start and End are byte offsets into the value passed to Detect.
type DetectedSensitiveInfoEntity struct {
	Start int
	End   int
	Type  EntityType
}

// SensitiveInfoResult is what a [SensitiveInfoBackend] returns: every detected
// entity, partitioned into those the configuration allows and those it denies.
type SensitiveInfoResult struct {
	Allowed []DetectedSensitiveInfoEntity
	Denied  []DetectedSensitiveInfoEntity
}

// SensitiveInfoBackendContext carries per-call context to a backend.
type SensitiveInfoBackendContext struct {
	// Log is a logger the backend may use for diagnostics (for example when it
	// truncates over-long input). Never nil: the SDK substitutes
	// [slog.Default] when it has no logger of its own.
	Log *slog.Logger
}

// SensitiveInfoBackendOptions carries optional per-call configuration to a
// backend.
type SensitiveInfoBackendOptions struct {
	// Detect is the rule's custom token-classification callback, if any. It is
	// passed through for backends that can use it; the Rampart backend works on
	// character spans rather than tokens and ignores it.
	Detect SensitiveInfoDetect
}

// SensitiveInfoBackendEntitySupporter is an optional interface a
// [SensitiveInfoBackend] may implement to declare which entity types it can
// detect. When a backend implements it, the SDK validates a rule's Allow/Deny
// lists against this set and rejects a type the backend cannot produce (which
// would otherwise be silently ignored, never matching). Backends that do not
// implement it are trusted to handle any listed type.
type SensitiveInfoBackendEntitySupporter interface {
	// SupportedEntities returns every entity type the backend can detect.
	SupportedEntities() []EntityType
}

// nativeSensitiveInfoTypes is the set of entity types the bundled WebAssembly
// analyzer detects without a backend.
var nativeSensitiveInfoTypes = map[EntityType]struct{}{
	SensitiveInfoEmail:            {},
	SensitiveInfoPhoneNumber:      {},
	SensitiveInfoIPAddress:        {},
	SensitiveInfoCreditCardNumber: {},
}

// validateSensitiveInfoEntities rejects a configuration that lists an entity
// type nothing can detect, surfacing the misconfiguration rather than silently
// ignoring it (mirroring arcjet-js and arcjet-py). A custom Detect callback can
// classify anything, so it disables the check. With a backend, the listed types
// are validated against the backend's declared set when it implements
// [SensitiveInfoBackendEntitySupporter]; otherwise the backend is trusted.
// Without either, only the bundled analyzer's native types are allowed.
func validateSensitiveInfoEntities(allow, deny []EntityType, backend SensitiveInfoBackend, hasDetect bool) error {
	if hasDetect {
		return nil
	}

	supported, ok := sensitiveInfoSupportedTypes(backend)
	if backend != nil && !ok {
		// Backend that does not declare its entities: trust it to handle any
		// listed type.
		return nil
	}

	for _, list := range [][]EntityType{allow, deny} {
		for _, t := range list {
			if _, allowed := supported[t]; allowed {
				continue
			}
			if backend != nil {
				return fmt.Errorf("arcjet: sensitive info: %w: %q is not detected "+
					"by the configured backend", ErrUnsupportedEntityType, string(t))
			}
			return fmt.Errorf("arcjet: sensitive info: %w: %q requires a backend "+
				"(github.com/arcjet/arcjet-go/sensitiveinfo/rampart) or a custom Detect",
				ErrUnsupportedEntityType, string(t))
		}
	}
	return nil
}

// sensitiveInfoSupportedTypes returns the set of entity types considered
// detectable for validation. With no backend it is the bundled analyzer's
// native types. With a backend that declares its entities it is that declared
// set; ok is false for a backend that does not declare (the caller then trusts
// it).
func sensitiveInfoSupportedTypes(backend SensitiveInfoBackend) (set map[EntityType]struct{}, ok bool) {
	if backend == nil {
		return nativeSensitiveInfoTypes, true
	}
	supporter, ok := backend.(SensitiveInfoBackendEntitySupporter)
	if !ok {
		return nil, false
	}
	declared := supporter.SupportedEntities()
	set = make(map[EntityType]struct{}, len(declared))
	for _, t := range declared {
		set[t] = struct{}{}
	}
	return set, true
}

// backendContext returns the context passed to a backend, defaulting the
// logger to [slog.Default].
func backendContext() SensitiveInfoBackendContext {
	return SensitiveInfoBackendContext{Log: slog.Default()}
}

// backendEntities projects a rule's Allow/Deny lists into the
// [SensitiveInfoEntities] a backend receives.
func backendEntities(allow, deny []EntityType) SensitiveInfoEntities {
	if len(allow) > 0 {
		return SensitiveInfoEntities{Deny: false, Entities: allow}
	}
	return SensitiveInfoEntities{Deny: true, Entities: deny}
}
