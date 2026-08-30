package arcjet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1/decidev1alpha1connect"
)

// reportTimeout bounds the background Report RPC issued after a local or
// cached decision so a slow Arcjet endpoint cannot pile up goroutines.
const reportTimeout = 5 * time.Second

// defaultProtectTimeout is applied when the caller's context has no deadline,
// matching the JavaScript and Python SDKs (2s). An email rule doubles it;
// a prompt-injection rule floors it at 1s (already satisfied by the 2s base).
// A caller-supplied deadline is never shortened.
const defaultProtectTimeout = 2 * time.Second

const (
	defaultDecideURL    = "https://decide.arcjet.com"
	defaultFlyDecideURL = "https://fly.decide.arcjet.com"
)

// Config configures a request protection Client.
type Config struct {
	// Key is the Arcjet site key. If empty, ARCJET_KEY is used.
	Key string
	// Rules are the request protection rules evaluated for each request.
	Rules []Rule
	// Characteristics are global rate-limit characteristic keys.
	Characteristics []string
	// HTTPClient is the client used for Arcjet RPCs. If nil, http.DefaultClient
	// is used, which honors the standard HTTP_PROXY, HTTPS_PROXY, and NO_PROXY
	// environment variables via http.ProxyFromEnvironment. Supply a custom
	// client only if you need different behavior; set its Transport's Proxy to
	// http.ProxyFromEnvironment to preserve outbound proxy support.
	HTTPClient *http.Client
	// BaseURL overrides the Arcjet Decide API base URL.
	BaseURL string
	// SDKVersion overrides the version reported to Arcjet.
	SDKVersion string
	// Proxies are the IP addresses or CIDRs of reverse proxies that are allowed
	// to supply X-Forwarded-For. NewClient rejects blank or malformed entries.
	// Configure every proxy hop and keep each range as narrow as possible; /0
	// entries trust an entire address family and produce a warning.
	//
	// When no managed platform is detected and RemoteAddr does not contain a
	// public IP, Arcjet may fall back to a public IP in a common forwarding
	// header. That result is unverified and produces one warning for the
	// lifetime of this Client. Use ClientIPDetails to inspect the result.
	//
	// Example:
	//
	//	client, err := arcjet.NewClient(arcjet.Config{
	//		Key:     os.Getenv("ARCJET_KEY"),
	//		Proxies: []string{"10.0.0.0/8", "192.168.1.10"},
	//	})
	Proxies []string
	// Log receives SDK diagnostics. If nil, slog.Default is used.
	Log *slog.Logger
	// Platform selects a managed hosting platform explicitly, overriding the
	// environment auto-detection. Set it when running behind a platform whose
	// environment variables aren't present — most importantly a Go service
	// behind the Cloudflare CDN. Leave empty to auto-detect.
	Platform Platform
	// SensitiveInfoDetect, if set, classifies tokens the bundled analyzer
	// didn't recognise. Shared across every SensitiveInfo rule on this
	// Client — the same callback model as arcjet-py's
	// `ImportCallbacks.sensitive_info_detect` and arcjet-js's analyzer
	// `detect` hook.
	SensitiveInfoDetect SensitiveInfoDetect
}

// SensitiveInfoDetect classifies tokens that the bundled wasm analyzer
// didn't recognise. The returned slice must have one entry per input
// token; an empty EntityType leaves the token unclassified, otherwise the
// value is recorded — either a built-in constant (SensitiveInfoEmail,
// SensitiveInfoPhoneNumber, …) or any custom label.
type SensitiveInfoDetect func(ctx context.Context, tokens []string) []EntityType

// Client evaluates HTTP requests with Arcjet request protection rules.
//
// A Client is safe for concurrent use and should be created once at startup and
// reused across handlers.
//
// The cache field is shared by clients derived via WithRule — derivatives
// shallow-copy the parent and alias the pointer so per-rule cache entries
// outlive each route-specific clone. All other fields are owned per-client.
type Client struct {
	key     string
	rules   []Rule
	ruleIDs []string
	// fpChars[i] is the characteristics list used to derive rule i's cache
	// fingerprint: the rule's own characteristics when it sets them (rate
	// limits), otherwise the client-level characteristics.
	fpChars    [][]string
	builtRules []*decidev1.Rule
	// builtRuleIndices[j] is the index into rules/ruleIDs/fpChars of the
	// rule that produced builtRules[j]. No-op rules are dropped from
	// builtRules, so this mapping is needed to align Decide-response
	// RuleResults back to the originating rule's cache namespace.
	builtRuleIndices []int
	characteristics  []string
	decideClient     decidev1alpha1connect.DecideServiceClient
	sdkVersion       string
	userAgent        string
	proxies          []trustedProxy
	platform         hostingPlatform
	local            *localEvaluator
	cache            *ruleCache
	log              *slog.Logger
	ipWarning        *clientIPWarningState
}

type clientIPWarningState struct {
	once sync.Once
}

// NewClient creates a reusable request protection client.
//
// If Config.Key is empty, NewClient reads ARCJET_KEY from the environment.
func NewClient(cfg Config) (*Client, error) {
	key := cfg.Key
	if key == "" {
		key = os.Getenv("ARCJET_KEY")
	}
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("arcjet: %w", ErrMissingKey)
	}

	version := cfg.SDKVersion
	if version == "" {
		version = Version
	}

	baseURL := defaultBaseURL(cfg.BaseURL)
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	ua := userAgent("arcjet-go", version)
	proxies, err := parseTrustedProxies(cfg.Proxies)
	if err != nil {
		return nil, err
	}
	logger := cfg.Log
	if logger == nil {
		logger = slog.Default()
	}
	if hasTrustAllProxy(proxies) {
		logger.Warn("Arcjet proxy configuration trusts an entire IP address family; use the narrowest proxy CIDRs possible", "trust_all", true)
	}
	platform := detectPlatform(os.Getenv)
	if cfg.Platform != "" {
		p, ok := cfg.Platform.toHostingPlatform()
		if !ok {
			return nil, fmt.Errorf("arcjet: %w: %q", ErrInvalidPlatform, cfg.Platform)
		}
		platform = p
	}
	rules := sortRulesByPriority(cfg.Rules)
	builtRules, builtRuleIndices, err := buildRequestRules(rules)
	if err != nil {
		return nil, err
	}
	local, err := newLocalEvaluator(context.Background(), rules, cfg.SensitiveInfoDetect)
	if err != nil {
		return nil, err
	}
	return &Client{
		key:              key,
		rules:            rules,
		ruleIDs:          collectRuleIDs(rules),
		fpChars:          collectFingerprintChars(rules, cfg.Characteristics),
		builtRules:       builtRules,
		builtRuleIndices: builtRuleIndices,
		characteristics:  append([]string(nil), cfg.Characteristics...),
		sdkVersion:       version,
		userAgent:        ua,
		proxies:          proxies,
		platform:         platform,
		decideClient:     decidev1alpha1connect.NewDecideServiceClient(httpClient, baseURL),
		local:            local,
		cache:            newRuleCache(),
		log:              logger,
		ipWarning:        &clientIPWarningState{},
	}, nil
}

// collectRuleIDs precomputes each rule's cache namespace once at client
// construction so Protect's hot path can index by position instead of
// invoking a virtual method per rule per request.
func collectRuleIDs(rules []Rule) []string {
	if len(rules) == 0 {
		return nil
	}
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.ruleID()
	}
	return out
}

// collectFingerprintChars precomputes, per rule, the characteristics used to
// derive that rule's cache fingerprint. Mirrors arcjet-js: a rate-limit rule
// fingerprints on its own characteristics (so a limit keyed on userId caches
// per user rather than per IP), while every other rule uses the client-level
// characteristics — the single global fingerprint.
func collectFingerprintChars(rules []Rule, clientChars []string) [][]string {
	if len(rules) == 0 {
		return nil
	}
	out := make([][]string, len(rules))
	for i, r := range rules {
		out[i] = fingerprintCharsFor(r, clientChars)
	}
	return out
}

// fingerprintCharsFor returns the rule's own characteristics when it declares
// any, otherwise the client-level characteristics.
func fingerprintCharsFor(r Rule, clientChars []string) []string {
	if rc := r.ruleCharacteristics(); len(rc) > 0 {
		return rc
	}
	return clientChars
}

// WithRule returns a copy of the client with an additional route-specific rule.
//
// The new rule is validated and converted to its wire form once; subsequent
// Protect calls reuse the cached representation.
func (c *Client) WithRule(rule Rule) (*Client, error) {
	if rule == nil {
		return nil, fmt.Errorf("arcjet: %w", ErrNilRule)
	}
	// Re-sort so the new rule lands in JS priority order and every
	// positional slice (ruleIDs, fpChars, builtRuleIndices) stays aligned.
	// Validation happens in buildRequestRules; a bad new rule fails there.
	rules := sortRulesByPriority(append(append([]Rule(nil), c.rules...), rule))
	builtRules, builtRuleIndices, err := buildRequestRules(rules)
	if err != nil {
		return nil, err
	}
	next := *c
	next.rules = rules
	next.ruleIDs = collectRuleIDs(rules)
	next.fpChars = collectFingerprintChars(rules, c.characteristics)
	next.builtRules = builtRules
	next.builtRuleIndices = builtRuleIndices
	next.characteristics = append([]string(nil), c.characteristics...)
	// Cache invalidation is per-rule via ruleID — adding a rule does not
	// touch existing rules' cache slots, so we keep the shared *ruleCache
	// from c rather than allocating a fresh one. The new rule simply has
	// no slot yet; its first Protect call will populate one.
	return &next, nil
}

// Close releases local WebAssembly resources held by the client.
func (c *Client) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return c.local.close(ctx)
}

// ProtectDetails is the request data Arcjet evaluates.
//
// Use DetailsFromRequest or Client.Protect for ordinary HTTP handlers. Construct
// ProtectDetails directly when protecting a non-standard request source.
type ProtectDetails struct {
	// IP is the request source IP address.
	IP string
	// Method is the HTTP method.
	Method string
	// Protocol is the HTTP protocol string.
	Protocol string
	// Host is the request host.
	Host string
	// Path is the URL path.
	Path string
	// Headers are request headers keyed by lowercase header name.
	Headers map[string]string
	// Body is an optional request body override.
	Body []byte
	// Email is the email address used by ValidateEmail.
	Email string
	// Cookies is the raw Cookie header.
	Cookies string
	// Query is the raw URL query, with or without a leading question mark.
	Query string
	// Extra contains additional string fields sent to Arcjet.
	Extra map[string]string
	// CorrelationId is an optional, caller-supplied opaque identifier used to
	// correlate this request with other Protect and Guard calls that belong to
	// the same workflow, agent run, or multi-step task. It does not affect the
	// decision and is excluded from the decision cache key; it is stored
	// alongside the recorded decision so a chain of actions can be
	// reconstructed. Bounded server-side to 256 bytes of printable ASCII;
	// invalid values are dropped, not truncated.
	CorrelationId   string
	clientIPDetails *ClientIPDetails
}

// ClientIPProvenance identifies where Arcjet obtained a client IP address.
type ClientIPProvenance string

const (
	// ClientIPProvenanceDirect means the address came from Request.RemoteAddr.
	ClientIPProvenanceDirect ClientIPProvenance = "direct"
	// ClientIPProvenancePlatform means a detected platform supplied the address.
	ClientIPProvenancePlatform ClientIPProvenance = "platform"
	// ClientIPProvenanceTrustedProxy means a configured proxy supplied the address.
	ClientIPProvenanceTrustedProxy ClientIPProvenance = "trusted-proxy"
	// ClientIPProvenanceUnverifiedHeader means an untrusted forwarding header supplied the address.
	ClientIPProvenanceUnverifiedHeader ClientIPProvenance = "unverified-header"
	// ClientIPProvenanceManual means WithIPSrc supplied the address.
	ClientIPProvenanceManual ClientIPProvenance = "manual"
	// ClientIPProvenanceRequest means ProtectDetails.IP supplied the address.
	ClientIPProvenanceRequest ClientIPProvenance = "request"
	// ClientIPProvenanceNone means no usable address was found.
	ClientIPProvenanceNone ClientIPProvenance = "none"
)

// ClientIPDetails explains how Arcjet selected the client IP for a request.
type ClientIPDetails struct {
	// IP is the normalized IPv4 or IPv6 address, or empty when none was found.
	IP string
	// Provenance identifies the source used to obtain IP.
	Provenance ClientIPProvenance
	// Verified reports whether the source was directly observed or explicitly trusted.
	Verified bool
	// Header is the lower-case header name used to obtain IP, or empty otherwise.
	Header string
}

// ProtectOptions contains per-request inputs used by specific rules.
//
// Most callers set these with ProtectOption helpers such as WithRequested and
// WithEmail.
type ProtectOptions struct {
	// Requested is the token or request cost consumed by this request.
	Requested int
	// Characteristics are per-request rate-limit characteristic values.
	Characteristics map[string]string
	// DetectPromptInjectionMessage is text scanned by prompt injection detection.
	DetectPromptInjectionMessage string
	// SensitiveInfoValue is text scanned by sensitive information detection.
	SensitiveInfoValue string
	// Email is the email address scanned by ValidateEmail.
	Email string
	// IPSrc overrides the request source IP. Prefer WithIPSrc, which also marks
	// the value as explicitly supplied and validates it during Protect.
	IPSrc    string
	ipSrcSet bool
	// FilterLocal contains local-only fields for Filter expressions.
	FilterLocal map[string]string
	// Extra contains additional string fields sent to Arcjet.
	Extra map[string]string
	// Body overrides the request body sent to Arcjet.
	Body []byte
	// CorrelationId is an optional, caller-supplied opaque identifier used to
	// correlate this request with other Protect and Guard calls in the same
	// workflow or agent run. It does not affect the decision and is excluded
	// from the decision cache key.
	CorrelationId string
	// Metadata is optional structured metadata for correlation and analytics:
	// string keys mapped to any JSON-serializable value, including nested maps
	// and slices. Each top-level value is JSON-encoded by the SDK and stored
	// verbatim.
	//
	// Server-enforced limits: 128 top-level keys, 4 KiB per serialized value, 10
	// levels of nesting, and key names limited to letters, digits, dash, dot,
	// and underscore. Anything over a limit drops that one key. Nothing here can
	// fail the call or change the decision — metadata is excluded from
	// fingerprinting and from the decision cache key.
	//
	// Prefer this over Extra, which stays a flat string map of SDK-derived
	// request context.
	Metadata Metadata
}

// ProtectOption configures a single Client.Protect or Client.ProtectDetails call.
type ProtectOption func(*ProtectOptions)

// WithRequested sets the token or request cost consumed by this request.
func WithRequested(n int) ProtectOption {
	return func(o *ProtectOptions) { o.Requested = n }
}

// WithCharacteristics sets values for rate-limit characteristics declared by rules.
func WithCharacteristics(values map[string]string) ProtectOption {
	return func(o *ProtectOptions) { o.Characteristics = cloneMap(values) }
}

// WithCharacteristic sets a single rate-limit characteristic value. It merges
// with any prior WithCharacteristic or WithCharacteristics call.
func WithCharacteristic(key, value string) ProtectOption {
	return func(o *ProtectOptions) {
		if o.Characteristics == nil {
			o.Characteristics = make(map[string]string)
		}
		o.Characteristics[key] = value
	}
}

// WithDetectPromptInjectionMessage sets the text scanned by prompt injection detection.
func WithDetectPromptInjectionMessage(s string) ProtectOption {
	return func(o *ProtectOptions) { o.DetectPromptInjectionMessage = s }
}

// WithSensitiveInfoValue sets the text scanned by sensitive information
// detection. Pair with [SensitiveInfo]; the value is evaluated locally and
// never leaves the SDK.
func WithSensitiveInfoValue(s string) ProtectOption {
	return func(o *ProtectOptions) { o.SensitiveInfoValue = s }
}

// WithEmail sets the email address scanned by email validation.
func WithEmail(email string) ProtectOption {
	return func(o *ProtectOptions) { o.Email = email }
}

// WithIPSrc overrides the request source IP sent to Arcjet.
//
// Use this only after your application or framework has authenticated the
// source of the address. Protect rejects empty or malformed values with
// ErrInvalidIP and normalizes valid IPv4 and IPv6 addresses.
//
// Example:
//
//	decision, err := client.Protect(ctx, request,
//		arcjet.WithIPSrc(request.Context().Value(clientIPKey).(string)),
//	)
func WithIPSrc(ip string) ProtectOption {
	return func(o *ProtectOptions) {
		o.IPSrc = ip
		o.ipSrcSet = true
	}
}

// WithFilterLocal sets local-only values available to Filter expressions.
//
// Values are evaluated by local WebAssembly and are not sent to Arcjet Cloud.
func WithFilterLocal(fields map[string]string) ProtectOption {
	return func(o *ProtectOptions) { o.FilterLocal = cloneMap(fields) }
}

// WithBody overrides the request body sent to Arcjet.
func WithBody(body []byte) ProtectOption {
	return func(o *ProtectOptions) { o.Body = append([]byte(nil), body...) }
}

// WithExtra sets additional string fields sent to Arcjet with the request.
func WithExtra(extra map[string]string) ProtectOption {
	return func(o *ProtectOptions) { o.Extra = cloneMap(extra) }
}

// WithCorrelationId sets an optional, caller-supplied opaque identifier used to
// correlate this request with other Protect and Guard calls in the same
// workflow or agent run. It does not affect the decision and is excluded from
// the decision cache key.
func WithCorrelationId(id string) ProtectOption {
	return func(o *ProtectOptions) { o.CorrelationId = id }
}

// WithMetadata sets structured metadata for correlation and analytics: string
// keys mapped to any JSON-serializable value, including nested maps and slices.
// It does not affect the decision and is excluded from the decision cache key.
// See ProtectOptions.Metadata for the limits.
func WithMetadata(metadata Metadata) ProtectOption {
	return func(o *ProtectOptions) { o.Metadata = maps.Clone(metadata) }
}

// Protect evaluates an HTTP request with the client's configured rules.
func (c *Client) Protect(ctx context.Context, r *http.Request, opts ...ProtectOption) (Decision, error) {
	if r == nil {
		return Decision{}, fmt.Errorf("arcjet: %w", ErrNilRequest)
	}
	details := detailsFromRequest(r, c.proxies, c.platform)
	return c.ProtectDetails(ctx, details, opts...)
}

// ProtectDetails evaluates explicit request details with the client's rules.
func (c *Client) ProtectDetails(ctx context.Context, details ProtectDetails, opts ...ProtectOption) (Decision, error) {
	if c == nil {
		return Decision{}, fmt.Errorf("arcjet: %w", ErrNilClient)
	}
	// Protect delegates here, so Protect(context.Background(), r) gets the
	// same fallback deadline as ProtectDetails.
	ctx, cancel := withDefaultDeadline(ctx, protectTimeout(c.rules))
	defer cancel()
	options := ProtectOptions{}
	for _, opt := range opts {
		opt(&options)
	}
	if options.Body != nil {
		details.Body = append([]byte(nil), options.Body...)
	}
	if options.Email != "" {
		details.Email = options.Email
	}
	ipDetails := details.clientIPDetails
	if ipDetails == nil {
		ipDetails = &ClientIPDetails{IP: details.IP, Provenance: ClientIPProvenanceRequest, Verified: true}
	}
	if options.ipSrcSet {
		ip := net.ParseIP(strings.TrimSpace(options.IPSrc))
		if ip == nil {
			return Decision{}, fmt.Errorf("arcjet: %w: %q", ErrInvalidIP, options.IPSrc)
		}
		details.IP = ip.String()
		ipDetails = &ClientIPDetails{IP: details.IP, Provenance: ClientIPProvenanceManual, Verified: true}
	}
	c.reportClientIP(*ipDetails)
	if options.CorrelationId != "" {
		details.CorrelationId = options.CorrelationId
	}
	if details.Extra == nil {
		details.Extra = make(map[string]string)
	}
	maps.Copy(details.Extra, options.Extra)
	if options.Requested > 0 {
		details.Extra["requested"] = strconv.Itoa(options.Requested)
	}
	maps.Copy(details.Extra, options.Characteristics)
	if options.DetectPromptInjectionMessage != "" {
		details.Extra["detectPromptInjectionMessage"] = options.DetectPromptInjectionMessage
	}
	// options.SensitiveInfoValue is intentionally not forwarded: the
	// sensitive-info rule runs locally in the SDK (see evaluateLocal ->
	// detectSensitiveInfo), so the raw value never needs to reach Decide or
	// Report and is kept in-process for privacy. See WithSensitiveInfoValue.

	rules := c.builtRules

	// fingerprints[i] is rule i's cache-key namespace, derived from the
	// rule's fingerprint characteristics via the same WASM export arcjet-js
	// uses, so identical inputs produce identical bytes. Most rules share
	// the client-level characteristics (one fingerprint), while a rate-limit
	// rule with its own characteristics gets its own — matching JS, which
	// recomputes the fingerprint per rate-limit rule. A WASM failure leaves
	// an entry empty, which silently skips caching for that rule rather than
	// failing the request. Skip the WASM round-trip entirely when the client
	// has no rules — there's nothing to look up or cache.
	var fingerprints []string
	if len(c.rules) > 0 {
		fingerprints = c.ruleFingerprints(ctx, details)
	}

	// Metadata is JSON-encoded once and attached to every request this call may
	// send (Decide, or a Report on a local deny). Keys the SDK could not encode
	// are reported to the server as untrusted local_warnings and surfaced on the
	// decision, so a dropped key is never silent.
	metadataJSON, warnings := encodeMetadata(options.Metadata, "")
	// Trim to the SDK ceiling so an oversized blob cannot push the request past
	// the 1 MiB protocol limit and get it rejected — a rejected request is a fail
	// open.
	warnings = append(warnings, enforceMetadataBudget([]map[string]string{metadataJSON})...)
	localWarnings := warningsToProtoV1(warnings)

	if local := c.evaluateLocal(ctx, details, options, fingerprints); local.liveDeny() {
		c.reportLocal(ctx, details, rules, local.decision, metadataJSON, localWarnings)
		return withProtectWarnings(decisionFromProto(local.decision), warnings), nil
	}

	// c.characteristics is set once during NewClient / WithRule and never
	// mutated; the proto only reads from the slice during serialization,
	// so sharing the backing array is safe.
	req := connect.NewRequest(&decidev1.DecideRequest{
		SdkStack:        decidev1.SDKStack_SDK_STACK_GO,
		SdkVersion:      c.sdkVersion,
		Details:         details.toProto(),
		Rules:           rules,
		Characteristics: c.characteristics,
		MetadataJson:    metadataJSON,
		LocalWarnings:   localWarnings,
	})
	req.Header().Set("Authorization", "Bearer "+c.key)
	req.Header().Set("User-Agent", c.userAgent)

	resp, err := c.decideClient.Decide(ctx, req)
	if err != nil {
		// Fail open: return a usable ERROR decision alongside the transport
		// error so IsAllowed()/IsErrored() are meaningful even if the caller
		// ignores err. Programmer errors (nil client, nil request) still
		// return the zero Decision.
		return withProtectWarnings(protectErrorDecision(err), warnings), err
	}
	c.cacheDecideResults(resp.Msg.GetDecision(), fingerprints)
	return withProtectWarnings(decisionFromProto(resp.Msg.GetDecision()), warnings), nil
}

// withProtectWarnings appends the SDK's own client-side warnings to a decision.
//
// Protect has no server-side warning channel, so this is how a dropped metadata
// key reaches the caller. arcjet-js and arcjet-py log instead; the Go SDK takes
// no logger, so the decision carries them.
func withProtectWarnings(d Decision, warnings []Warning) Decision {
	if len(warnings) == 0 {
		return d
	}
	d.Warnings = append(d.Warnings, warnings...)
	return d
}

// warningsToProtoV1 converts SDK warnings into the v1alpha1 proto Warning
// messages carried by DecideRequest.local_warnings and ReportRequest.local_warnings.
func warningsToProtoV1(warnings []Warning) []*decidev1.Warning {
	if len(warnings) == 0 {
		return nil
	}
	out := make([]*decidev1.Warning, 0, len(warnings))
	for _, w := range warnings {
		out = append(out, &decidev1.Warning{Code: w.Code, Message: w.Message})
	}
	return out
}

// ruleFingerprints computes one cache fingerprint per rule, indexed to align
// with c.rules / c.ruleIDs / c.fpChars. Rules sharing the same characteristics
// (the common case — everything but rate-limit rules with their own) share a
// single WASM round-trip via the per-call memo.
func (c *Client) ruleFingerprints(ctx context.Context, details ProtectDetails) []string {
	out := make([]string, len(c.rules))
	memo := make(map[string]string, 2)
	for i := range c.rules {
		chars := c.fpChars[i]
		key := strings.Join(chars, "\x00")
		fp, ok := memo[key]
		if !ok {
			fp, _ = c.local.fingerprint(ctx, details, chars)
			memo[key] = fp
		}
		out[i] = fp
	}
	return out
}

// evaluateLocal runs each configured rule, consulting and populating the
// per-rule cache around each call. Returns the first live DENY (cached or
// fresh) so the caller can skip the Decide RPC and report just that
// result, matching arcjet-js's protect() flow.
func (c *Client) evaluateLocal(ctx context.Context, details ProtectDetails, options ProtectOptions, fingerprints []string) *localDecision {
	if c.local == nil {
		return nil
	}
	for i, rule := range c.rules {
		id := c.ruleIDs[i]
		fingerprint := fingerprints[i]
		if cached := c.cache.get(id, fingerprint); cached != nil {
			// Cache only stores live DENY results, so a hit is always a
			// live DENY — return it directly without running the rule.
			return decisionFromRuleResult(cached)
		}
		decision, err := rule.evaluateLocal(ctx, details, options, c.local)
		if err != nil {
			continue
		}
		if decision == nil {
			continue
		}
		// Cache the rule's RuleResult on the way out. cache.set is a no-op
		// for non-cacheable results (DRY_RUN, ALLOW, TTL=0), so calling it
		// unconditionally keeps the per-rule logic simple.
		if results := decision.decision.GetRuleResults(); len(results) > 0 {
			c.cache.set(id, fingerprint, results[0])
		}
		if decision.liveDeny() {
			return decision
		}
	}
	return nil
}

// cacheDecideResults stores rule results returned by the Decide RPC back
// into the per-rule cache. The response's RuleResults are position-aligned
// with the rules sent to Decide (c.builtRules, no-ops dropped), so each
// result is mapped through c.builtRuleIndices back to its originating rule's
// ruleID and fingerprint. Mirrors arcjet-js's intent of letting future calls
// short-circuit on a cached server DENY without another network round-trip —
// but with the granularity JS uses for its local-rule cache.
func (c *Client) cacheDecideResults(decision *decidev1.Decision, fingerprints []string) {
	if c.cache == nil || decision == nil {
		return
	}
	results := decision.GetRuleResults()
	for j, result := range results {
		if j >= len(c.builtRuleIndices) {
			// More results than rules we sent — can't attribute the extras
			// to a rule, so leave them uncached rather than guess.
			break
		}
		idx := c.builtRuleIndices[j]
		c.cache.set(c.ruleIDs[idx], fingerprints[idx], result)
	}
}

func (c *Client) reportLocal(
	ctx context.Context,
	details ProtectDetails,
	rules []*decidev1.Rule,
	decision *decidev1.Decision,
	metadataJSON map[string]string,
	localWarnings []*decidev1.Warning,
) {
	if decision == nil {
		return
	}
	reportDetails := redactReportDetails(details)
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportTimeout)
	go func() {
		defer cancel()
		req := connect.NewRequest(&decidev1.ReportRequest{
			SdkStack:        decidev1.SDKStack_SDK_STACK_GO,
			SdkVersion:      c.sdkVersion,
			Details:         reportDetails.toProto(),
			Decision:        decision,
			Rules:           rules,
			Characteristics: c.characteristics,
			MetadataJson:    metadataJSON,
			LocalWarnings:   localWarnings,
		})
		req.Header().Set("Authorization", "Bearer "+c.key)
		req.Header().Set("User-Agent", c.userAgent)
		//nolint:errcheck // Report is best-effort telemetry; a failed report
		// must not change the decision returned to the caller.
		_, _ = c.decideClient.Report(reportCtx, req)
	}()
}

// redactReportDetails returns a copy of details with the prompt-injection input
// (and, defensively, any sensitive-info value) replaced with "<redacted>". The
// raw prompt-injection text is needed by the Decide RPC for server-side
// inference, but Report is dashboard telemetry and must not leak it. The
// sensitive-info value is evaluated locally and never placed in Extra today, so
// its branch is a guard against a future code path forwarding it under this
// key. Mirrors https://github.com/arcjet/arcjet-py/pull/118.
func redactReportDetails(d ProtectDetails) ProtectDetails {
	if d.Extra == nil {
		return d
	}
	const redacted = "<redacted>"
	_, hasPI := d.Extra["detectPromptInjectionMessage"]
	_, hasSI := d.Extra["sensitiveInfoValue"]
	if !hasPI && !hasSI {
		return d
	}
	out := d
	out.Extra = maps.Clone(d.Extra)
	if hasPI {
		out.Extra["detectPromptInjectionMessage"] = redacted
	}
	if hasSI {
		out.Extra["sensitiveInfoValue"] = redacted
	}
	return out
}

// buildRequestRules converts each rule to its wire form, dropping no-ops.
// Alongside the built rules it returns indices[j] = the position of rule j's
// source in the input slice, so a caller can map the Decide response's
// position-aligned RuleResults back to the originating rule despite the gaps
// left by dropped no-ops.
func buildRequestRules(rules []Rule) ([]*decidev1.Rule, []int, error) {
	out := make([]*decidev1.Rule, 0, len(rules))
	indices := make([]int, 0, len(rules))
	for i, rule := range rules {
		built, err := buildRequestRule(rule)
		if err != nil {
			return nil, nil, err
		}
		if built == nil {
			// Rule is a no-op (e.g. an analyzer that isn't shipped yet).
			// Skip — nothing to send to Decide.
			continue
		}
		out = append(out, built)
		indices = append(indices, i)
	}
	return out, indices, nil
}

// buildRequestRule converts one Rule to its proto representation. Returns
// (nil, nil) when the Rule is a no-op — its requestRule() returned a nil
// map. Callers must skip the result.
func buildRequestRule(rule Rule) (*decidev1.Rule, error) {
	if rule == nil {
		return nil, fmt.Errorf("arcjet: %w", ErrNilRule)
	}
	wire, err := rule.requestRule()
	if err != nil {
		return nil, err
	}
	if wire == nil {
		return nil, nil
	}
	data, err := jsonMarshal(wire)
	if err != nil {
		return nil, err
	}
	var protoRule decidev1.Rule
	if err := protojson.Unmarshal(data, &protoRule); err != nil {
		return nil, fmt.Errorf("arcjet: encode rule: %w", err)
	}
	return &protoRule, nil
}

// DetailsFromRequest extracts Arcjet request details from an HTTP request.
//
// It uses Request.RemoteAddr when it contains a public source IP. Otherwise it
// may fall back to a public address from a common forwarding header; because no
// Client configuration is available, that fallback is unverified. Use
// Client.ClientIPDetails or Client.Protect to apply Config.Proxies and managed
// platform detection.
func DetailsFromRequest(r *http.Request) ProtectDetails {
	return detailsFromRequest(r, nil, platformNone)
}

func detailsFromRequest(r *http.Request, proxies []trustedProxy, platform hostingPlatform) ProtectDetails {
	headers := make(map[string]string, len(r.Header))
	for k, values := range r.Header {
		headers[strings.ToLower(k)] = strings.Join(values, ", ")
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	ipDetails := clientIPDetails(r, proxies, platform)
	return ProtectDetails{
		IP:              ipDetails.IP,
		Method:          r.Method,
		Protocol:        r.Proto,
		Host:            host,
		Path:            r.URL.Path,
		Headers:         headers,
		Cookies:         r.Header.Get("Cookie"),
		Query:           r.URL.RawQuery,
		Extra:           map[string]string{},
		clientIPDetails: &ipDetails,
	}
}

type trustedProxy struct {
	ip      net.IP
	network *net.IPNet
}

func parseTrustedProxies(values []string) ([]trustedProxy, error) {
	if len(values) == 0 {
		return nil, nil
	}
	proxies := make([]trustedProxy, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("arcjet: %w: empty value", ErrInvalidProxy)
		}
		if ip, network, err := net.ParseCIDR(value); err == nil {
			network.IP = ip
			proxies = append(proxies, trustedProxy{network: network})
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("arcjet: %w: %q", ErrInvalidProxy, value)
		}
		proxies = append(proxies, trustedProxy{ip: ip})
	}
	return proxies, nil
}

func hasTrustAllProxy(proxies []trustedProxy) bool {
	for _, proxy := range proxies {
		if proxy.network == nil {
			continue
		}
		ones, _ := proxy.network.Mask.Size()
		if ones == 0 {
			return true
		}
	}
	return false
}

// clientIP returns the request's source IP.
//
// When a hosting platform is detected, its signed headers are trusted directly
// (e.g. Fly-Client-Ip on Fly.io, X-Real-IP on Vercel/Railway). The platform's
// edge is the only ingress, so its headers are the authoritative source and
// take precedence over any RemoteAddr/X-Forwarded-For walk.
//
// Otherwise, when the direct peer (RemoteAddr) is a configured trusted proxy,
// the X-Forwarded-For header is walked right-to-left and the first entry that
// is itself not a trusted proxy is returned. This matches @arcjet/ip's findIp
// behavior — the rightmost untrusted entry is the closest hop our proxies
// observed and is the hardest for the user to spoof. Walking left-to-right
// instead would trust whatever the original client wrote in.
//
// If RemoteAddr is a public address and is not a trusted proxy, it wins over
// forwarding headers. If RemoteAddr is missing or non-public, common forwarding
// headers are used as a best-effort fallback and marked unverified.
func clientIP(r *http.Request, proxies []trustedProxy, platform hostingPlatform) string {
	return clientIPDetails(r, proxies, platform).IP
}

func clientIPDetails(r *http.Request, proxies []trustedProxy, platform hostingPlatform) ClientIPDetails {
	if platform != platformNone {
		if details := platformIPDetails(r, platform, proxies); details.IP != "" {
			return details
		}
		ip := remoteIP(r.RemoteAddr)
		if ip == "" {
			return ClientIPDetails{Provenance: ClientIPProvenanceNone}
		}
		return ClientIPDetails{IP: ip, Provenance: ClientIPProvenanceDirect, Verified: true}
	}
	remote := remoteIP(r.RemoteAddr)
	if isTrustedProxy(remote, proxies) {
		if ip := rightmostUntrustedXFF(r.Header.Get("X-Forwarded-For"), proxies); ip != "" {
			return ClientIPDetails{
				IP:         ip,
				Provenance: ClientIPProvenanceTrustedProxy,
				Verified:   true,
				Header:     "x-forwarded-for",
			}
		}
		return ClientIPDetails{IP: remote, Provenance: ClientIPProvenanceDirect, Verified: true}
	}
	if isPublicIP(remote) {
		return ClientIPDetails{IP: remote, Provenance: ClientIPProvenanceDirect, Verified: true}
	}
	if ip, header := unverifiedHeaderIP(r.Header); ip != "" {
		return ClientIPDetails{
			IP:         ip,
			Provenance: ClientIPProvenanceUnverifiedHeader,
			Verified:   false,
			Header:     header,
		}
	}
	if remote != "" {
		return ClientIPDetails{IP: remote, Provenance: ClientIPProvenanceDirect, Verified: true}
	}
	return ClientIPDetails{Provenance: ClientIPProvenanceNone}
}

var fallbackClientIPHeaders = [...]string{
	"x-client-ip",
	"do-connecting-ip",
	"fastly-client-ip",
	"true-client-ip",
	"x-real-ip",
	"x-cluster-client-ip",
	"x-forwarded",
	"forwarded-for",
	"forwarded",
	"x-appengine-user-ip",
}

func unverifiedHeaderIP(headers http.Header) (string, string) {
	if ip := rightmostPublicIP(headers.Get("X-Forwarded-For")); ip != "" {
		return ip, "x-forwarded-for"
	}
	for _, header := range fallbackClientIPHeaders {
		if ip := firstPublicIP(headers.Get(header)); ip != "" {
			return ip, header
		}
	}
	return "", ""
}

func rightmostPublicIP(value string) string {
	for _, part := range slices.Backward(strings.Split(value, ",")) {
		if ip := firstPublicIP(part); ip != "" {
			return ip
		}
	}
	return ""
}

func firstPublicIP(value string) string {
	for _, field := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '=' || r == ' ' || r == '\t'
	}) {
		candidate := strings.Trim(strings.TrimSpace(field), "\"")
		if strings.HasPrefix(candidate, "[") && strings.HasSuffix(candidate, "]") {
			candidate = strings.TrimSuffix(strings.TrimPrefix(candidate, "["), "]")
		}
		if ip := remoteIP(candidate); isPublicIP(ip) {
			return ip
		}
	}
	return ""
}

func isPublicIP(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func isTrustedProxy(value string, proxies []trustedProxy) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	for _, proxy := range proxies {
		if proxy.network != nil && proxy.network.Contains(ip) {
			return true
		}
		if proxy.ip != nil && proxy.ip.Equal(ip) {
			return true
		}
	}
	return false
}

func remoteIP(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		addr = host
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// ClientIPDetails explains how this client would resolve the request IP.
//
// It is side-effect-free: it does not protect the request, emit debug logs, or
// consume the once-per-Client unverified-header warning. Inspect Provenance,
// Verified, and Header when diagnosing proxy configuration.
//
// Example:
//
//	details := client.ClientIPDetails(request)
//	slog.Info("Arcjet client IP", "ip", details.IP,
//		"provenance", details.Provenance, "verified", details.Verified)
func (c *Client) ClientIPDetails(r *http.Request) ClientIPDetails {
	if c == nil || r == nil {
		return ClientIPDetails{Provenance: ClientIPProvenanceNone}
	}
	return clientIPDetails(r, c.proxies, c.platform)
}

func (c *Client) reportClientIP(details ClientIPDetails) {
	if c.log != nil {
		c.log.Debug(
			"Arcjet client IP resolved",
			"client_ip_provenance", details.Provenance,
			"client_ip_verified", details.Verified,
			"client_ip_header", details.Header,
		)
	}
	if details.Provenance != ClientIPProvenanceUnverifiedHeader || c.ipWarning == nil {
		return
	}
	c.ipWarning.once.Do(func() {
		c.log.Warn(
			"Arcjet resolved the client IP from an unverified forwarding header; ensure a trusted proxy overwrites or safely appends forwarding headers, configure Proxies, or pass a validated WithIPSrc value",
			"client_ip_provenance", details.Provenance,
			"client_ip_header", details.Header,
		)
	})
}

func (d ProtectDetails) toProto() *decidev1.RequestDetails {
	return &decidev1.RequestDetails{
		Ip:       d.IP,
		Method:   d.Method,
		Protocol: d.Protocol,
		Host:     d.Host,
		Path:     d.Path,
		Headers:  cloneMap(d.Headers),
		Body:     append([]byte(nil), d.Body...),
		Extra:    cloneMap(d.Extra),
		Email:    d.Email,
		Cookies:  d.Cookies,
		Query:    queryWithQuestion(d.Query),
		// Not a fingerprint characteristic, so it never enters the per-rule
		// cache key (ruleID, fingerprint); see ruleFingerprints.
		CorrelationId: d.CorrelationId,
	}
}

func queryWithQuestion(q string) string {
	if q == "" || strings.HasPrefix(q, "?") {
		return q
	}
	return "?" + q
}

// withDefaultDeadline returns ctx unchanged when it already has a deadline.
// Otherwise it derives a child with timeout. The cancel func is always safe
// to defer (a no-op when the original context is reused).
func withDefaultDeadline(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// protectTimeout returns the SDK default Protect deadline, matching the
// JavaScript and Python SDK base (2s) with the JS adjustments: ×2 when an
// email rule is present, floored at 1s when a prompt-injection rule is
// present. With a 2s base the PI floor is already met; email+PI is 4s
// (email doubling), not 2s.
func protectTimeout(rules []Rule) time.Duration {
	timeout := defaultProtectTimeout
	hasEmail := false
	hasPromptInjection := false
	for _, r := range rules {
		if r == nil {
			continue
		}
		switch r.localKind() {
		case localKindEmail:
			hasEmail = true
		case localKindPromptInjection:
			hasPromptInjection = true
		default:
		}
	}
	if hasEmail {
		timeout *= 2
	}
	if hasPromptInjection && timeout < time.Second {
		timeout = time.Second
	}
	return timeout
}

// protectErrorDecision synthesizes a fail-open ERROR decision for a
// transport failure. Conclusion is ERROR so IsErrored() is true; IsAllowed()
// treats ERROR as allowed, matching ArcjetErrorDecision in arcjet-js.
//
// Results contains one synthesized ERROR entry, not one per configured rule:
// no rules ran, so there are no rule IDs to attach. Callers correlating
// per-rule outcomes should treat a transport-failure decision as having no
// per-rule results.
func protectErrorDecision(err error) Decision {
	msg := "decide request failed"
	if err != nil {
		msg = err.Error()
	}
	reason := Reason{Type: ReasonError, Message: msg}
	return Decision{
		Conclusion: ConclusionError,
		Reason:     reason,
		Results: []RuleResult{{
			State:      RuleStateRun,
			Conclusion: ConclusionError,
			Reason:     reason,
		}},
	}
}

func defaultBaseURL(configured string) string {
	if configured != "" {
		return strings.TrimRight(configured, "/")
	}
	if os.Getenv("FLY_APP_NAME") != "" || os.Getenv("FLY_REGION") != "" {
		return defaultFlyDecideURL
	}
	if env := os.Getenv("ARCJET_BASE_URL"); env != "" {
		return strings.TrimRight(env, "/")
	}
	return defaultDecideURL
}

func userAgent(product, version string) string {
	return fmt.Sprintf("%s/%s (Go %s; %s %s)", product, version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	return maps.Clone(in)
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
