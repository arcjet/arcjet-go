package arcjet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1/decidev1alpha1connect"
)

// reportTimeout bounds the background Report RPC issued after a local or
// cached decision so a slow Arcjet endpoint cannot pile up goroutines.
const reportTimeout = 5 * time.Second

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
	// Proxies are trusted proxy IPs or CIDRs used to trust X-Forwarded-For.
	Proxies []string
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
type Client struct {
	key             string
	rules           []Rule
	builtRules      []*decidev1.Rule
	characteristics []string
	decideClient    decidev1alpha1connect.DecideServiceClient
	sdkVersion      string
	userAgent       string
	proxies         []trustedProxy
	platform        hostingPlatform
	local           *localEvaluator
	cache           *decisionCache
	rulesHash       string
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
	platform := detectPlatform(os.Getenv)
	if cfg.Platform != "" {
		p, ok := cfg.Platform.toHostingPlatform()
		if !ok {
			return nil, fmt.Errorf("arcjet: %w: %q", ErrInvalidPlatform, cfg.Platform)
		}
		platform = p
	}
	builtRules, err := buildRequestRules(cfg.Rules)
	if err != nil {
		return nil, err
	}
	rulesHash, err := hashRules(builtRules)
	if err != nil {
		return nil, err
	}
	local, err := newLocalEvaluator(context.Background(), cfg.Rules, cfg.SensitiveInfoDetect)
	if err != nil {
		return nil, err
	}
	return &Client{
		key:             key,
		rules:           append([]Rule(nil), cfg.Rules...),
		builtRules:      builtRules,
		characteristics: append([]string(nil), cfg.Characteristics...),
		sdkVersion:      version,
		userAgent:       ua,
		proxies:         proxies,
		platform:        platform,
		decideClient:    decidev1alpha1connect.NewDecideServiceClient(httpClient, baseURL),
		local:           local,
		cache:           newDecisionCache(),
		rulesHash:       rulesHash,
	}, nil
}

// WithRule returns a copy of the client with an additional route-specific rule.
//
// The new rule is validated and converted to its wire form once; subsequent
// Protect calls reuse the cached representation.
func (c *Client) WithRule(rule Rule) (*Client, error) {
	if rule == nil {
		return nil, fmt.Errorf("arcjet: %w", ErrNilRule)
	}
	wireRule, err := buildRequestRule(rule)
	if err != nil {
		return nil, err
	}
	next := *c
	next.rules = append(append([]Rule(nil), c.rules...), rule)
	next.builtRules = append([]*decidev1.Rule(nil), c.builtRules...)
	if wireRule != nil {
		next.builtRules = append(next.builtRules, wireRule)
	}
	next.characteristics = append([]string(nil), c.characteristics...)
	rulesHash, err := hashRules(next.builtRules)
	if err != nil {
		return nil, err
	}
	next.rulesHash = rulesHash
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
	// IPSrc overrides the request source IP.
	IPSrc string
	// FilterLocal contains local-only fields for Filter expressions.
	FilterLocal map[string]string
	// Extra contains additional string fields sent to Arcjet.
	Extra map[string]string
	// Body overrides the request body sent to Arcjet.
	Body []byte
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
func WithIPSrc(ip string) ProtectOption {
	return func(o *ProtectOptions) { o.IPSrc = ip }
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
	if options.IPSrc != "" {
		details.IP = options.IPSrc
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
	cacheKey := makeDecisionCacheKey(details, c.rulesHash, options)
	if cached := c.cache.get(cacheKey); cached != nil {
		c.reportLocal(ctx, details, rules, cached)
		return decisionFromProto(cached), nil
	}
	if local := c.evaluateLocal(ctx, details, options); local.liveDeny() {
		c.reportLocal(ctx, details, rules, local.decision)
		c.cache.set(cacheKey, local.decision)
		return decisionFromProto(local.decision), nil
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
	})
	req.Header().Set("Authorization", "Bearer "+c.key)
	req.Header().Set("User-Agent", c.userAgent)

	resp, err := c.decideClient.Decide(ctx, req)
	if err != nil {
		return Decision{}, err
	}
	c.cache.set(cacheKey, resp.Msg.GetDecision())
	return decisionFromProto(resp.Msg.GetDecision()), nil
}

func (c *Client) evaluateLocal(ctx context.Context, details ProtectDetails, options ProtectOptions) *localDecision {
	if c.local == nil {
		return nil
	}
	for _, rule := range c.rules {
		decision, err := rule.evaluateLocal(ctx, details, options, c.local)
		if err != nil {
			continue
		}
		if decision.liveDeny() {
			return decision
		}
	}
	return nil
}

func (c *Client) reportLocal(ctx context.Context, details ProtectDetails, rules []*decidev1.Rule, decision *decidev1.Decision) {
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

func buildRequestRules(rules []Rule) ([]*decidev1.Rule, error) {
	out := make([]*decidev1.Rule, 0, len(rules))
	for _, rule := range rules {
		built, err := buildRequestRule(rule)
		if err != nil {
			return nil, err
		}
		if built == nil {
			// Rule is a no-op (e.g. an analyzer that isn't shipped yet).
			// Skip — nothing to send to Decide.
			continue
		}
		out = append(out, built)
	}
	return out, nil
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
// It uses Request.RemoteAddr for the source IP. Configure Config.Proxies and use
// Client.Protect when Arcjet should trust X-Forwarded-For from known proxies,
// or when running on a supported hosting platform (Fly.io, Vercel, Render,
// Firebase, Railway) where Client.Protect reads the platform's signed headers.
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
	return ProtectDetails{
		IP:       clientIP(r, proxies, platform),
		Method:   r.Method,
		Protocol: r.Proto,
		Host:     host,
		Path:     r.URL.Path,
		Headers:  headers,
		Cookies:  r.Header.Get("Cookie"),
		Query:    r.URL.RawQuery,
		Extra:    map[string]string{},
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
			continue
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
// If RemoteAddr is not a trusted proxy, X-Forwarded-For is ignored entirely.
func clientIP(r *http.Request, proxies []trustedProxy, platform hostingPlatform) string {
	if platform != platformNone {
		if ip := platformIP(r, platform, proxies); ip != "" {
			return ip
		}
		return remoteIP(r.RemoteAddr)
	}
	remote := remoteIP(r.RemoteAddr)
	if len(proxies) == 0 || !isTrustedProxy(remote, proxies) {
		return remote
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remote
	}
	parts := strings.Split(xff, ",")
	for _, part := range slices.Backward(parts) {
		ip := strings.TrimSpace(part)
		if ip == "" {
			continue
		}
		if isTrustedProxy(ip, proxies) {
			continue
		}
		return ip
	}
	return remote
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
		return host
	}
	return addr
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
	}
}

func queryWithQuestion(q string) string {
	if q == "" || strings.HasPrefix(q, "?") {
		return q
	}
	return "?" + q
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

// hashRules returns a stable digest of the built rule set. The digest is
// only used as a cache key namespace, so canonicalisation across processes
// is not required — within a single process, identical rule sets must hash
// the same. proto.Marshal with Deterministic=true is sufficient and far
// cheaper than the previous protojson-via-json.RawMessage approach.
func hashRules(rules []*decidev1.Rule) (string, error) {
	if len(rules) == 0 {
		return "", nil
	}
	h := sha256.New()
	var lenBuf [4]byte
	opts := proto.MarshalOptions{Deterministic: true}
	for _, rule := range rules {
		data, err := opts.Marshal(rule)
		if err != nil {
			return "", err
		}
		binary.BigEndian.PutUint32(lenBuf[:], safeUint32(len(data)))
		h.Write(lenBuf[:])
		h.Write(data)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	var buf [sha256.Size * 2]byte
	hex.Encode(buf[:], sum[:])
	return string(buf[:]), nil
}
