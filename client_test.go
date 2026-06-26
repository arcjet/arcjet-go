package arcjet

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1/decidev1alpha1connect"
)

type testDecideHandler struct {
	mu       sync.Mutex
	reportCh chan struct{}

	seen         *decidev1.DecideRequest
	reportSeen   *decidev1.ReportRequest
	header       http.Header
	reportHeader http.Header
	decideCalls  int
	reportCalls  int
	decision     *decidev1.Decision
}

type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func (h *testDecideHandler) Decide(ctx context.Context, req *connect.Request[decidev1.DecideRequest]) (*connect.Response[decidev1.DecideResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.decideCalls++
	h.seen = req.Msg
	h.header = req.Header()
	if h.decision != nil {
		return connect.NewResponse(&decidev1.DecideResponse{Decision: h.decision}), nil
	}
	return connect.NewResponse(&decidev1.DecideResponse{
		Decision: &decidev1.Decision{
			Id:         "req_test",
			Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
			Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
				RateLimit: &decidev1.RateLimitReason{
					Max:             10,
					Remaining:       0,
					ResetInSeconds:  30,
					WindowInSeconds: 60,
				},
			}},
			RuleResults: []*decidev1.RuleResult{
				{
					RuleId:     "rule_test",
					State:      decidev1.RuleState_RULE_STATE_RUN,
					Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
					Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
						RateLimit: &decidev1.RateLimitReason{Max: 10},
					}},
				},
			},
			IpDetails: &decidev1.IpDetails{
				Latitude:       37.7749,
				Longitude:      -122.4194,
				AccuracyRadius: 50,
				Timezone:       "America/Los_Angeles",
				PostalCode:     "94105",
				City:           "San Francisco",
				Region:         "CA",
				Country:        "US",
				CountryName:    "United States",
				Continent:      "NA",
				ContinentName:  "North America",
				Asn:            "AS15169",
				AsnName:        "Google LLC",
				AsnDomain:      "google.com",
				AsnType:        "business",
				AsnCountry:     "US",
				Service:        "Google",
				IsHosting:      true,
				Bots:           map[string]string{"GOOGLE_CRAWLER": "Googlebot"},
			},
		},
	}), nil
}

func (h *testDecideHandler) Report(_ context.Context, req *connect.Request[decidev1.ReportRequest]) (*connect.Response[decidev1.ReportResponse], error) {
	h.mu.Lock()
	h.reportCalls++
	h.reportSeen = req.Msg
	h.reportHeader = req.Header()
	ch := h.reportCh
	h.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return connect.NewResponse(&decidev1.ReportResponse{}), nil
}

func (h *testDecideHandler) waitReport(t *testing.T) {
	t.Helper()
	if h.reportCh == nil {
		return
	}
	select {
	case <-h.reportCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for report")
	}
}

type handlerSnapshot struct {
	decideCalls  int
	reportCalls  int
	seen         *decidev1.DecideRequest
	reportSeen   *decidev1.ReportRequest
	header       http.Header
	reportHeader http.Header
}

func (h *testDecideHandler) snapshot() handlerSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return handlerSnapshot{
		decideCalls:  h.decideCalls,
		reportCalls:  h.reportCalls,
		seen:         h.seen,
		reportSeen:   h.reportSeen,
		header:       h.header,
		reportHeader: h.reportHeader,
	}
}

func mustCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func TestProtectUsesConnectAndBuildsRequest(t *testing.T) {
	handler := &testDecideHandler{}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	client, err := NewClient(Config{
		Key:             "ajkey_test",
		BaseURL:         "http://arcjet.test",
		HTTPClient:      &http.Client{Transport: handlerTransport{handler: mux}},
		Characteristics: []string{"userId"},
		Rules: []Rule{
			Shield(ShieldOptions{Mode: ModeLive}),
			TokenBucket(TokenBucketOptions{
				Mode:       ModeLive,
				RefillRate: 100,
				Interval:   time.Minute,
				Capacity:   500,
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/chat?debug=1", http.NoBody)
	req.RemoteAddr = "203.0.113.10:4567"
	req.Header.Set("User-Agent", "go-test")
	req.Header.Set("Cookie", "sid=abc")

	decision, err := client.Protect(
		context.Background(),
		req,
		WithRequested(42),
		WithCharacteristics(map[string]string{"userId": "user_123"}),
		WithDetectPromptInjectionMessage("hello"),
		WithCorrelationId("wf_abcdef"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsDenied() {
		t.Fatalf("expected denied decision, got %#v", decision)
	}
	if decision.Reason.Type != ReasonRateLimit {
		t.Fatalf("expected rate-limit reason, got %q", decision.Reason.Type)
	}
	if !decision.IP.IsHosting || decision.IP.Country != "US" {
		t.Fatalf("expected IP details to round-trip, got %#v", decision.IP)
	}
	if decision.IP.Latitude != 37.7749 || decision.IP.Region != "CA" || decision.IP.ASNDomain != "google.com" || decision.IP.Bots["GOOGLE_CRAWLER"] != "Googlebot" {
		t.Fatalf("expected full IP details to round-trip, got %#v", decision.IP)
	}

	seen := handler.seen
	if seen == nil {
		t.Fatal("handler did not see request")
	}
	if got := handler.header.Get("Authorization"); got != "Bearer ajkey_test" {
		t.Fatalf("authorization header = %q", got)
	}
	if seen.GetSdkVersion() != Version {
		t.Fatalf("sdk version = %q", seen.GetSdkVersion())
	}
	if seen.GetDetails().GetIp() != "203.0.113.10" {
		t.Fatalf("ip = %q", seen.GetDetails().GetIp())
	}
	if seen.GetDetails().GetQuery() != "?debug=1" {
		t.Fatalf("query = %q", seen.GetDetails().GetQuery())
	}
	if seen.GetDetails().GetCorrelationId() != "wf_abcdef" {
		t.Fatalf("correlation_id = %q", seen.GetDetails().GetCorrelationId())
	}
	if _, ok := seen.GetDetails().GetExtra()["correlationId"]; ok {
		t.Fatalf("correlation_id leaked into extra: %#v", seen.GetDetails().GetExtra())
	}
	if seen.GetDetails().GetExtra()["userId"] != "user_123" {
		t.Fatalf("missing userId extra: %#v", seen.GetDetails().GetExtra())
	}
	if seen.GetDetails().GetExtra()["requested"] != "42" {
		t.Fatalf("missing requested extra: %#v", seen.GetDetails().GetExtra())
	}
	if _, ok := seen.GetDetails().GetExtra()["plan"]; ok {
		t.Fatalf("filter-local field was sent remotely: %#v", seen.GetDetails().GetExtra())
	}
	if len(seen.GetRules()) != 2 {
		t.Fatalf("rule count = %d", len(seen.GetRules()))
	}
	if seen.GetRules()[1].GetRateLimit().GetAlgorithm() != decidev1.RateLimitAlgorithm_RATE_LIMIT_ALGORITHM_TOKEN_BUCKET {
		t.Fatalf("expected token bucket rule, got %#v", seen.GetRules()[1])
	}
}

func TestProtectUsesTrustedProxyAndIPOverride(t *testing.T) {
	handler := &testDecideHandler{}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Proxies:    []string{"10.0.0.0/8"},
		Rules: []Rule{
			TokenBucket(TokenBucketOptions{
				Mode:       ModeLive,
				RefillRate: 1,
				Interval:   time.Minute,
				Capacity:   10,
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.44, 10.1.2.3")

	if _, err := client.Protect(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := handler.seen.GetDetails().GetIp(); got != "198.51.100.44" {
		t.Fatalf("trusted proxy ip = %q", got)
	}

	if _, err := client.Protect(context.Background(), req, WithIPSrc("203.0.113.77")); err != nil {
		t.Fatal(err)
	}
	if got := handler.seen.GetDetails().GetIp(); got != "203.0.113.77" {
		t.Fatalf("ip override = %q", got)
	}
}

func TestProtectIgnoresForwardedForFromUntrustedProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.44")

	details := detailsFromRequest(req, []trustedProxy{{network: mustCIDR(t, "10.0.0.0/8")}}, platformNone)
	if details.IP != "203.0.113.10" {
		t.Fatalf("ip = %q", details.IP)
	}
}

func TestClientIPWalksXFFRightToLeftSkippingTrustedProxies(t *testing.T) {
	// Multi-hop chain: spoofed client header, real user, trusted edge, trusted LB.
	// Both 10.0.0.0/8 hops are trusted; the rightmost non-trusted is the user IP.
	proxies := []trustedProxy{{network: mustCIDR(t, "10.0.0.0/8")}}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.99.0.1:443"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.44, 10.0.0.5, 10.99.0.1")

	if got := clientIP(req, proxies, platformNone); got != "198.51.100.44" {
		t.Fatalf("expected rightmost non-trusted hop, got %q", got)
	}

	// All XFF entries are trusted — fall back to remote.
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 10.99.0.1")
	if got := clientIP(req, proxies, platformNone); got != "10.99.0.1" {
		t.Fatalf("all-trusted should fall back to remote, got %q", got)
	}

	// Empty XFF, trusted peer, no override — still remote.
	req.Header.Set("X-Forwarded-For", "")
	if got := clientIP(req, proxies, platformNone); got != "10.99.0.1" {
		t.Fatalf("empty XFF should fall back to remote, got %q", got)
	}
}

func TestNewClientRejectsInvalidProxy(t *testing.T) {
	_, err := NewClient(Config{Key: "ajkey_test", Proxies: []string{"not an ip"}})
	if !errors.Is(err, ErrInvalidProxy) {
		t.Fatalf("expected ErrInvalidProxy, got %v", err)
	}
}

func TestProtectReportsLocalEmailWasmDecision(t *testing.T) {
	handler := &testDecideHandler{reportCh: make(chan struct{}, 1)}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Rules: []Rule{
			ValidateEmail(EmailOptions{Mode: ModeLive, Deny: []EmailType{EmailTypeInvalid}}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	decision, err := client.ProtectDetails(context.Background(), ProtectDetails{Email: "invalid-email@//example-com"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsDenied() || decision.Reason.Type != ReasonEmail {
		t.Fatalf("expected local email deny, got %#v", decision)
	}
	handler.waitReport(t)
	snap := handler.snapshot()
	decideCalls, reportCalls, reportSeen, reportHeader := snap.decideCalls, snap.reportCalls, snap.reportSeen, snap.reportHeader
	if decideCalls != 0 || reportCalls != 1 {
		t.Fatalf("expected report-only path, decide=%d report=%d", decideCalls, reportCalls)
	}
	if got := reportHeader.Get("Authorization"); got != "Bearer ajkey_test" {
		t.Fatalf("report authorization header = %q", got)
	}
	if got := reportSeen.GetDecision().GetReason().GetEmail().GetEmailTypes()[0]; got != decidev1.EmailType_EMAIL_TYPE_INVALID {
		t.Fatalf("reported email type = %s", got)
	}
}

func TestProtectReportsLocalFilterWasmDecision(t *testing.T) {
	handler := &testDecideHandler{reportCh: make(chan struct{}, 1)}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Rules: []Rule{
			Filter(FilterOptions{Mode: ModeLive, Deny: []string{`http.host == "example.com"`}}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	decision, err := client.ProtectDetails(context.Background(), ProtectDetails{Host: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsDenied() || decision.Reason.Type != ReasonFilter {
		t.Fatalf("expected local filter deny, got %#v", decision)
	}
	handler.waitReport(t)
	snap := handler.snapshot()
	decideCalls, reportCalls, reportSeen := snap.decideCalls, snap.reportCalls, snap.reportSeen
	if decideCalls != 0 || reportCalls != 1 {
		t.Fatalf("expected report-only path, decide=%d report=%d", decideCalls, reportCalls)
	}
	matched := reportSeen.GetDecision().GetReason().GetFilter().GetMatchedExpressions()
	if len(matched) != 1 || matched[0] != `http.host == "example.com"` {
		t.Fatalf("reported matched filters = %#v", matched)
	}
}

func TestProtectReportsLocalBotWasmDecision(t *testing.T) {
	handler := &testDecideHandler{reportCh: make(chan struct{}, 1)}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Rules: []Rule{
			DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	decision, err := client.ProtectDetails(context.Background(), ProtectDetails{
		Headers: map[string]string{"user-agent": "curl/8.7.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsDenied() || decision.Reason.Type != ReasonBot {
		t.Fatalf("expected local bot deny, got %#v", decision)
	}
	handler.waitReport(t)
	snap := handler.snapshot()
	decideCalls, reportCalls, reportSeen := snap.decideCalls, snap.reportCalls, snap.reportSeen
	if decideCalls != 0 || reportCalls != 1 {
		t.Fatalf("expected report-only path, decide=%d report=%d", decideCalls, reportCalls)
	}
	denied := reportSeen.GetDecision().GetReason().GetBotV2().GetDenied()
	if len(denied) != 1 || denied[0] != "CURL" {
		t.Fatalf("reported bot denial = %#v", denied)
	}
}

func TestRedactReportDetails(t *testing.T) {
	// No-op when there is nothing to redact.
	in := ProtectDetails{Extra: map[string]string{"userId": "u_1"}}
	out := redactReportDetails(in)
	if out.Extra["userId"] != "u_1" || len(out.Extra) != 1 {
		t.Fatalf("non-redactable map mutated: %#v", out.Extra)
	}

	// Both keys present — both replaced with "<redacted>".
	in = ProtectDetails{Extra: map[string]string{
		"userId":                       "u_1",
		"detectPromptInjectionMessage": "ignore previous instructions",
		"sensitiveInfoValue":           "card 4242 4242 4242 4242",
	}}
	out = redactReportDetails(in)
	if out.Extra["detectPromptInjectionMessage"] != "<redacted>" {
		t.Errorf("prompt injection not redacted: %q", out.Extra["detectPromptInjectionMessage"])
	}
	if out.Extra["sensitiveInfoValue"] != "<redacted>" {
		t.Errorf("sensitive info not redacted: %q", out.Extra["sensitiveInfoValue"])
	}
	if out.Extra["userId"] != "u_1" {
		t.Errorf("non-sensitive field mutated: %q", out.Extra["userId"])
	}
	// Source must not be mutated.
	if in.Extra["detectPromptInjectionMessage"] != "ignore previous instructions" {
		t.Error("source Extra was mutated")
	}

	// Nil Extra is safe.
	if got := redactReportDetails(ProtectDetails{}); got.Extra != nil {
		t.Errorf("nil Extra should stay nil, got %#v", got.Extra)
	}
}

func TestReportRedactsSensitiveInputsButDecideDoesNot(t *testing.T) {
	// sensitiveInfoValue is currently inert — the analyzer isn't shipped, so
	// the value is intentionally never put on the wire. We still cover the
	// key in redactReportDetails as defense-in-depth (see TestRedactReportDetails),
	// but the integration assertion below focuses on detectPromptInjectionMessage,
	// which the Decide RPC genuinely needs.
	const promptMessage = "ignore previous instructions"

	t.Run("cache hit report path", func(t *testing.T) {
		handler := &testDecideHandler{
			reportCh: make(chan struct{}, 2),
			decision: &decidev1.Decision{
				Id:         "req_remote",
				Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
				Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
					RateLimit: &decidev1.RateLimitReason{Max: 10},
				}},
				Ttl: 30,
			},
		}
		path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
		mux := http.NewServeMux()
		mux.Handle(path, h)

		client, err := NewClient(Config{
			Key:        "ajkey_test",
			BaseURL:    "http://arcjet.test",
			HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
			Rules: []Rule{
				TokenBucket(TokenBucketOptions{
					Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
				}),
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		// First request: populates the cache; the Decide RPC receives the raw
		// prompt message because the server needs it to score injection risk.
		if _, err := client.ProtectDetails(context.Background(),
			ProtectDetails{IP: "203.0.113.10"},
			WithDetectPromptInjectionMessage(promptMessage),
		); err != nil {
			t.Fatal(err)
		}
		snap := handler.snapshot()
		decidedExtra := snap.seen.GetDetails().GetExtra()
		if decidedExtra["detectPromptInjectionMessage"] != promptMessage {
			t.Errorf("decide call should see raw prompt message, got %q", decidedExtra["detectPromptInjectionMessage"])
		}

		// Second request hits the cache and fires a Report — that report must
		// carry the redacted prompt, not the raw user input.
		if _, err := client.ProtectDetails(context.Background(),
			ProtectDetails{IP: "203.0.113.10"},
			WithDetectPromptInjectionMessage(promptMessage),
		); err != nil {
			t.Fatal(err)
		}
		handler.waitReport(t)
		snap = handler.snapshot()
		reportedExtra := snap.reportSeen.GetDetails().GetExtra()
		if got := reportedExtra["detectPromptInjectionMessage"]; got != "<redacted>" {
			t.Errorf("report leaked raw prompt message: %q", got)
		}
	})

	t.Run("local deny report path", func(t *testing.T) {
		handler := &testDecideHandler{reportCh: make(chan struct{}, 1)}
		path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
		mux := http.NewServeMux()
		mux.Handle(path, h)

		client, err := NewClient(Config{
			Key:        "ajkey_test",
			BaseURL:    "http://arcjet.test",
			HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
			Rules: []Rule{
				DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := client.ProtectDetails(context.Background(),
			ProtectDetails{Headers: map[string]string{"user-agent": "curl/8.7.1"}},
			WithDetectPromptInjectionMessage(promptMessage),
		); err != nil {
			t.Fatal(err)
		}
		handler.waitReport(t)
		snap := handler.snapshot()
		if snap.decideCalls != 0 {
			t.Fatalf("expected local-only path, got %d decide calls", snap.decideCalls)
		}
		reportedExtra := snap.reportSeen.GetDetails().GetExtra()
		if got := reportedExtra["detectPromptInjectionMessage"]; got != "<redacted>" {
			t.Errorf("local-deny report leaked raw prompt message: %q", got)
		}
	})
}

func TestProtectDoesNotForwardSensitiveInfoValueToServer(t *testing.T) {
	// Sensitive-info scanning runs locally via the bundled wasm analyzer;
	// the raw text passed to WithSensitiveInfoValue must never appear on
	// the Decide RPC wire (only the locally-computed decision does).
	handler := &testDecideHandler{}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Rules: []Rule{
			TokenBucket(TokenBucketOptions{
				Mode: ModeLive, RefillRate: 1, Interval: time.Minute, Capacity: 10,
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.ProtectDetails(context.Background(),
		ProtectDetails{IP: "203.0.113.10"},
		WithSensitiveInfoValue("card 4242 4242 4242 4242"),
	); err != nil {
		t.Fatal(err)
	}
	extra := handler.seen.GetDetails().GetExtra()
	if v, ok := extra["sensitiveInfoValue"]; ok {
		t.Errorf("sensitiveInfoValue must not be sent to the server, got %q", v)
	}
}

func TestSensitiveInfoRulePublishesWireConfig(t *testing.T) {
	// The local analyzer makes the decision, but the rule config still
	// needs to reach Arcjet so the dashboard/report path knows how the
	// rule was set. Mode + allow/deny are forwarded; the scanned text
	// stays in the SDK (asserted by
	// TestProtectDoesNotForwardSensitiveInfoValueToServer).
	client, err := NewClient(Config{
		Key: "ajkey_test",
		Rules: []Rule{
			Shield(ShieldOptions{Mode: ModeLive}),
			SensitiveInfo(SensitiveInfoOptions{
				Mode: ModeLive,
				Deny: []EntityType{SensitiveInfoEmail},
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(client.builtRules); got != 2 {
		t.Fatalf("expected Shield + SensitiveInfo in builtRules, got %d entries", got)
	}
	var sensitive *decidev1.SensitiveInfoRule
	for _, r := range client.builtRules {
		if s := r.GetSensitiveInfo(); s != nil {
			sensitive = s
			break
		}
	}
	if sensitive == nil {
		t.Fatal("expected a sensitiveInfo wire entry in builtRules")
	}
	if sensitive.GetMode() != decidev1.Mode_MODE_LIVE {
		t.Errorf("wire mode = %v, want MODE_LIVE", sensitive.GetMode())
	}
	deny := sensitive.GetDeny()
	if len(deny) != 1 || deny[0] != string(SensitiveInfoEmail) {
		t.Errorf("wire deny = %v, want [%s]", deny, SensitiveInfoEmail)
	}
}

func TestProtectCachesLocalBotDenyAndReportsCacheHit(t *testing.T) {
	handler := &testDecideHandler{reportCh: make(chan struct{}, 2)}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Rules: []Rule{
			DetectBot(BotOptions{Mode: ModeLive, Deny: []string{"CURL"}}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	details := ProtectDetails{Headers: map[string]string{"user-agent": "curl/8.7.1"}}

	first, err := client.ProtectDetails(context.Background(), details)
	if err != nil {
		t.Fatal(err)
	}
	if !first.IsDenied() || first.TTL == 0 {
		t.Fatalf("expected cacheable local deny, got %#v", first)
	}
	handler.waitReport(t)

	second, err := client.ProtectDetails(context.Background(), details)
	if err != nil {
		t.Fatal(err)
	}
	if !second.IsDenied() || second.Results[0].State != "RULE_STATE_CACHED" {
		t.Fatalf("expected cached deny, got %#v", second)
	}
	handler.waitReport(t)

	snap := handler.snapshot()
	decideCalls, reportCalls := snap.decideCalls, snap.reportCalls
	if decideCalls != 0 || reportCalls != 2 {
		t.Fatalf("expected two reports and no decide calls, decide=%d report=%d", decideCalls, reportCalls)
	}
}

func TestProtectCachesRemoteDenyAndReportsCacheHit(t *testing.T) {
	handler := &testDecideHandler{
		reportCh: make(chan struct{}, 1),
		decision: &decidev1.Decision{
			Id:         "req_remote",
			Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
			Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
				RateLimit: &decidev1.RateLimitReason{Max: 10},
			}},
			RuleResults: []*decidev1.RuleResult{
				{
					RuleId:     "rule_remote",
					State:      decidev1.RuleState_RULE_STATE_RUN,
					Conclusion: decidev1.Conclusion_CONCLUSION_DENY,
					Reason: &decidev1.Reason{Reason: &decidev1.Reason_RateLimit{
						RateLimit: &decidev1.RateLimitReason{Max: 10},
					}},
					Ttl: 30,
				},
			},
			Ttl: 30,
		},
	}
	path, h := decidev1alpha1connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	client, err := NewClient(Config{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
		Rules: []Rule{
			TokenBucket(TokenBucketOptions{
				Mode:       ModeLive,
				RefillRate: 1,
				Interval:   time.Minute,
				Capacity:   10,
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := client.ProtectDetails(context.Background(), ProtectDetails{IP: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if !first.IsDenied() {
		t.Fatalf("expected remote deny, got %#v", first)
	}

	second, err := client.ProtectDetails(context.Background(), ProtectDetails{IP: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if !second.IsDenied() || second.Results[0].State != "RULE_STATE_CACHED" {
		t.Fatalf("expected cached remote deny, got %#v", second)
	}
	handler.waitReport(t)

	snap := handler.snapshot()
	decideCalls, reportCalls, reportSeen := snap.decideCalls, snap.reportCalls, snap.reportSeen
	if decideCalls != 1 || reportCalls != 1 {
		t.Fatalf("expected one decide and one cache-hit report, decide=%d report=%d", decideCalls, reportCalls)
	}
	if reportSeen.GetDecision().GetId() == "req_remote" {
		t.Fatal("expected cache-hit report to use a fresh local decision id")
	}
}

func TestWithRuleIsImmutable(t *testing.T) {
	client, err := NewClient(Config{Key: "ajkey_test"})
	if err != nil {
		t.Fatal(err)
	}
	next, err := client.WithRule(Shield(ShieldOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(client.rules) != 0 || len(client.builtRules) != 0 {
		t.Fatalf("original client mutated: %d rules / %d built", len(client.rules), len(client.builtRules))
	}
	if len(next.rules) != 1 || len(next.builtRules) != 1 {
		t.Fatalf("new client rule count = %d / built = %d", len(next.rules), len(next.builtRules))
	}
}

func TestWithRuleRejectsNil(t *testing.T) {
	client, err := NewClient(Config{Key: "ajkey_test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WithRule(nil); !errors.Is(err, ErrNilRule) {
		t.Errorf("expected ErrNilRule, got %v", err)
	}
}

func TestNewClientValidatesRulesEagerly(t *testing.T) {
	_, err := NewClient(Config{Key: "ajkey_test", Rules: []Rule{
		TokenBucket(TokenBucketOptions{}),
	}})
	if !errors.Is(err, ErrInvalidRateLimit) {
		t.Fatalf("expected ErrInvalidRateLimit at NewClient time, got %v", err)
	}
}

func TestNewClientRequiresKey(t *testing.T) {
	t.Setenv("ARCJET_KEY", "")
	_, err := NewClient(Config{})
	if !errors.Is(err, ErrMissingKey) {
		t.Errorf("expected ErrMissingKey, got %v", err)
	}
	_, err = NewClient(Config{Key: "   "})
	if !errors.Is(err, ErrMissingKey) {
		t.Errorf("expected ErrMissingKey for whitespace, got %v", err)
	}
}

func TestProtectNilRequestReturnsError(t *testing.T) {
	client, err := NewClient(Config{Key: "ajkey_test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Protect(context.Background(), nil)
	if !errors.Is(err, ErrNilRequest) {
		t.Errorf("expected ErrNilRequest, got %v", err)
	}
}

func TestProtectDetailsRejectsNilClient(t *testing.T) {
	var c *Client
	_, err := c.ProtectDetails(context.Background(), ProtectDetails{})
	if !errors.Is(err, ErrNilClient) {
		t.Errorf("expected ErrNilClient, got %v", err)
	}
}

func TestClientCloseToleratesNil(t *testing.T) {
	var c *Client
	if err := c.Close(context.Background()); err != nil {
		t.Errorf("nil client close = %v", err)
	}
}

func TestRemoteIPHandlesShapes(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"203.0.113.1:1234":   "203.0.113.1",
		"[2001:db8::1]:1234": "2001:db8::1",
		"plain-without-port": "plain-without-port",
	}
	for in, want := range cases {
		if got := remoteIP(in); got != want {
			t.Errorf("remoteIP(%q) = %q want %q", in, got, want)
		}
	}
}

func TestClientIPBlankXFFFallsBackToRemote(t *testing.T) {
	proxies := []trustedProxy{{network: mustCIDR(t, "10.0.0.0/8")}}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.5:1234"
	if got := clientIP(req, proxies, platformNone); got != "10.0.0.5" {
		t.Errorf("missing XFF should fall back to remote, got %q", got)
	}
	req.Header.Set("X-Forwarded-For", ", ,  ")
	if got := clientIP(req, proxies, platformNone); got != "10.0.0.5" {
		t.Errorf("blank XFF should fall back to remote, got %q", got)
	}
}

func TestIsTrustedProxyMatchesIPAndCIDR(t *testing.T) {
	proxies, err := parseTrustedProxies([]string{"10.0.0.5", "10.0.0.0/8", "  ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if !isTrustedProxy("10.0.0.5", proxies) {
		t.Error("exact IP not matched")
	}
	if !isTrustedProxy("10.1.2.3", proxies) {
		t.Error("CIDR not matched")
	}
	if isTrustedProxy("203.0.113.1", proxies) {
		t.Error("external IP should not match")
	}
	if isTrustedProxy("not-an-ip", proxies) {
		t.Error("non-IP value should not match")
	}
}

func TestParseTrustedProxiesRejectsAndAcceptsMixed(t *testing.T) {
	if _, err := parseTrustedProxies([]string{"definitely not"}); err == nil {
		t.Error("expected error for invalid entry")
	}
	proxies, err := parseTrustedProxies([]string{"::1", "fe80::/10"})
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 2 {
		t.Errorf("expected 2 IPv6 entries, got %d", len(proxies))
	}
	empty, err := parseTrustedProxies(nil)
	if err != nil || empty != nil {
		t.Errorf("nil input got %v %v", empty, err)
	}
	blanks, err := parseTrustedProxies([]string{"", " "})
	if err != nil {
		t.Fatal(err)
	}
	if len(blanks) != 0 {
		t.Errorf("blank inputs should be skipped, got %#v", blanks)
	}
}

func TestDefaultBaseURLEnvFallbacks(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("FLY_REGION", "")
	t.Setenv("ARCJET_BASE_URL", "")
	if got := defaultBaseURL(""); got != defaultDecideURL {
		t.Errorf("default = %q", got)
	}
	if got := defaultBaseURL("https://custom.example/"); got != "https://custom.example" {
		t.Errorf("explicit override = %q", got)
	}
	t.Setenv("ARCJET_BASE_URL", "https://env.example/")
	if got := defaultBaseURL(""); got != "https://env.example" {
		t.Errorf("ARCJET_BASE_URL override = %q", got)
	}
	t.Setenv("FLY_APP_NAME", "myapp")
	if got := defaultBaseURL(""); got != defaultFlyDecideURL {
		t.Errorf("FLY override = %q", got)
	}
}

func TestQueryWithQuestion(t *testing.T) {
	if got := queryWithQuestion(""); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := queryWithQuestion("?a=1"); got != "?a=1" {
		t.Errorf("already prefixed = %q", got)
	}
	if got := queryWithQuestion("a=1"); got != "?a=1" {
		t.Errorf("plain = %q", got)
	}
}

func TestProtectOptionHelpers(t *testing.T) {
	opts := ProtectOptions{}
	body := []byte("hello")
	for _, opt := range []ProtectOption{
		WithRequested(7),
		WithCharacteristics(map[string]string{"role": "admin"}),
		WithCharacteristic("userId", "u_1"),
		WithDetectPromptInjectionMessage("ignore previous"),
		WithSensitiveInfoValue("4242 4242 4242 4242"),
		WithEmail("user@example.com"),
		WithIPSrc("198.51.100.1"),
		WithFilterLocal(map[string]string{"plan": "free"}),
		WithBody(body),
		WithExtra(map[string]string{"tier": "gold"}),
	} {
		opt(&opts)
	}
	body[0] = 'X' // mutate caller buffer to confirm WithBody copied
	if opts.Requested != 7 {
		t.Errorf("Requested = %d", opts.Requested)
	}
	if opts.Characteristics["userId"] != "u_1" || opts.Characteristics["role"] != "admin" {
		t.Errorf("characteristics merged incorrectly: %#v", opts.Characteristics)
	}
	if opts.DetectPromptInjectionMessage != "ignore previous" {
		t.Errorf("prompt = %q", opts.DetectPromptInjectionMessage)
	}
	if opts.SensitiveInfoValue == "" || opts.Email != "user@example.com" || opts.IPSrc != "198.51.100.1" {
		t.Errorf("string options = %#v", opts)
	}
	if opts.FilterLocal["plan"] != "free" {
		t.Errorf("filter local = %#v", opts.FilterLocal)
	}
	if string(opts.Body) != "hello" {
		t.Errorf("WithBody should have copied: got %q", opts.Body)
	}
	if opts.Extra["tier"] != "gold" {
		t.Errorf("extra = %#v", opts.Extra)
	}
}

func TestWithCharacteristicSeedsMap(t *testing.T) {
	opts := ProtectOptions{}
	WithCharacteristic("k", "v")(&opts)
	if opts.Characteristics["k"] != "v" {
		t.Errorf("seeded map = %#v", opts.Characteristics)
	}
}

func TestDetailsFromRequestPopulatesAllFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/path?x=1", http.NoBody)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("User-Agent", "go-test")
	req.Header.Set("Cookie", "sid=abc")
	d := DetailsFromRequest(req)
	if d.IP != "203.0.113.10" || d.Method != http.MethodPost || d.Host != "example.com" ||
		d.Path != "/path" || d.Query != "x=1" || d.Cookies != "sid=abc" {
		t.Fatalf("details = %#v", d)
	}
	if d.Headers["user-agent"] != "go-test" {
		t.Errorf("headers lowercased = %#v", d.Headers)
	}
}
