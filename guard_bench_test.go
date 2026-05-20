package arcjet

import (
	"context"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

// benchGuardHandler is a Guard handler that returns a canned allow response
// without inspecting submissions. The handler used by Guard tests panics on
// empty submission lists; this variant tolerates them so callers can drive
// it from any benchmark configuration.
type benchGuardHandler struct {
	resp *decidev2.GuardResponse
}

func (h *benchGuardHandler) Guard(_ context.Context, _ *connect.Request[decidev2.GuardRequest]) (*connect.Response[decidev2.GuardResponse], error) {
	return connect.NewResponse(h.resp), nil
}

func newBenchGuardClient(b *testing.B) *GuardClient {
	b.Helper()
	handler := &benchGuardHandler{resp: &decidev2.GuardResponse{
		Decision: &decidev2.GuardDecision{
			Id:         "gdec_bench",
			Conclusion: decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW,
		},
	}}
	path, h := decidev2connect.NewDecideServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	client, err := NewGuardClient(GuardConfig{
		Key:        "ajkey_test",
		BaseURL:    "http://arcjet.test",
		HTTPClient: &http.Client{Transport: handlerTransport{handler: mux}},
	})
	if err != nil {
		b.Fatal(err)
	}
	return client
}

// BenchmarkGuardTokenBucket measures a single Guard call with one token
// bucket rule input: input ID generation, key hashing, submission JSON
// encoding, protojson decode, and the in-process Connect round-trip.
func BenchmarkGuardTokenBucket(b *testing.B) {
	client := newBenchGuardClient(b)
	rule, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode:       ModeLive,
		RefillRate: 1,
		Interval:   time.Minute,
		Capacity:   10,
		Label:      "tools.get-weather",
	})
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	req := GuardRequest{
		Label: "tools.get-weather",
		Rules: []GuardRuleInput{rule.Key("user_123", 1)},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		// Rebuild the request each iteration so we exercise input ID
		// generation and key hashing on every call — that's the realistic
		// shape of a per-Guard-call hot path.
		req.Rules = []GuardRuleInput{rule.Key("user_123", 1)}
		if _, err := client.Guard(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGuardMultipleRules measures a Guard call binding three rules in a
// single request — the realistic shape of an MCP tool call protected by a
// rate limit, a prompt injection scan, and a sliding window quota.
func BenchmarkGuardMultipleRules(b *testing.B) {
	client := newBenchGuardClient(b)
	bucket, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode:       ModeLive,
		RefillRate: 1,
		Interval:   time.Minute,
		Capacity:   10,
		Label:      "tools.get-weather",
	})
	if err != nil {
		b.Fatal(err)
	}
	window, err := GuardSlidingWindow(GuardSlidingWindowOptions{
		Mode:        ModeLive,
		Interval:    time.Hour,
		MaxRequests: 100,
		Label:       "tools.get-weather",
	})
	if err != nil {
		b.Fatal(err)
	}
	injection, err := GuardPromptInjection(GuardPromptInjectionOptions{
		Mode:  ModeLive,
		Label: "tools.get-weather",
	})
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		req := GuardRequest{
			Label: "tools.get-weather",
			Rules: []GuardRuleInput{
				bucket.Key("user_123", 1),
				window.Key("user_123", 1),
				injection.Text("what's the weather in Tokyo?"),
			},
		}
		if _, err := client.Guard(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGuardTokenBucketKey measures only the input-binding cost: a new
// input ID and a SHA-256 of the key. This is the part that runs for every
// Guard call regardless of network state.
func BenchmarkGuardTokenBucketKey(b *testing.B) {
	rule, err := GuardTokenBucket(GuardTokenBucketOptions{
		Mode:       ModeLive,
		RefillRate: 1,
		Interval:   time.Minute,
		Capacity:   10,
		Label:      "tools.get-weather",
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		input := rule.Key("user_123", 1)
		if _, err := input.guardSubmission(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGuardPromptInjectionText measures binding text to a prompt
// injection rule input — currently a no-op build with a new input ID, but
// still on the hot path of every prompt-injection-guarded call.
func BenchmarkGuardPromptInjectionText(b *testing.B) {
	rule, err := GuardPromptInjection(GuardPromptInjectionOptions{
		Mode:  ModeLive,
		Label: "tools.get-weather",
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	text := "what's the weather in Tokyo?"

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		input := rule.Text(text)
		if _, err := input.guardSubmission(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
