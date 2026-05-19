// Example net/http server protected with the Arcjet Go SDK.
//
// Hits GET /?message=... and runs each request through Shield, bot detection,
// and a token bucket rate limit. (Sensitive-info detection is exposed by the
// SDK but is currently a no-op pending a WebAssembly analyzer, so it is not
// wired up here.)
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/arcjet/arcjet-go"
)

func main() {
	key := os.Getenv("ARCJET_KEY")
	if key == "" {
		slog.Error("ARCJET_KEY is required. Get one with: arcjet sites get-key, or from https://app.arcjet.com")
		os.Exit(1)
	}

	aj, err := arcjet.NewClient(arcjet.Config{
		Key: key,
		Rules: []arcjet.Rule{
			// Shield protects your app from common attacks e.g. SQL injection.
			arcjet.Shield(arcjet.ShieldOptions{Mode: arcjet.ModeLive}),

			// Block automated clients except well-known search engines.
			arcjet.DetectBot(arcjet.BotOptions{
				Mode: arcjet.ModeLive,
				Allow: []string{
					arcjet.BotCategorySearchEngine, // Google, Bing, etc.
					"CURL",
					// Uncomment to allow these other common bot categories.
					// See the full list at https://arcjet.com/bot-list
					// arcjet.BotCategoryMonitor, // Uptime monitoring services
					// arcjet.BotCategoryPreview, // Link previews e.g. Slack, Discord
				},
			}),

			// Token bucket rate limit. Tracked by IP address by default;
			// to track per-user, set Characteristics and pass values via
			// arcjet.WithCharacteristics at call time.
			// See https://docs.arcjet.com/fingerprints
			arcjet.TokenBucket(arcjet.TokenBucketOptions{
				Mode:       arcjet.ModeLive,
				RefillRate: 5,                // Refill 5 tokens per interval.
				Interval:   10 * time.Second, // Refill every 10 seconds.
				Capacity:   10,               // Bucket capacity of 10 tokens.
			}),
		},
	})
	if err != nil {
		slog.Error("arcjet: create client", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", hello(aj))

	srv := &http.Server{
		Addr:              ":3000",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	slog.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("http: serve", "err", err)
		os.Exit(1)
	}
}

func hello(aj *arcjet.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decision, err := aj.Protect(
			r.Context(),
			r,
			arcjet.WithRequested(5), // Deduct 5 tokens from the bucket.
		)
		if err != nil {
			// Arcjet fails open — log and continue serving.
			slog.Warn("arcjet: protect", "err", err)
		}

		// Typed IP details are available directly on decision.IP.
		if city := decision.IP.City; city != "" {
			slog.Info("request", "city", city, "country", decision.IP.CountryName)
		}

		// Handle denied requests.
		if decision.IsDenied() {
			status := http.StatusForbidden
			if decision.Reason.IsRateLimit() {
				status = http.StatusTooManyRequests
			}
			writeJSON(w, status, map[string]any{
				"error":  "Denied",
				"reason": decision.Reason,
			})
			return
		}

		// Check IP metadata (VPNs, hosting, geolocation, etc.).
		if decision.IP.IsHosting {
			// Hosting IPs are commonly bots, so they can often be blocked.
			// Consider your use case though — an API endpoint may legitimately
			// see hosting IPs.
			// https://docs.arcjet.com/blueprints/vpn-proxy-detection
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "Denied from hosting IP",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"message":  "Hello world",
			"decision": decision,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Warn("write response", "err", err)
	}
}
