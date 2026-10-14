// Example net/http server protected with the Arcjet Go SDK.
//
// GET / runs each request through Shield, bot detection, and a token bucket
// rate limit. POST /submit additionally scans the request body for sensitive
// information (names, emails, addresses, SSNs, card numbers, and more) with the
// on-device Rampart NER backend. The scanned text is analyzed in-process and
// never leaves the SDK.
package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/arcjet/arcjet-go"
	"github.com/arcjet/arcjet-go/sensitiveinfo/rampart"
)

func main() {
	key := os.Getenv("ARCJET_KEY")
	if key == "" {
		slog.Error("ARCJET_KEY is required. Get one with: arcjet sites get-key, or from https://app.arcjet.com")
		os.Exit(1)
	}

	// On-device NER backend for sensitive-information detection. It runs a
	// quantized model embedded in the binary, so the scanned text stays
	// in-process. Loading dequantizes the weights once and is relatively
	// expensive, so create it at startup and share it across requests.
	backend, err := rampart.New(rampart.Options{})
	if err != nil {
		slog.Error("rampart: load on-device model", "err", err)
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

			// Block request bodies containing sensitive information. The text to
			// scan is passed per request with arcjet.WithSensitiveInfoValue and is
			// analyzed locally — it is never sent to Arcjet. The rule only runs
			// when a value is supplied, so it is a no-op on GET / below.
			// rampart.Entities() denies every type the backend can detect; pass
			// a narrower slice (e.g. GivenName, Surname, SSN) to scope it down.
			arcjet.SensitiveInfo(arcjet.SensitiveInfoOptions{
				Mode:    arcjet.ModeLive,
				Deny:    rampart.Entities(),
				Backend: backend,
			}),
		},
	})
	if err != nil {
		slog.Error("arcjet: create client", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", hello(aj))
	mux.HandleFunc("POST /submit", submit(aj))

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

// submit scans the request body for sensitive information before accepting
// it. A rejection reports the exact text of each detected entity and where it
// was found, so you can tell the user what to remove.
func submit(aj *arcjet.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read the body so we can scan it, capping the size so a large body
		// can't exhaust memory.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"error": "Could not read request body",
			})
			return
		}
		text := string(body)

		decision, err := aj.Protect(
			r.Context(),
			r,
			// The text to scan stays in the SDK — it is never sent to Arcjet,
			// and the on-device model runs in-process.
			arcjet.WithSensitiveInfoValue(text),
		)
		if err != nil {
			// Arcjet fails open — log and continue serving.
			slog.Warn("arcjet: protect", "err", err)
		}

		if decision.IsDenied() {
			if si := decision.Reason.SensitiveInfo; si != nil {
				// Report each detection with its type and the matched text
				// (Start/End are byte offsets into the scanned value).
				found := make([]map[string]any, 0, len(si.Denied))
				for _, e := range si.Denied {
					match := ""
					if e.Start >= 0 && e.End <= len(text) && e.Start <= e.End {
						match = text[e.Start:e.End]
					}
					found = append(found, map[string]any{
						"type":  e.Type,
						"start": e.Start,
						"end":   e.End,
						"match": match,
					})
				}
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error":    "Sensitive information detected",
					"detected": found,
				})
				return
			}

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

		writeJSON(w, http.StatusOK, map[string]any{"message": "Submission accepted"})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Warn("write response", "err", err)
	}
}
