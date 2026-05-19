<a href="https://arcjet.com" target="_arcjet-home"> <picture> <source
  media="(prefers-color-scheme: dark)"
    srcset="https://arcjet.com/logo/arcjet-dark-lockup-voyage-horizontal.svg">
<img src="https://arcjet.com/logo/arcjet-light-lockup-voyage-horizontal.svg"
  alt="Arcjet Logo" height="128" width="auto"> </picture> </a>

# arcjet

> [!IMPORTANT]
> The Go SDK is pre-release and unstable.

[Arcjet](https://arcjet.com) is the runtime security platform that ships with your AI code. Stop bots and automated attacks from burning your AI budget, leaking data, or misusing tools with Arcjet's AI security building blocks.

This is the Go SDK for [Arcjet](https://arcjet.com) — use `arcjet.NewClient` for
**request protection** in `net/http` handlers (and any router that exposes
`*http.Request`) and `arcjet.NewGuardClient` for **guard protection** (AI agent
tool calls, MCP servers, background jobs, queue workers).

## Getting started

### Install the Arcjet CLI

The CLI is used to log in, manage site keys, and install protection skills.

**Homebrew (macOS and Linux):**

```sh
brew install arcjet/tap/arcjet
```

**npx (Node.js)** — run any command without installing:

```sh
npx @arcjet/cli <command>
```

**Or [download a binary](https://github.com/arcjet/arcjet-cli/releases)** for
macOS (Apple Silicon, Intel), Linux (x86_64, arm64), and Windows (x86_64,
arm64).

> Examples below use the `arcjet` binary. If you installed via npx, replace
> `arcjet` with `npx @arcjet/cli`.

### Quick setup with an AI agent

1. Log in with the CLI:
   ```sh
   arcjet auth login
   ```
2. Install the protection skill:
   ```sh
   npx skills add arcjet/skills --skill add-request-protection
   ```
   For guard protection: `--skill add-guard-protection`
3. Tell your agent what to protect — it handles the rest.

### Manual setup

1. **Log in** with the CLI (or at [`app.arcjet.com`](https://app.arcjet.com)):
   ```sh
   arcjet auth login
   ```
2. `go get github.com/arcjet/arcjet-go`
3. **Get your site key:**
   ```sh
   arcjet sites get-key
   ```
   Or copy it from the [Arcjet dashboard](https://app.arcjet.com).
4. Set `ARCJET_KEY=ajkey_yourkey` in your environment.
5. Protect a handler — see the [AI protection example](#quick-start) or
   individual [feature examples](#features) below.

### Get help

[Join our Discord server](https://arcjet.com/discord) or [reach out for
support](https://docs.arcjet.com/support).

## Quick start

> **Note:** Create the client once at package scope and reuse it across
> handlers. For larger projects, move it into its own package
> (e.g. `internal/security/arcjet.go`) so handlers can import a single shared
> instance.

Protect an AI chat endpoint with prompt injection detection, token budget
rate limiting, and bot protection:

```go
// main.go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/arcjet/arcjet-go"
)

var arcjetKey = func() string {
	key := os.Getenv("ARCJET_KEY")
	if key == "" {
		log.Fatal("ARCJET_KEY is required. Get one with: arcjet sites get-key" +
			" or from https://app.arcjet.com")
	}
	return key
}()

// Create a single Arcjet client and reuse it across requests.
var aj = must(arcjet.NewClient(arcjet.Config{
	Key: arcjetKey,
	Rules: []arcjet.Rule{
		// Detect and block prompt injection attacks in user messages.
		arcjet.DetectPromptInjection(arcjet.PromptInjectionOptions{
			Mode: arcjet.ModeLive,
		}),
		// Rate limit by token budget — refill 100 tokens every 60 seconds.
		arcjet.TokenBucket(arcjet.TokenBucketOptions{
			Mode:            arcjet.ModeLive,
			Characteristics: []string{"userId"},
			RefillRate:      100,
			Interval:        time.Minute,
			Capacity:        1000,
		}),
		// Block automated clients and scrapers from your AI endpoints.
		arcjet.DetectBot(arcjet.BotOptions{
			Mode:  arcjet.ModeLive,
			Allow: []string{}, // empty = block all bots
		}),
		// Protect against common web attacks (SQLi, XSS, etc.).
		arcjet.Shield(arcjet.ShieldOptions{Mode: arcjet.ModeLive}),
	},
}))

type chatRequest struct {
	Message string `json:"message"`
}

func chat(w http.ResponseWriter, r *http.Request) {
	var body chatRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	userID := "user_123" // replace with real user ID from session

	decision, err := aj.Protect(
		r.Context(),
		r,
		arcjet.WithRequested(5), // tokens consumed per request
		arcjet.WithCharacteristics(map[string]string{"userId": userID}),
		arcjet.WithDetectPromptInjectionMessage(body.Message), // scan for prompt injection
	)
	if err != nil {
		// Arcjet fails open — log and continue serving.
		log.Printf("arcjet: %v", err)
	} else if decision.IsDenied() {
		status := http.StatusForbidden
		if decision.Reason.IsRateLimit() {
			status = http.StatusTooManyRequests
		}
		http.Error(w, "denied", status)
		return
	}

	// Safe to pass body.Message to your LLM.
	_ = json.NewEncoder(w).Encode(map[string]string{"reply": "..."})
}

func main() {
	http.HandleFunc("/chat", chat)
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}
```

Pass `r.Context()` to `Protect` (as the example does) so the call honors
client disconnects.

Call `aj.Protect` inside each handler — once per request. Avoid wrapping it in
generic `net/http` middleware that runs on every path (including static
assets); you lose the ability to apply per-route rules and risk
double-counting traffic.

## Features

| Feature | Request (`NewClient`) | Guard (`NewGuardClient`) |
| --- | :---: | :---: |
| Rate Limiting | ✅ | ✅ |
| Prompt Injection Detection | ✅ | ✅ |
| Sensitive Information Detection | ⏳ | ⏳ |
| Bot Protection | ✅ | — |
| Shield WAF | ✅ | — |
| Email Validation | ✅ | — |
| Request Filters | ✅ | — |
| IP Analysis | ✅ | — |
| Custom Rules | — | ✅ |

⏳ = API present but currently a no-op.

- 🔒 [Prompt Injection Detection](#prompt-injection-detection) — detect and block
  prompt injection attacks before they reach your LLM.
- 🤖 [Bot Protection](#bot-protection) — stop scrapers, credential stuffers, and
  AI crawlers from abusing your endpoints.
- 🛑 [Rate Limiting](#rate-limiting) — token bucket, fixed window, and sliding
  window algorithms; model AI token budgets per user.
- 🛡️ [Shield WAF](#shield-waf) — protect against SQL injection, XSS, and other
  common web attacks.
- 📧 [Email Validation](#email-validation) — block disposable, invalid, and
  undeliverable addresses at signup.
- 🎯 [Request Filters](#request-filters) — expression-based rules on IP, path,
  headers, and custom fields.
- 🌐 [IP Analysis](#ip-analysis) — geolocation, ASN, VPN, proxy, Tor, and hosting
  detection included with every request.
- 🧩 [Arcjet Guard](#arcjet-guard) — lower-level API for AI agent tool calls and
  background tasks where there is no HTTP request.

### Which features do I need?

| If your app has...      | Recommended features                                                                                                  |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| LLM / AI chat endpoints | Prompt injection + token bucket rate limit + bot protection + shield                                                  |
| AI agent tool calls     | [Arcjet Guard](#arcjet-guard) — rate limiting + prompt injection + custom rules                                       |
| MCP servers             | [Arcjet Guard](#arcjet-guard) — tool calls run over stdio/SSE, not HTTP, so use guard rules at each tool call site    |
| Background jobs/workers | [Arcjet Guard](#arcjet-guard) — no HTTP request at the protection site                                                |
| Public API              | Rate limiting + bot protection + shield                                                                               |
| Signup / login forms    | Email validation + bot protection + rate limiting (or [signup protection](https://docs.arcjet.com/signup-protection)) |
| Internal / admin routes | Shield + request filters (country, VPN/proxy blocking)                                                                |
| Any web application     | Shield + bot protection (good baseline for all apps)                                                                  |

All features can be combined in a single Arcjet client. Rules are evaluated
together — if **any** rule denies the request, `decision.IsDenied()` returns
`true`. Use `arcjet.ModeDryRun` on individual rules to test them before
enforcing.

## Installation

```sh
go get github.com/arcjet/arcjet-go
```

The SDK requires Go 1.25 or later.

## Prompt injection detection

Detect and block prompt injection attacks — attempts by users to hijack your
LLM's behavior through crafted input — before they reach your model.

```go
aj, err := arcjet.NewClient(arcjet.Config{
	Key: arcjetKey,
	Rules: []arcjet.Rule{
		arcjet.DetectPromptInjection(arcjet.PromptInjectionOptions{
			Mode: arcjet.ModeLive,
		}),
	},
})
if err != nil {
	return err
}

decision, err := aj.Protect(
	r.Context(),
	r,
	arcjet.WithDetectPromptInjectionMessage(body.Message),
)
if err != nil {
	// Fails open — log and continue.
	return err
}

if decision.IsDenied() {
	http.Error(w, "Prompt injection detected", http.StatusBadRequest)
	return
}

// Safe to pass body.Message to your LLM.
```

See the [Prompt Injection docs](https://docs.arcjet.com/prompt-injection) for
more details.

## Bot protection

Manage traffic from automated clients. Block scrapers, credential stuffers, and
AI crawlers, while allowing legitimate bots like search engines and monitors.

```go
aj, err := arcjet.NewClient(arcjet.Config{
	Key: arcjetKey,
	Rules: []arcjet.Rule{
		arcjet.DetectBot(arcjet.BotOptions{
			Mode: arcjet.ModeLive,
			Allow: []string{
				arcjet.BotCategorySearchEngine, // Google, Bing, etc.
				// arcjet.BotCategoryMonitor,    // Uptime monitoring
				// arcjet.BotCategoryPreview,    // Link previews (Slack, Discord)
				// "OPENAI_CRAWLER_SEARCH",      // Allow a specific bot by name
			},
		}),
	},
})
if err != nil {
	return err
}

decision, err := aj.Protect(r.Context(), r)
if err != nil {
	return err
}

if decision.IsDenied() {
	http.Error(w, "Bot detected", http.StatusForbidden)
	return
}

if decision.IsSpoofedBot() {
	http.Error(w, "Spoofed bot", http.StatusForbidden)
	return
}
```

### Bot categories

Configure rules using
[categories](https://docs.arcjet.com/bot-protection/identifying-bots#bot-categories)
or [specific bot identifiers](https://github.com/arcjet/well-known-bots):

```go
arcjet.DetectBot(arcjet.BotOptions{
	Mode: arcjet.ModeLive,
	Allow: []string{
		arcjet.BotCategorySearchEngine,
		"OPENAI_CRAWLER_SEARCH",
	},
})
```

Exported constants cover all built-in categories: `arcjet.BotCategoryAcademic`,
`BotCategoryAdvertising`, `BotCategoryAI`, `BotCategoryAmazon`,
`BotCategoryArchive`, `BotCategoryBotnet`, `BotCategoryFeedFetcher`,
`BotCategoryGoogle`, `BotCategoryMeta`, `BotCategoryMicrosoft`,
`BotCategoryMonitor`, `BotCategoryOptimizer`, `BotCategoryPreview`,
`BotCategoryProgrammatic`, `BotCategorySearchEngine`, `BotCategorySlack`,
`BotCategorySocial`, `BotCategoryTool`, `BotCategoryUnknown`,
`BotCategoryVercel`, `BotCategoryYahoo`. Plain strings still work (e.g.
`"CATEGORY:AI"` or `"OPENAI_CRAWLER_SEARCH"` for [specific bots by
name](https://arcjet.com/bot-list)) — the constants exist for autocomplete and
to catch typos at compile time.

If you specify an allow list, all other bots are denied. An empty allow list
blocks all bots. The reverse applies for deny lists.

### Verified vs. spoofed bots

Bots claiming to be well-known crawlers (e.g. Googlebot) are verified against
their known IP ranges. Use `decision.IsSpoofedBot()` to check:

```go
if decision.IsSpoofedBot() {
	http.Error(w, "Spoofed bot", http.StatusForbidden)
	return
}
```

See the [Bot Protection docs](https://docs.arcjet.com/bot-protection) for more
details.

## Rate limiting

Limit request rates per IP, user, or any custom characteristic. Arcjet supports
token bucket, fixed window, and sliding window algorithms. Token buckets are
ideal for controlling AI token budgets — set `Capacity` to the max tokens a
user can spend, `RefillRate` to how many tokens are restored per `Interval`,
and deduct tokens per request via `arcjet.WithRequested(n)`. The `Interval`
accepts a `time.Duration`. Use `Characteristics` to track limits per user
instead of per IP.

### Token bucket (recommended for AI)

Rate limits track by IP address by default. To track per user, declare the key
name in `Characteristics` on the rule, then pass the actual value via
`arcjet.WithCharacteristics` at call time:

```go
aj, err := arcjet.NewClient(arcjet.Config{
	Key: arcjetKey,
	Rules: []arcjet.Rule{
		arcjet.TokenBucket(arcjet.TokenBucketOptions{
			Mode:            arcjet.ModeLive,
			Characteristics: []string{"userId"}, // or omit for IP-based
			RefillRate:      100,                // tokens added per interval
			Interval:        time.Minute,        // interval duration
			Capacity:        1000,               // maximum tokens per bucket
		}),
	},
})

decision, err := aj.Protect(
	r.Context(),
	r,
	arcjet.WithRequested(5), // tokens consumed by this request
	arcjet.WithCharacteristics(map[string]string{"userId": "user_123"}),
)

if decision.IsDenied() {
	http.Error(w, "Rate limited", http.StatusTooManyRequests)
	return
}
```

Put `Characteristics` on the specific rate-limit rule that needs it, not on the
global client — that way different rules can key by different things.

### Fixed window

```go
arcjet.FixedWindow(arcjet.FixedWindowOptions{
	Mode:        arcjet.ModeLive,
	Window:      time.Minute,
	MaxRequests: 100,
})
```

### Sliding window

```go
arcjet.SlidingWindow(arcjet.SlidingWindowOptions{
	Mode:        arcjet.ModeLive,
	Interval:    time.Minute,
	MaxRequests: 100,
})
```

See the [Rate Limiting docs](https://docs.arcjet.com/rate-limiting) for more
details.

## Sensitive information detection

> [!IMPORTANT]
> **Not yet implemented in the Go SDK.** Sensitive-info detection runs as a
> WebAssembly analyzer in the JavaScript SDK (`@arcjet/analyze-wasm`) and has
> not been ported to Go yet. `SensitiveInfo` and `WithSensitiveInfoValue`
> exist so that call sites stay stable when the analyzer lands, but they are
> currently no-ops: the rule is omitted from the wire request and
> `WithSensitiveInfoValue` is silently ignored. Do not depend on this for
> PII enforcement today.
>
> When the analyzer ships, the planned shape — kept ready in the current API
> — is:
>
> ```go
> aj, err := arcjet.NewClient(arcjet.Config{
> 	Key: arcjetKey,
> 	Rules: []arcjet.Rule{
> 		arcjet.SensitiveInfo(arcjet.SensitiveInfoOptions{
> 			Mode: arcjet.ModeLive,
> 			Deny: []arcjet.EntityType{
> 				arcjet.SensitiveInfoEmail,
> 				arcjet.SensitiveInfoCreditCardNumber,
> 			},
> 		}),
> 	},
> })
>
> decision, err := aj.Protect(
> 	r.Context(),
> 	r,
> 	arcjet.WithSensitiveInfoValue("User input to scan"),
> )
> ```
>
> See the [Sensitive Information docs](https://docs.arcjet.com/sensitive-info)
> for the planned behavior. For PII enforcement today, scan the input
> yourself before passing it to your model.

## Shield WAF

Protect against common web attacks including SQL injection, XSS, path
traversal, and other OWASP Top 10 threats. No additional configuration
needed — Shield analyzes request patterns automatically.

```go
arcjet.Shield(arcjet.ShieldOptions{Mode: arcjet.ModeLive})
```

Always include `Shield` on the shared client as a base rule — it costs nothing
to add and protects every route.

See the [Shield docs](https://docs.arcjet.com/shield) for more details.

## Email validation

Prevent users from signing up with disposable, invalid, or undeliverable email
addresses. Deny types: `DISPOSABLE`, `FREE`, `INVALID`, `NO_MX_RECORDS`,
`NO_GRAVATAR`.

```go
aj, err := arcjet.NewClient(arcjet.Config{
	Key: arcjetKey,
	Rules: []arcjet.Rule{
		arcjet.ValidateEmail(arcjet.EmailOptions{
			Mode: arcjet.ModeLive,
			Deny: []arcjet.EmailType{
				arcjet.EmailTypeDisposable,
				arcjet.EmailTypeInvalid,
				arcjet.EmailTypeNoMXRecords,
			},
		}),
	},
})

// Pass the email with each Protect call.
decision, err := aj.Protect(
	r.Context(),
	r,
	arcjet.WithEmail("user@example.com"),
)
```

See the [Email Validation docs](https://docs.arcjet.com/email-validation) for
more details.

## Request filters

Filter requests using expression-based rules against request properties (IP
address, headers, path, HTTP method, and custom local fields).

### Block by country

Restrict access to specific countries — useful for licensing, compliance, or
regional rollouts. The `Allow` list denies all countries not listed:

```go
aj, err := arcjet.NewClient(arcjet.Config{
	Key: arcjetKey,
	Rules: []arcjet.Rule{
		// Allow only US traffic — all other countries are denied.
		arcjet.Filter(arcjet.FilterOptions{
			Mode:  arcjet.ModeLive,
			Allow: []string{`ip.src.country == "US"`},
		}),
	},
})

decision, err := aj.Protect(r.Context(), r)
if decision.IsDenied() {
	http.Error(w, "Access restricted in your region", http.StatusForbidden)
	return
}
```

To restrict to a specific state or province, combine country and region:

```go
arcjet.Filter(arcjet.FilterOptions{
	Mode: arcjet.ModeLive,
	// Allow only California — useful for state-level compliance e.g. CCPA testing.
	Allow: []string{`ip.src.country == "US" && ip.src.region == "California"`},
})
```

### Block VPN and proxy traffic

Prevent anonymized traffic from accessing sensitive endpoints — useful for
fraud prevention, enforcing geo-restrictions, and reducing abuse:

```go
arcjet.Filter(arcjet.FilterOptions{
	Mode: arcjet.ModeLive,
	Deny: []string{
		"ip.src.vpn",   // VPN services
		"ip.src.proxy", // Open proxies
		"ip.src.tor",   // Tor exit nodes
	},
})
```

For cases where you want to allow some anonymized traffic (e.g. Apple Private
Relay) but still log or handle it differently, use `decision.IP` helpers after
calling `Protect`:

```go
decision, err := aj.Protect(r.Context(), r)
if err != nil {
	return err
}

if decision.IP.IsVPN || decision.IP.IsTor {
	http.Error(w, "VPN traffic not allowed", http.StatusForbidden)
	return
}
if decision.IP.IsRelay {
	// Privacy relay (e.g. Apple Private Relay) — lower risk than a VPN.
	// Allow through with custom handling.
}
```

### Custom local fields

Pass arbitrary values from your application for use in filter expressions:

```go
decision, err := aj.Protect(
	r.Context(),
	r,
	arcjet.WithFilterLocal(map[string]string{
		"userId": currentUser.ID,
		"plan":   currentUser.Plan,
	}),
)
```

These are then available as `local["userId"]` and `local["plan"]` in
expressions:

```go
arcjet.Filter(arcjet.FilterOptions{
	Mode: arcjet.ModeLive,
	Deny: []string{`local["plan"] == "free" && ip.src.country != "US"`},
})
```

`WithFilterLocal` values stay local — they are evaluated by the embedded
WebAssembly runtime and are never sent to Arcjet Cloud.

See the [Request Filters docs](https://docs.arcjet.com/filters),
[IP Geolocation blueprint](https://docs.arcjet.com/blueprints/ip-geolocation),
and [VPN/Proxy Detection
blueprint](https://docs.arcjet.com/blueprints/vpn-proxy-detection) for more
details.

## IP analysis

Arcjet returns IP metadata with every decision — no extra API calls needed.

```go
if decision.IP.IsHosting {
	// Likely a cloud/hosting provider — often suspicious for bots.
	http.Error(w, "Hosting IP blocked", http.StatusForbidden)
	return
}

if decision.IP.IsVPN || decision.IP.IsProxy || decision.IP.IsTor {
	// Apply your policy for anonymized traffic.
}

ip := decision.IP
log.Println(ip.City, ip.CountryName) // geolocation
log.Println(ip.ASN, ip.ASNName)      // ASN / network
log.Println(ip.IsVPN, ip.IsHosting)  // reputation
```

Available fields include geolocation (`Latitude`, `Longitude`, `City`,
`Region`, `Country`, `Continent`), network (`ASN`, `ASNName`, `ASNDomain`,
`ASNType`, `ASNCountry`), and reputation (`IsVPN`, `IsProxy`, `IsTor`,
`IsHosting`, `IsRelay`).

## Arcjet Guard

`arcjet.NewGuardClient` is a lower-level API designed for AI agent tool calls
and background tasks where there is no HTTP request object. It gives you
fine-grained, per-call control over rate limiting, prompt injection detection,
and custom rules. Sensitive-info detection is also exposed via
`GuardSensitiveInfo`, but is currently a no-op (see
[Sensitive information detection](#sensitive-information-detection-1) below).

### How it differs from `NewClient`

| | `NewClient` (request protection) | `NewGuardClient` (guard) |
| --- | --- | --- |
| **Designed for** | HTTP request protection | AI agent tool calls, background jobs |
| **Request object** | Required (`Protect(ctx, r, ...)`) | Not needed |
| **Rule binding** | Rules configured once, input via `Protect` options | Rules configured once, bound with input per invocation |
| **Rate limit key** | IP or `WithCharacteristics` | Explicit key string (SHA-256 hashed before sending) |
| **Custom rules** | Not supported | `GuardCustom` |

### Installation

Guard is part of the same `github.com/arcjet/arcjet-go` module — no extra
install required.

### Quick start

Declare the guard client and each rule once at package scope. Call `guard.Guard`
at each specific operation with a **hardcoded** `Label` so the dashboard groups
calls by what they actually are.

```go
package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/arcjet/arcjet-go"
)

// Single guard client — reused across calls.
var guard = must(arcjet.NewGuardClient(arcjet.GuardConfig{
	Key: os.Getenv("ARCJET_KEY"),
}))

// Rules configured once. Each rule's Bucket groups its counters server-side.
var (
	userLimit = must(arcjet.GuardTokenBucket(arcjet.GuardTokenBucketOptions{
		Mode:       arcjet.ModeLive,
		RefillRate: 100,
		Interval:   time.Minute,
		Capacity:   1000,
		Bucket:     "agent.user-tokens", // distinct from any Label
	}))
	promptScan = must(arcjet.GuardPromptInjection(arcjet.GuardPromptInjectionOptions{Mode: arcjet.ModeLive}))
)

// GetWeather is an agent tool. Guard at the tool function (or at the
// dispatch arm right before calling it) — never in a generic
// handleToolCall(name, args) wrapper with an interpolated label.
func GetWeather(ctx context.Context, userID, message string) error {
	decision, err := guard.Guard(ctx, arcjet.GuardRequest{
		Label: "tools.get_weather", // hardcoded string, not fmt.Sprintf
		Metadata: map[string]string{
			"userId": userID,
		},
		Rules: []arcjet.GuardRuleInput{
			userLimit.Key(userID, 1),
			promptScan.Text(message),
		},
	})
	if err != nil {
		// Guard fails open — log and continue.
		return nil
	}
	if decision.IsDenied() {
		// Use the per-rule accessor to recover details — rate limit reset
		// time, prompt injection signal — so the caller knows WHY.
		if r := userLimit.DeniedResult(decision); r != nil {
			return fmt.Errorf("rate limited — resets at unix %d", r.ResetAtUnixSeconds)
		}
		if promptScan.DeniedResult(decision) != nil {
			return errors.New("input flagged as prompt injection")
		}
		return errors.New("blocked")
	}

	// ... do the work.
	return nil
}
```

> **Note:** The `Label` argument should be a hardcoded string like
> `"tools.get_weather"`, not `fmt.Sprintf("tools.%s", name)`. Hardcoded labels
> stay greppable, and the dashboard groups by them. Interpolation produces a
> sea of distinct-looking entries instead of one bucket per operation.

### Rate limiting

Token bucket, fixed window, and sliding window algorithms are available.
Configure the rule once, then call `.Key(key, requested)` with a key and
optional requested count for each invocation.

Every guard rate-limit rule requires an explicit `Key` at call time. There is
no IP fallback — guard runs where there is no HTTP context. When there is no
per-user context (e.g. a stdio MCP server or a single-tenant worker), pick a
stable identifier such as the deployment name or `"default"` and add a comment
explaining why.

#### Token bucket

```go
userLimit, err := arcjet.GuardTokenBucket(arcjet.GuardTokenBucketOptions{
	Mode:       arcjet.ModeLive,
	RefillRate: 100,         // tokens added per interval
	Interval:   time.Minute, // refill interval
	Capacity:   1000,        // maximum bucket capacity
	Bucket:     "agent.user-tokens",
})

// At call time:
decision, err := guard.Guard(ctx, arcjet.GuardRequest{
	Label: "tools.get_weather",
	Rules: []arcjet.GuardRuleInput{userLimit.Key(userID, 5)},
})
```

#### Fixed window

```go
teamLimit, err := arcjet.GuardFixedWindow(arcjet.GuardFixedWindowOptions{
	Mode:        arcjet.ModeLive,
	Window:      time.Hour,
	MaxRequests: 1000,
	Bucket:      "api.search",
})

decision, err := guard.Guard(ctx, arcjet.GuardRequest{
	Label: "api.search",
	Rules: []arcjet.GuardRuleInput{teamLimit.Key(teamID, 1)},
})
```

#### Sliding window

```go
apiLimit, err := arcjet.GuardSlidingWindow(arcjet.GuardSlidingWindowOptions{
	Mode:        arcjet.ModeLive,
	Interval:    time.Minute,
	MaxRequests: 500,
	Bucket:      "api.query",
})

decision, err := guard.Guard(ctx, arcjet.GuardRequest{
	Label: "api.query",
	Rules: []arcjet.GuardRuleInput{apiLimit.Key(userID, 1)},
})
```

### Prompt injection detection

Use on any untrusted text before it reaches a model or tool argument — and on
tool call *results* when the tool fetches content from untrusted sources.

```go
promptScan, err := arcjet.GuardPromptInjection(arcjet.GuardPromptInjectionOptions{Mode: arcjet.ModeLive})

decision, err := guard.Guard(ctx, arcjet.GuardRequest{
	Label: "tools.get_weather",
	Rules: []arcjet.GuardRuleInput{promptScan.Text(userMessage)},
})

if decision.IsDenied() && decision.Reason == arcjet.ReasonPromptInjection {
	return errors.New("prompt injection detected")
}
```

### Custom rules

Define custom local rules with `GuardCustom`. The evaluation function runs in
your process — Arcjet never executes it. The `Input` map you pass at call time
is submitted to Arcjet alongside the function's `Conclusion` and any opaque
`Data`, so the dashboard can show what the rule saw. Do not pass raw secrets
or unhashed PII through `Input`; hash or redact first if the inputs are
sensitive.

```go
topicRule, err := arcjet.GuardCustom(arcjet.GuardCustomOptions{
	Mode:   arcjet.ModeLive,
	Config: map[string]string{"blocked_topic": "weapons"},
	Func: func(ctx context.Context, input map[string]string) (arcjet.GuardCustomResult, error) {
		if input["topic"] == "weapons" {
			return arcjet.GuardCustomResult{
				Conclusion: arcjet.ConclusionDeny,
				Data:       map[string]string{"matched": input["topic"]},
			}, nil
		}
		return arcjet.GuardCustomResult{Conclusion: arcjet.ConclusionAllow}, nil
	},
})

decision, err := guard.Guard(ctx, arcjet.GuardRequest{
	Label: "content",
	Rules: []arcjet.GuardRuleInput{
		topicRule.Input(map[string]string{"topic": userTopic}),
	},
})
```

### Per-rule results

`decision.Results` contains one entry per rule invocation, with typed result
details for inspection:

```go
for _, result := range decision.Results {
	switch {
	case result.TokenBucket != nil:
		log.Printf("rate limit: %d / %d remaining; resets at %d",
			result.TokenBucket.RemainingTokens,
			result.TokenBucket.MaxTokens,
			result.TokenBucket.ResetAtUnixSeconds)
	case result.PromptInjection != nil:
		log.Printf("prompt injection detected=%v", result.PromptInjection.Detected)
	// case result.LocalSensitiveInfo != nil: ... — currently unreachable;
	// see the Sensitive information detection section above.
	}
	if result.IsDenied() {
		log.Printf("denied by %s", result.Reason)
	}
}
```

### Decision API

```go
decision, err := guard.Guard(ctx, arcjet.GuardRequest{
	Label: "tools.get_weather",
	Rules: []arcjet.GuardRuleInput{userLimit.Key(userID, 5)},
})

// Layer 1: conclusion and reason.
decision.Conclusion // arcjet.ConclusionAllow or arcjet.ConclusionDeny
decision.Reason     // arcjet.ReasonRateLimit, ReasonPromptInjection, etc.

// Layer 2: error detection.
decision.IsErrored() // true if any rule errored or the server reported diagnostics

// Layer 3: per-rule results (see "Per-rule results" above).
for _, result := range decision.Results {
	log.Println(result.Type, result.Conclusion)
}
```

### `Guard` parameter reference

| Field | Type | Description |
| --- | --- | --- |
| `Rules` | `[]arcjet.GuardRuleInput` | Bound rule inputs (required) |
| `Label` | `string` | Hardcoded label identifying this guard call (required) |
| `Metadata` | `map[string]string` | Optional key-value metadata recorded in the dashboard |

### DRY_RUN mode

All guard rules accept a `Mode` parameter. Use `arcjet.ModeDryRun` to evaluate
rules without blocking:

```go
userLimit, err := arcjet.GuardTokenBucket(arcjet.GuardTokenBucketOptions{
	Mode:       arcjet.ModeDryRun,
	RefillRate: 10,
	Interval:   time.Minute,
	Capacity:   100,
	Bucket:     "agent.user-tokens",
})
```

## Best practices

### Single-instance pattern

Create one Arcjet client at startup and reuse it across all handlers:

```go
// Good — one instance, created once at package scope.
var aj = must(arcjet.NewClient(arcjet.Config{Key: arcjetKey, Rules: []arcjet.Rule{...}}))

// Bad — new client per request wastes resources and creates a new HTTP/2
// connection each time.
func handler(w http.ResponseWriter, r *http.Request) {
	aj, _ := arcjet.NewClient(arcjet.Config{...}) // don't do this
}
```

### Shared client in its own package

For larger projects, put the client in its own package (e.g.
`internal/security/arcjet.go`) and import it from handlers. Always include
`Shield` as a base rule, then layer route-specific rules with `WithRule`:

```go
// internal/security/arcjet.go
package security

import (
	"os"

	"github.com/arcjet/arcjet-go"
)

var Client = must(arcjet.NewClient(arcjet.Config{
	Key: os.Getenv("ARCJET_KEY"),
	Rules: []arcjet.Rule{
		arcjet.Shield(arcjet.ShieldOptions{Mode: arcjet.ModeLive}),
		arcjet.DetectBot(arcjet.BotOptions{Mode: arcjet.ModeLive, Allow: []string{}}),
	},
}))
```

```go
// internal/http/chat.go
package http

import (
	"log"
	"net/http"
	"time"

	"github.com/arcjet/arcjet-go"
	"example.com/app/internal/security"
)

// Layer per-route rules without mutating the shared client. WithRule
// validates and pre-builds the rule's wire form, so it returns an error
// for misconfigured rules — keep the call at package scope so a bad rule
// fails at startup instead of on the first request.
var chatClient = must(security.Client.WithRule(arcjet.TokenBucket(arcjet.TokenBucketOptions{
	Mode:            arcjet.ModeLive,
	Characteristics: []string{"userId"},
	RefillRate:      100,
	Interval:        time.Minute,
	Capacity:        1000,
})))

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}
```

`WithRule` returns a copy — the original client is left unchanged, so the same
base instance can be specialised for many routes.

### DRY_RUN mode for testing

Use `arcjet.ModeDryRun` to test rules without blocking traffic. Decisions are
logged but requests are allowed through:

```go
arcjet.DetectBot(arcjet.BotOptions{Mode: arcjet.ModeDryRun, Allow: []string{}})
arcjet.TokenBucket(arcjet.TokenBucketOptions{
	Mode:       arcjet.ModeDryRun,
	RefillRate: 5,
	Interval:   10 * time.Second,
	Capacity:   10,
})
```

### Proxy configuration

When running behind a load balancer or reverse proxy, configure trusted IPs so
Arcjet resolves the real client IP from `X-Forwarded-For`:

```go
aj, err := arcjet.NewClient(arcjet.Config{
	Key:     arcjetKey,
	Rules:   []arcjet.Rule{...},
	Proxies: []string{"10.0.0.0/8", "192.168.0.1"},
})
```

### `Protect` parameter reference

All options are optional and passed alongside the `*http.Request`:

| Option                                     | Used by                                            |
| ------------------------------------------ | -------------------------------------------------- |
| `WithRequested(int)`                       | Token bucket rate limit                            |
| `WithCharacteristic(key, value string)`    | Rate limiting — single key/value                   |
| `WithCharacteristics(map[string]string)`   | Rate limiting (values for keys declared in rules)  |
| `WithDetectPromptInjectionMessage(string)` | Prompt injection detection                         |
| `WithSensitiveInfoValue(string)`           | Sensitive information detection (currently a no-op — see [section](#sensitive-information-detection)) |
| `WithEmail(string)`                        | Email validation                                   |
| `WithFilterLocal(map[string]string)`       | Request filters using `local["field"]` expressions |
| `WithIPSrc(string)`                        | Manual IP override (advanced)                      |
| `WithBody([]byte)`                         | Request body override                              |
| `WithExtra(map[string]string)`             | Additional fields sent to Arcjet                   |

### Decision response

```go
decision, err := aj.Protect(r.Context(), r)

// Top-level checks.
decision.IsDenied()    // true if any LIVE rule denied the request
decision.IsAllowed()   // true if all rules allowed the request
decision.IsErrored()   // true if Arcjet encountered an error (fails open)

// Branch on reason for actionable error responses. Only branch on reasons that
// produce a different response — a SHIELD arm returning 403 when the default
// already returns 403 is dead code.
switch {
case decision.Reason.IsRateLimit():
	log.Println(decision.Reason.RateLimit.Remaining)
case decision.Reason.IsBot():
	log.Println(decision.Reason.Bot.Denied)
}

// Per-rule results.
for _, result := range decision.Results {
	log.Println(result.Reason.Type, result.Conclusion)
}
```

### Error handling

Arcjet is designed to fail open — if the service is unavailable, requests are
allowed through. Check for errors explicitly if your use case requires it:

```go
decision, err := aj.Protect(r.Context(), r)
if err != nil {
	// Arcjet service error — fail open or apply fallback policy.
	log.Printf("arcjet: %v", err)
} else if decision.IsDenied() {
	http.Error(w, "Denied", http.StatusForbidden)
	return
}
```

Configuration and validation errors wrap exported sentinels so they can be
detected with `errors.Is`:

```go
aj, err := arcjet.NewClient(arcjet.Config{Key: ""})
if errors.Is(err, arcjet.ErrMissingKey) {
	log.Fatal("set ARCJET_KEY in your environment")
}
```

Available sentinels: `ErrMissingKey`, `ErrNilClient`, `ErrNilRequest`,
`ErrNilRule`, `ErrInvalidMode`, `ErrAllowDenyConflict`, `ErrInvalidProxy`,
`ErrInvalidLabel`, `ErrInvalidRateLimit`, `ErrEmptyKey`, `ErrMissingFunc`,
`ErrInvalidWasm`, `ErrWasmClosed`, `ErrWasmExportNotFound`, `ErrEmptyResponse`.

Remote and per-rule errors are surfaced as `ArcjetError` values with a `Code`
field. Match a specific server error code with `errors.Is`:

```go
if errors.Is(err, arcjet.ArcjetError{Code: "AJ1100"}) {
	// handle a specific Arcjet error code
}
```

`Decision.Err()` and `GuardDecision.Err()` return the underlying `ArcjetError`
(or `nil`) when the decision errored — useful for bubbling Arcjet errors out
of helpers.

## Verify decisions

After wiring up protection, confirm it is actually firing. There is no shortcut
to seeing a real decision — trigger one, then check the platform.

1. Build and start the app (`go build ./... && ./your-app`).
2. Trigger a real request, e.g. `curl http://localhost:3000/chat`. To trip a
   rate limit, loop the call:
   ```sh
   for i in {1..50}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/chat; done
   ```
   For guard calls, invoke the protected function directly (`go run ./cmd/agent-smoketest`)
   rather than trying to `curl` something — there is no HTTP surface.
3. Confirm the decision via the Arcjet CLI:
   ```sh
   arcjet requests list --site-id <id>   # request protection
   arcjet guards list --site-id <id>     # guard
   arcjet requests explain --site-id <id> --request-id <id>
   ```

The dashboard at [app.arcjet.com](https://app.arcjet.com) shows the same data
with filtering and history.

## Gotchas

- **Wrong client**: `NewClient` is for HTTP routes; `NewGuardClient` is for
  non-HTTP code (tool calls, MCP servers, queue workers, background jobs).
  Using the wrong one is the most common mistake — MCP "servers" don't receive
  HTTP requests, so they use `NewGuardClient`.
- **Wrong placement**: `Protect` belongs inside each handler, not in generic
  middleware that wraps every request including static assets.
- **Wrong layer for `Guard`**: don't put `guard.Guard` in a
  `handleToolCall(name, args)` dispatcher. Put it inside each specific tool
  function (or the dispatch arm right before the call) so the `Label` and
  `Metadata` can be hardcoded.
- **Interpolated labels**: `Label: fmt.Sprintf("tools.%s", name)` defeats the
  dashboard grouping. Use a hardcoded string per tool.
- **Double-counting**: calling `Protect` or `Guard` multiple times for the same
  operation counts against rate limits multiple times.
- **Hardcoded keys**: never hardcode `ARCJET_KEY` — read it from the
  environment. Don't commit it to source.

## Support

This repository follows the [Arcjet Support
Policy](https://docs.arcjet.com/support).

## Security

This repository follows the [Arcjet Security
Policy](https://docs.arcjet.com/security).

## License

Licensed under the [Apache License, Version
2.0](http://www.apache.org/licenses/LICENSE-2.0).
