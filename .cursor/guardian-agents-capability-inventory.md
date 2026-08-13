# Arcjet Go SDK — Guardian Agents capability inventory

**Scope:** This repository only (`github.com/arcjet/arcjet-go`). Facts are taken from shipping public APIs, comments, and vendored protos in this checkout. Features that exist only on Arcjet Cloud, the dashboard, the CLI, or other language SDKs are marked as such and are **not** counted as native Go-SDK capabilities.

**Method:** Read the public constructors, rule builders, Guard surface, local WASM path, redact/rampart modules, examples, and the vendored Decide/Guard protos. Do not invent features. If a capability is not implemented here, it is **Absent**.

**Repo status (maturity):** Public, **pre-release and unstable**. `README.md` line 10: “The Go SDK is pre-release and unstable.” `AGENTS.md` and `doc.go` treat the exported API as a contract but still pre-release. `types.go` `Version = "0.1.0"`. Requires Go 1.25+. Apache-2.0.

**Gartner context (for mapping only):** Market Guide for Guardian Agents (G00836388, Feb 2026). Gartner counts a vendor as in-market only if they natively cover **all three** mandatory categories: (1) AI visibility and traceability, (2) continuous assurances / AI agent posture management, (3) runtime inspection and enforcement. This report maps **what this SDK implements**, not the Arcjet product as a whole.

---

## A) What this repo ships

This is a **runtime security SDK**, not a guardian-agent control plane. It exposes two clients plus two optional sibling modules:

| Artifact | Module | What it is |
| --- | --- | --- |
| Request protection | `github.com/arcjet/arcjet-go` | `arcjet.NewClient` — `net/http` (`*http.Request`) protection |
| Guard protection | same module | `arcjet.NewGuardClient` — non-HTTP calls (documented for AI tool calls, MCP servers, jobs, queues) |
| Redact | `github.com/arcjet/arcjet-go/redact` | In-process detect + redact + unredact; no Arcjet key required |
| On-device NER | `github.com/arcjet/arcjet-go/sensitiveinfo/rampart` | Optional ~15 MB embedded BERT backend for `SensitiveInfo` / `GuardSensitiveInfo` |
| Example | `examples/nethttp/` | Runnable `net/http` server (not in CI gate) |
| Rampart example | `sensitiveinfo/rampart/examples/` | Offline `backend.Detect` demo (no key) |

**Not shipped in this repo**

- No MCP protocol adapter, MCP server wrapper, or MCP SDK types.
- No dedicated “tool authorization” rule type (no allowlist of tool names, no capability/RBAC primitive).
- No agent catalog, maps, ownership registry, or lineage graph.
- No posture-management API.
- No `Capture` / OpenTelemetry event API (present in the vendored v2 proto, **not** wired in the Go client).
- No Guard or MCP example under `examples/`.
- No content-moderation rule on the request (`NewClient`) path; Guard’s content-moderation constructor is **Experimental** and documented as possibly unavailable.

### Public constructors

| API | File | Signature / role |
| --- | --- | --- |
| `NewClient` | `client.go:108` | `func NewClient(cfg Config) (*Client, error)` — HTTP request protection |
| `Client.Protect` | `client.go:406` | `Protect(ctx, *http.Request, ...ProtectOption) (Decision, error)` |
| `Client.ProtectDetails` | `client.go:415` | Same rules against a constructed `ProtectDetails` (non-standard request sources) |
| `Client.WithRule` | `client.go:209` | Copy of the client plus one extra rule (does not mutate the base) |
| `Client.Close` | `client.go:238` | Releases local WASM |
| `NewGuardClient` | `guard.go:57` | `func NewGuardClient(cfg GuardConfig) (*GuardClient, error)` — no HTTP request |
| `GuardClient.Guard` | `guard.go:132` | `Guard(ctx, GuardRequest) (GuardDecision, error)` |
| `GuardClient.Close` | `guard.go:87` | Releases lazy WASM if compiled |
| `redact.New` | `redact/redact.go:93` | Compiles redact WASM once; reuse across calls |
| `rampart.New` | `sensitiveinfo/rampart/rampart.go` | Loads embedded NER weights once |

`doc.go` states the intended split: `NewClient` inside each HTTP handler; `NewGuardClient` at each non-HTTP operation with a **hardcoded** `Label` such as `"tools.get-weather"`.

---

## B) Architecture (Guard vs request; in-process vs remote)

### Two clients, two wire protocols

```
┌─ NewClient (request) ─────────────────────────────────────────┐
│  local WASM (eager): bot, email, filter, sensitive-info,      │
│                      fingerprint for cache                    │
│  live local DENY → skip Decide, background Report (v1alpha1)  │
│  otherwise → Connect RPC Decide (v1alpha1)                    │
│  cache: only enforced DENY with TTL>0                         │
└───────────────────────────────────────────────────────────────┘

┌─ NewGuardClient (guard) ──────────────────────────────────────┐
│  local (lazy WASM): GuardSensitiveInfo, GuardCustom           │
│  remote: rate limits, prompt injection, experimental          │
│          content moderation                                   │
│  always → Connect RPC Guard (v2)                              │
│  no local short-circuit cache                                 │
└───────────────────────────────────────────────────────────────┘
```

| | `NewClient` | `NewGuardClient` |
| --- | --- | --- |
| Designed for | HTTP handlers / anything with `*http.Request` | Tool calls, MCP (stdio/SSE), jobs, queues |
| Request object | Required (`Protect`) or `ProtectDetails` | None |
| Wire | Decide + Report, proto `v1alpha1` (`client.go`, `internal/proto/decide/v1alpha1/`) | Guard only, proto `v2` (`guard.go`, `internal/proto/decide/v2/`) |
| User-Agent product | `arcjet-go` | `arcjet-guard-go` |
| Rate-limit key | IP by default, or `Characteristics` | Explicit `Key` (SHA-256 hashed); no IP fallback |
| Custom rules | Not supported | `GuardCustom` |
| Bot / Shield / Email / Filter | Yes | No |
| Prompt injection | Remote (text in Decide `extra`) | Remote (`inputText` on the Guard rule) |
| Sensitive info | Local; raw text never sent | Local; only SHA-256 hash + computed result sent |
| Fail-open | Transport error → `err != nil`, caller continues | Transport error → usable `ALLOW` + synthetic `TRANSPORT_ERROR` + `HasFailedOpen()` |

Endpoints (`client.go:28-31`, `defaultBaseURL` at `client.go:879`): `https://decide.arcjet.com`, or `https://fly.decide.arcjet.com` when `FLY_APP_NAME` / `FLY_REGION` is set, or `ARCJET_BASE_URL` / `Config.BaseURL`.

Connect routes are hand-pinned (`internal/proto/decide/v1alpha1/decidev1alpha1connect/decide.connect.go`, `.../v2/decidev2connect/decide.connect.go`):

- `/proto.decide.v1alpha1.DecideService/Decide`
- `/proto.decide.v1alpha1.DecideService/Report`
- `/proto.decide.v2.DecideService/Guard`

The v2 proto also defines `Capture` (`internal/proto/decide/v2/decide.pb.go` `CaptureEvent` / `CaptureRequest`, comments at 2532–2583). The Go v2 Connect client **only implements `Guard`**. There is no public `Capture` method.

### Local vs remote by rule

| Rule | Where it evaluates | Evidence |
| --- | --- | --- |
| Shield | Remote (Decide) | `rules.go:202` — wire only, no `local` func |
| Rate limit (request) | Remote (Decide); DENY cacheable | `rules.go` TokenBucket/FixedWindow/SlidingWindow; `cache.go` |
| Bot | Local WASM first; live DENY short-circuits | `rules.go:247` `evaluator.detectBot`; `local_decision.go:168` |
| Email | Local WASM first | `rules.go:292` `evaluator.validateEmail` |
| Filter | Local WASM; `WithFilterLocal` never sent to Cloud | `rules.go:427`; `client.go:372-376` |
| Sensitive info (request) | Local WASM or `Backend`; value not put on Decide/Report | `client.go:446-449`; `local_decision.go:246` |
| Prompt injection (request) | Remote; message in `extra["detectPromptInjectionMessage"]` | `client.go:443-445`; Report redacts it (`client.go:644-669`) |
| Guard rate limits | Remote | `guard.go` Key() sends hashed key |
| Guard prompt injection | Remote; raw `inputText` sent | `guard.go:618-624` |
| Experimental content moderation | Remote; raw `inputText` sent | `guard.go:704-710` |
| Guard sensitive info | Local; hash + result submitted | `guard.go:827-870` |
| Guard custom | Local `Func`; Input + Conclusion + Data submitted | `guard.go:957-980` |
| `redact` | Entirely in-process | `redact/redact.go` package comment |
| Rampart | Entirely in-process | `sensitiveinfo/rampart/README.md` |

### WASM / Wazero

- Runtime: `github.com/tetratelabs/wazero v1.12.0` (`go.mod`).
- Analyze component: `internal/local/jsreq/` — same `arcjet_analyze_js_req` world as `@arcjet/analyze-wasm` (JS) and `arcjet._analyze` (Python). Go vendors the **wizer’d core** wasm because wazero speaks core wasm, not the Component Model (`docs/LOCAL_WASM_EVALUATION.md`).
- Redact component: `internal/local/redact/` — same `arcjet:redact` world as `@arcjet/redact` / `arcjet.redact`.
- Lifecycle: factory compiled once; **fresh instance per call** (`local_decision.go:342-355`). `NewClient` compiles eagerly if any rule exists (`local_decision.go:49-72`); `NewGuardClient` is lazy (`guard.go:79-81`).
- Public `WasmModule` (`wasm.go`) is a raw wazero helper; “Most applications do not need this type.”
- Host callbacks default to fail-open (`docs/LOCAL_WASM_EVALUATION.md` table): unset email/bot/filter/sensitive-info imports never tip a decision to deny.

### Decision cache (request path only)

`cache.go`: per-rule cache keyed by `(ruleID, WASM fingerprint)`. Stores only `CONCLUSION_DENY` + `RULE_STATE_RUN` + TTL > 0. Mirrors arcjet-js. Guard has no equivalent cache.

### Fail-open / fail-closed

- Default product posture: **fail open** (`doc.go:23-24`, `README.md` Error handling).
- Guard transport failure returns `ALLOW` + `HasFailedOpen() == true` so a caller can fail closed (`guard.go:125-131`, `wire_guard.go:99-111`).
- Programmer errors (nil client, bad label, nil rule) return zero decision + error; not fail-open.

---

## C) Capability inventory (with file pointers)

### C.1 Request rules (`NewClient`)

All builders are in `rules.go`. `Rule` is an unexported-method interface (`rules.go:14-30`); only SDK constructors can implement it.

| Primitive | Constructor | Options | Local? | Notes |
| --- | --- | --- | --- | --- |
| Token bucket | `TokenBucket` `rules.go:81` | Mode, Characteristics, RefillRate, Interval, Capacity | No | AI token budgets via `WithRequested` |
| Fixed window | `FixedWindow` `rules.go:124` | Mode, Characteristics, Window, MaxRequests | No | |
| Sliding window | `SlidingWindow` `rules.go:165` | Mode, Characteristics, Interval, MaxRequests | No | |
| Shield WAF | `Shield` `rules.go:202` | Mode, Characteristics | No | SQLi/XSS/path traversal — analyzed remotely |
| Bots | `DetectBot` `rules.go:235` | Mode, Allow **xor** Deny | Yes | Empty Allow = block all detected bots. Categories in `constants.go` |
| Email | `ValidateEmail` `rules.go:278` | Mode, Allow/Deny types, TLD/domain-literal flags | Yes | Types: DISPOSABLE, FREE, INVALID, NO_MX_RECORDS, NO_GRAVATAR |
| Sensitive info | `SensitiveInfo` `rules.go:334` | Mode, Allow/Deny entities, optional Backend | Yes | Text via `WithSensitiveInfoValue` |
| Prompt injection | `DetectPromptInjection` `rules.go:385` | Mode only | No | “Arcjet no longer exposes a prompt injection threshold” (`rules.go:377-378`) |
| Filter | `Filter` `rules.go:415` | Mode, Allow **xor** Deny expressions | Yes | IP/path/headers/`local["…"]` |
| Signup bundle | `ProtectSignup` `rules.go:459` | Sliding window + bots + email | mixed | Sugar; mirrors JS `protectSignup` |

**Modes** (`types.go:16-21`): `ModeDryRun` (“DRY_RUN”), `ModeLive` (“LIVE”). Empty mode normalizes to dry-run (`types.go:23-27`).

**Per-call options** (`client.go:326-403`): `WithRequested`, `WithCharacteristic(s)`, `WithDetectPromptInjectionMessage`, `WithSensitiveInfoValue`, `WithEmail`, `WithIPSrc`, `WithFilterLocal`, `WithBody`, `WithExtra`, `WithCorrelationId`, `WithMetadata`.

**IP / platform** (`platform.go`, `client.go:782-824`): trusted `Config.Proxies`; auto-detect Firebase, Fly.io, Vercel, Render, Cloudflare Pages (`CF_PAGES`), Railway. Explicit `Config.Platform` for Cloudflare CDN origins. `decision.IP` carries geo, ASN, VPN/proxy/Tor/hosting/relay, optional `ThreatIntelligence` (`types.go:447-487`).

**Rate-limit headers:** `SetRateLimitHeaders` (`headers.go:23`) writes IETF draft `RateLimit` / `RateLimit-Policy`.

### C.2 Guard rules (`NewGuardClient`)

All in `guard.go`. Each rule is configured once; bound per call via `.Key` / `.Text` / `.Input`. Accessors: `Result`, `DeniedResult`, `ErrorResult` (correlated by `ConfigID`).

| Primitive | Constructor | Bind | Eval |
| --- | --- | --- | --- |
| Token bucket | `GuardTokenBucket` `guard.go:319` | `.Key(key, requested)` | Remote; `inputKeyHash` |
| Fixed window | `GuardFixedWindow` `guard.go:425` | `.Key` | Remote |
| Sliding window | `GuardSlidingWindow` `guard.go:522` | `.Key` | Remote |
| Prompt injection | `GuardPromptInjection` `guard.go:610` | `.Text(text)` | Remote; sends raw text |
| Content moderation | `ExperimentalGuardModerateContent` `guard.go:696` | `.Text(text)` | Remote; **experimental**, may error / fail open |
| Sensitive info | `GuardSensitiveInfo` `guard.go:777` | `.Text(text)` | Local; hash + result |
| Custom | `GuardCustom` `guard.go:912` | `.Input(map[string]string)` | Local `Func`; Input/Config/Data go to Cloud |

`GuardRequest` (`guard.go:95-116`): required `Label` + `Rules`; optional `Metadata`, `CorrelationId`.

Label rules (`guard.go:1021-1038`): required, ≤256 bytes, `[a-z0-9][a-z0-9.-]*[a-z0-9]`. README forbids interpolating tool names.

Rate-limit keys are hashed (`guard.go:989-1012`); empty key is `ErrEmptyKey`. Bucket names default to `"default"` and must be label-like slugs.

### C.3 Sensitive info — detect

**Bundled WASM analyzer** (no extra module): `EMAIL`, `PHONE_NUMBER`, `IP_ADDRESS`, `CREDIT_CARD_NUMBER` (`constants.go:50-54`).

**Custom detect callback:** `Config.SensitiveInfoDetect` / `GuardConfig.SensitiveInfoDetect` (`client.go:58-71`) — one `EntityType` per token; empty = unclassified. Same hook model as JS/Python.

**Pluggable backend:** `SensitiveInfoBackend` (`sensitive_info_backend.go:23-33`). Rampart implements it.

**Rampart entities** (`constants.go:56-71`, `sensitiveinfo/rampart/README.md`): names, URL, SSN, tax/bank/gov IDs, passport, driver’s license, address parts. Default `MaxInputChars = 4096` (JS/Python default 100_000 — documented Go-only tightness). Listing a non-native type without a backend or custom detect is `ErrUnsupportedEntityType`.

Allow and Deny are mutually exclusive. Deny-list blocks listed types; allow-list blocks everything except listed types.

### C.4 Sensitive info — redact

`github.com/arcjet/arcjet-go/redact` (`redact/redact.go`):

- In-process; text never sent to Arcjet.
- Same WASM as `@arcjet/redact` and `arcjet.redact` — “all three SDKs redact identically.”
- Built-in entities: `email`, `phone-number`, `ip-address`, `credit-card-number` (string names, not the `EntityType` constants).
- `Options.Detect` / `Options.Replace` / `Options.Entities` / `ContextWindowSize`.
- Returns `(redacted, Unredact, error)` so a prompt can be scrubbed and values restored in the model response.
- Independent of `NewClient` / `NewGuardClient`. Does not enforce; it transforms text.

### C.5 Prompt injection behavior

- **Request:** `DetectPromptInjection` + `WithDetectPromptInjectionMessage`. Text is sent to Decide in `extra`. Report telemetry redacts it to `"<redacted>"` (`client.go:644-669`).
- **Guard:** `GuardPromptInjection.Text(text)` sends `detectPromptInjection.inputText` on the v2 Guard RPC. **Not redacted** on the Guard path (unlike Report).
- Result (request): `PromptInjectionReason{Detected, TotalTokens}` (`types.go:424-428`). Proto v1 also has `Score`; the Go public type does **not** expose score or threshold.
- Result (Guard): `GuardPromptResult{Conclusion, Detected, Billing}` (`wire_guard.go:177-182`). Billing unit `tokens`.
- No local WASM analyzer for prompt injection. No per-rule threshold. Mode is the only control (live vs dry-run).
- README recommends scanning untrusted tool **results** as well as inputs (`README.md` ~1085-1086). That is a usage pattern, not a separate API.

### C.6 “Tool authorization”

**There is no `AuthorizeTool`, tool-name allowlist, or MCP tool-schema rule.**

What exists:

1. Marketing copy: “authorize agent tool calls” (`README.md:12`).
2. Placement guidance: call `Guard` **inside each tool function** (or the dispatch arm immediately before it), never in a generic `handleToolCall(name, args)` wrapper (`README.md` Gotchas; `doc.go:16-18`).
3. `GuardCustom` — caller-supplied `func(ctx, map[string]string) (GuardCustomResult, error)` can return `ConclusionDeny`. That is a local hook, not a productized tool-auth policy.
4. Rate-limit / prompt-injection / sensitive-info at the tool site.

“Authorize” in this SDK means **the application calls Guard before the tool runs and honors `IsDenied()`**. It does not mean a built-in tool-permission graph.

### C.7 MCP

MCP appears only as a **documented use case**:

- `doc.go:13-21`, `README.md` feature table and Guard section, `AGENTS.md`.
- Rationale: MCP tool calls run over stdio/SSE, so there is no `*http.Request` → use `NewGuardClient`.
- For stdio / single-tenant workers, pick a stable rate-limit key (deployment name or `"default"`).

**Absent:** MCP types, stdio/SSE transport, tool-list introspection, session identity, resource/prompt guards, example server.

### C.8 Logging, audit, decision reasons

**SDK logging:** The SDK **does not take a logger**. `client.go:509-510`: “arcjet-js and arcjet-py log instead; the Go SDK takes no logger, so the decision carries [warnings].” Enums implement `slog.LogValuer` (`types.go`) so *callers* can log them. Rampart backends receive `slog.Default()` (`sensitive_info_backend.go:157-160`).

**Decision identity / reasons (request):** `Decision` (`types.go:243-256`) — `ID`, `Conclusion` (ALLOW/DENY/CHALLENGE/ERROR), typed `Reason`, per-rule `Results`, `TTL`, `IP`, `Warnings`. Helpers: `IsDenied`, `IsAllowed`, `IsChallenged`, `IsErrored`, `IsSpoofedBot`, `IsVerifiedBot`, `IsMissingUserAgent`.

**Decision identity / reasons (Guard):** `GuardDecision` (`wire_guard.go:64-73`) — `ID`, `Conclusion`, `Reason`, `Results`, `Warnings`. `HasFailedOpen`, `ErrorResults`, `Err`. Per-rule typed payloads (tokens remaining, PI detected, SI entity types, custom data).

**Correlation (not a catalog):**

- `CorrelationId` — opaque, ≤256 bytes printable ASCII; excluded from cache key; stored with the recorded decision so a chain of Protect/Guard calls can be reconstructed (`client.go:272-279`, `guard.go:108-113`, proto comment `decide.pb.go:2361-2368`).
- `Metadata` — JSON-serializable map for analytics; **does not affect the decision**; untrusted, not redacted (`metadata.go:16-24`).
- `Label` — hardcoded slug for dashboard grouping.

**What is reported to Cloud:**

- Request: every Decide call; local live DENY also `Report`s (prompt-injection text redacted).
- Guard: every `Guard` call (local SI/custom results included).
- README “Verify decisions”: `arcjet requests list` / `arcjet guards list` / `arcjet requests explain`, and `app.arcjet.com`. Those are **CLI/dashboard**, not this module.

**Not implemented here:** tamper-evident hash chain, signed audit log, WORM store, agent catalog, ownership, data-lineage graph, compliance report export, `Capture` events, OTLP conversion (proto comments mention `"otlp"` as a Capture `source`; Go does not implement it).

### C.9 Examples

| Path | Covers |
| --- | --- |
| `README.md` Quick start | HTTP chat: PI + token bucket + bots + Shield |
| `README.md` Guard section | Conceptual `GetWeather` tool with rate limit + PI |
| `examples/nethttp/` | Shield + bots + token bucket + SensitiveInfo + Rampart NER. **No** prompt injection, **no** Guard, **no** MCP |
| `sensitiveinfo/rampart/examples/` | Offline Rampart `Detect` |

### C.10 Parity vs JS/Python (only what this repo states)

Documented **shared** behavior:

- Same analyze WASM world → identical local bot/email/filter/SI decisions (`docs/LOCAL_WASM_EVALUATION.md`).
- Same redact WASM → identical redaction (`redact/redact.go`).
- Fingerprint export matches JS byte-for-byte (`local_decision.go:112-115`).
- Cache policy, `protectSignup`, `setRateLimitHeaders`, `@arcjet/inspect` bot helpers, `@arcjet/ip` platform detection — explicitly mirrored.

Documented **differences** (Go vs JS/Python):

| Topic | This repo says |
| --- | --- |
| Metadata key order | Go sorts keys; JS/Python preserve insertion order (`README.md` ~1315-1318, `metadata.go:148`) |
| Metadata numbers | Go keeps exact `int64`; JS is float64 on the wire (`metadata_test.go:58`) |
| Warnings | JS/Python log dropped metadata keys; Go has no logger and puts them on the decision (`client.go:509-510`) |
| Railway platform | Go detects Railway; “Railway is not detected by the JS SDK” (`platform.go:68-69`) |
| Analyze WASM flavor | Go: wizer’d core (no Edge size cap). JS: no-Wizer for Vercel Edge bundle size (`docs/LOCAL_WASM_EVALUATION.md`) |
| Rampart `MaxInputChars` | Go default 4096 vs JS/Python 100_000 (`sensitiveinfo/rampart/rampart.go:45-52`) |
| Rampart span merge | Precedence “differs deliberately from arcjet-js” (`sensitiveinfo/rampart/spans.go:125-126`) |

**Not claimed in this repo:** feature-complete parity of every JS package (`@arcjet/next`, adapters, Nosecone, etc.). Those packages are not present here.

### C.11 Beta vs GA

| Surface | Maturity in this repo |
| --- | --- |
| Module as a whole | Pre-release, unstable, `Version = "0.1.0"` |
| Request rules (Shield, bots, rate limit, email, filter, SI, PI) | Shipped public API; no “experimental” marker |
| Guard rate limit / PI / SI / custom | Shipped public API; no “experimental” marker |
| `ExperimentalGuardModerateContent` | Explicitly experimental; “may not be available yet”; errors fail open (`guard.go:661-695`) |
| Rampart | Optional separate module; shipping, not marked experimental |
| `Capture` RPC | In vendored proto only; **not** a Go API |
| Content moderation on `NewClient` | **Absent** |

---

## D) Mapping to Gartner mandatory + common features

Ratings apply to **this Go SDK**, not to Arcjet Cloud or other SDKs.

**Native** = first-class, documented, implemented here.  
**Partial** = a related primitive exists but does not cover the Gartner meaning.  
**Absent** = no implementation in this repo.

### Mandatory 1 — AI visibility and traceability

Gartner sub-parts: agent catalog, maps, ownership + lineage, tamper-evident audit trails.

| Sub-capability | Rating | Evidence |
| --- | --- | --- |
| Agent catalog | **Absent** | No inventory, registration, or discovery of agents/tools. `Label` is a per-call string, not a catalog. |
| Maps (agent/tool topology) | **Absent** | No graph, dependency map, or topology API. |
| Ownership | **Absent** | No owner/team fields. `Metadata` can carry arbitrary JSON if the app puts it there; the SDK does not model ownership. |
| Lineage | **Partial** | `CorrelationId` is documented as reconstructing a chain of Protect/Guard calls (`client.go:272-279`, proto `decide.pb.go:2361-2368`). That is call-correlation, not data/model/agent lineage. |
| Tamper-evident audit trails | **Absent** | Decisions have IDs and are reported to Cloud. No hash chain, signature, immutability proof, or local audit log. `Capture` (proto-only) is not exposed. |
| **Category overall** | **Partial** | Observability hooks (label, metadata, correlation, decision IDs, CLI/dashboard *mentioned*) exist. Catalog, maps, ownership, and tamper-evident audit do **not**. |

### Mandatory 2 — Continuous assurances (AI agent posture management)

| Sub-capability | Rating | Evidence |
| --- | --- | --- |
| Agent posture management | **Absent** | No inventory of agents, no posture score, no continuous assessment of agent config/permissions/tools, no drift detection. |
| Continuous assurance loop | **Absent** | `ModeDryRun` evaluates rules without blocking; that is rule testing, not posture management. |
| **Category overall** | **Absent** | |

### Mandatory 3 — Runtime inspection and enforcement

Gartner sub-parts: agent alignment, anomaly detection, runtime adaptation.

| Sub-capability | Rating | Evidence |
| --- | --- | --- |
| Runtime enforcement (generic) | **Native** | `Protect` / `Guard` allow or deny before the action. LIVE vs DRY_RUN. Caller must honor `IsDenied()`. |
| Agent alignment | **Partial** | Prompt-injection detection (request + Guard) is a remote alignment check on **text**. Experimental content moderation (Guard only, may be unavailable). No goal/policy/trajectory alignment, no tool-argument schema alignment product. |
| Anomaly detection | **Absent** (as agent-behavior anomaly) | No agent-trajectory or tool-sequence anomaly API. Related but different: bot detection, IP threat intel, rate limits — request-abuse controls, not guardian-agent anomaly. |
| Runtime adaptation | **Absent** | No automatic policy mutation, no adaptive thresholds, no self-tuning. Mode is static config. Fail-open vs fail-closed is a **caller** choice (`HasFailedOpen`). |
| **Category overall** | **Partial** | Strong runtime **enforcement** of configured rules. Does not natively cover alignment + anomaly + adaptation as Gartner lists them. |

### Common features

| Feature | Rating | Evidence |
| --- | --- | --- |
| Identity discovery | **Partial** | Request: client IP (proxies/platforms), bot verified/spoofed, IP geo/ASN/VPN/Tor/hosting, optional threat intel. Guard: caller-supplied key/metadata only — no agent or MCP identity discovery. |
| Data mapping / lineage | **Partial** | SI detect returns entity type + byte offsets (`IdentifiedEntity`, `types.go:411-416`). Redact maps originals ↔ placeholders. No dataset/map/lineage product. |
| Security testing | **Absent** | No DAST/red-team/agent-abuse test harness. `ModeDryRun` is not security testing. Rampart has adversarial unit tests (`sensitiveinfo/rampart/adversarial_test.go`) — engineering tests, not a customer feature. |
| Risk / control validation | **Partial** | Dry-run + typed reasons + per-rule results + `HasFailedOpen` let an app validate controls at runtime. No control-framework mapping or attestation API. |
| Compliance reporting | **Absent** | No report generator, evidence pack, or framework mapping in this repo. Dashboard/CLI are out of scope. |
| Automatic blocking | **Native** | `ModeLive` + `IsDenied()` is the intended block path. Shield/bots/rate-limit/PI/SI/filter/custom can all deny. **Caller must enforce** — the SDK does not wrap the handler or abort the tool by itself. |
| Autoremediation | **Absent** | No auto-revoke, quarantine, or ticket. `redact` is a transform the caller applies. Fail-open is the opposite of auto-remediate. |
| Continuous compliance | **Absent** | No continuous control monitoring or compliance posture. |

### Gartner in-market bar (this SDK alone)

Gartner requires **native coverage of all three mandatory categories**. On the evidence in this repo:

- Cat 1 visibility/traceability: **Partial** (hooks, not catalog/maps/ownership/tamper-evident audit)
- Cat 2 continuous assurances / posture: **Absent**
- Cat 3 runtime inspection/enforcement: **Partial** (enforcement yes; alignment/anomaly/adaptation incomplete)

**This repository, by itself, does not meet the Gartner in-market bar.** It is a runtime rule-evaluation SDK. Whether Arcjet the *vendor* meets the bar depends on Cloud/dashboard/other products, which are not in this checkout.

---

## E) Agent / MCP / tool-call surface in detail

### What the SDK actually gives an agent author

1. Create one `GuardClient` at process start (`NewGuardClient`).
2. Create each rule once (`GuardTokenBucket`, `GuardPromptInjection`, `GuardSensitiveInfo`, `GuardCustom`, …).
3. Inside a **specific** tool function, call `guard.Guard(ctx, GuardRequest{ Label: "tools.get-weather", Metadata: …, CorrelationId: …, Rules: []GuardRuleInput{ userLimit.Key(userID, n), promptScan.Text(message), si.Text(message) } })`.
4. If `IsDenied()`, do not run the tool. Optionally inspect `DeniedResult` for reset time / PI / SI types.
5. If `HasFailedOpen()`, optionally refuse (fail closed) for sensitive tools.

That is the entire agent/MCP integration model. It is **library-in-the-call-path**, not a sidecar, proxy, or MCP middleware.

### MCP

| Question | Answer |
| --- | --- |
| Does the SDK speak MCP? | No |
| Does it wrap MCP servers? | No |
| Does it list/authorize MCP tools? | No |
| Why is MCP mentioned? | MCP I/O is not HTTP, so `NewClient` cannot be used; `NewGuardClient` can |
| Example? | None in `examples/` |

### Tool-call authorization (precise)

| Mechanism | Present? |
| --- | --- |
| Dedicated tool-auth rule | No |
| Allow/deny by tool name | Only if the app encodes it in `GuardCustom` or skips the `Guard` call |
| Argument schema / capability tokens | No |
| Human-in-the-loop approval | No |
| Rate-limit a tool | Yes — Guard rate-limit `.Key` |
| Scan tool input/output for PI | Yes — `GuardPromptInjection.Text` (remote) |
| Scan tool input/output for PII | Yes — `GuardSensitiveInfo.Text` (local) |
| Dashboard grouping by tool | Yes — hardcoded `Label` |
| Correlate a request → tool chain | Yes — `CorrelationId` (storage is Cloud-side) |

### Prompt injection on the agent path

- Remote model (Decide/Guard service). Raw text leaves the process on Guard (and on request Decide).
- Binary `Detected` + billing tokens. No score, no threshold, no category of injection.
- Dry-run still evaluates and records; LIVE can deny the Guard call.

### What works without HTTP

Everything on `NewGuardClient`: rate limits, prompt injection, experimental content moderation, local SI, custom rules, metadata, correlation. Also `redact` and Rampart `Detect` (no key).

What does **not** work without HTTP: Shield, bots, email, filters, request IP analysis, `SetRateLimitHeaders`, `Protect`/`ProtectDetails` (unless the app fabricates `ProtectDetails`).

---

## F) Gaps vs Gartner in-market bar; Go-only gaps vs JS

### F.1 Gaps vs Gartner in-market (this SDK)

These are **Absent** or only **Partial** relative to the three mandatory categories plus common features:

1. **No agent catalog, maps, or ownership model.** Labels are free-form slugs.
2. **No tamper-evident audit.** Decision reporting is telemetry to Cloud, not an audit product in this repo. `Capture` is proto-only.
3. **No AI agent posture management** (the entire second mandatory category).
4. **No agent-behavior anomaly detection** and **no runtime adaptation**.
5. **Alignment is prompt-injection (and experimental moderation), not agent-goal/trajectory alignment.**
6. **No MCP-native control.** MCP is a comment, not an integration.
7. **No productized tool authorization** (permissions, schemas, approval).
8. **No compliance reporting, continuous compliance, security testing product, or autoremediation.**
9. **Enforcement is cooperative.** The SDK returns a decision; the application must block. There is no mandatory interceptor.
10. **Fail-open by default** — a Guardian-Agent “always enforce” story requires the caller to check `HasFailedOpen()` (Guard) or `err` (Protect).

### F.2 Go-only gaps vs JS (stated in this repo, plus surfaces JS comments imply)

**Stated in-repo:**

- No SDK logger (JS/Python log metadata drops).
- Metadata key survival under size limits differs (sorted vs insertion order).
- Rampart default scan ceiling is much lower (4096 vs 100_000) because inference is pure Go, not ONNX Runtime.
- Analyze WASM is a larger wizer’d core (intentional; not a feature gap).

**Present in vendored proto / comments but not exposed in Go:**

- **`Capture` RPC** and OTLP-sourced events (`decide.pb.go` CaptureEvent `source`: `"sdk"` / `"otlp"`). Go Connect client does not implement `Capture`. If JS/Python expose `capture()`, that is a Go gap for visibility/audit.
- **`ExperimentalGuardModerateContent`** is the only content-moderation constructor; it is experimental and documented as possibly returning errors. No request-path moderation rule.
- **Prompt-injection score/threshold:** v1 proto has `Score` / `Threshold`; Go public API dropped both (`rules.go:377-378`, `types.go:424-428`).
- **No Guard example** and **no framework adapters** in this repo (JS has Next/Node/etc. adapters; this repo has one `net/http` example).
- **Custom rules are Guard-only** (`README.md` feature table). Request `NewClient` cannot run `GuardCustom`.
- **Railway detection** is a Go *addition* vs JS, not a gap.

**Not asserted:** This inventory does not fetch arcjet-js or arcjet-py. Any JS feature not mentioned in this repo is out of scope.

---

## Appendix — file index

| Path | Role |
| --- | --- |
| `doc.go` | Package contract: NewClient vs NewGuardClient, fail-open |
| `README.md` | Public feature matrix, examples, Guard docs |
| `types.go` | Version, Mode, Decision, Reason, IP, conclusions |
| `constants.go` | Bot categories, email types, SI entity types |
| `rules.go` | All request rule constructors |
| `client.go` | NewClient, Protect, Decide/Report, options |
| `guard.go` | NewGuardClient, all Guard rules, label/key hashing |
| `wire_guard.go` | GuardDecision / per-rule result types |
| `wire_decide.go` | Request Decision decoding |
| `local_decision.go` | WASM evaluator: bot, email, filter, SI, fingerprint |
| `cache.go` | Per-rule DENY cache |
| `metadata.go` | Metadata encode/limits |
| `headers.go` | RateLimit headers |
| `platform.go` | Hosting-platform IP |
| `errors.go` | Sentinels |
| `wasm.go` | Raw wazero helper |
| `sensitive_info_backend.go` | Backend interface + validation |
| `redact/redact.go` | Public redact API |
| `sensitiveinfo/rampart/` | Optional NER backend |
| `docs/LOCAL_WASM_EVALUATION.md` | WASM architecture + JS/Py parity |
| `examples/nethttp/` | Only HTTP example |
| `internal/proto/decide/v1alpha1/` | Request Decide/Report proto |
| `internal/proto/decide/v2/` | Guard (+ unused Capture) proto |
| `internal/local/jsreq/` | Analyze WASM bindings |
| `internal/local/redact/` | Redact WASM bindings |

---

*Inventory date: 2026-08-13. Source: this checkout of `github.com/arcjet/arcjet-go`. No product code was changed for this report.*
