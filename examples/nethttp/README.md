# Arcjet Go SDK example — `net/http`

A minimal HTTP server built on the Go standard library and protected by the
Arcjet Go SDK.

`GET /` runs the request through:

- **Shield** — common attacks (SQLi, XSS, path traversal).
- **Bot detection** — allows verified search engines, blocks everything else.
- **Token bucket rate limiting** — refills 5 tokens every 10 seconds, capacity
  10; each request deducts 5 tokens (so the third request inside 10 seconds is
  rate-limited).

`POST /submit` additionally runs:

- **Sensitive information detection** — scans the request body for emails and
  credit card numbers and rejects it if any are present. The body is analyzed
  locally by a bundled WebAssembly component and is never sent to Arcjet.

`POST /submit-ner` runs the same sensitive-information rule but with the
optional **on-device NER backend**
([`sensitiveinfo/rampart`](../../sensitiveinfo/rampart)):

- It runs a quantized named-entity-recognition model embedded in the binary, so
  it detects many more entity types — names, addresses, SSNs, tax and
  government IDs, and more — while still keeping the scanned text in-process.
- The model is loaded once at startup with `rampart.New` and shared across
  requests. Loading dequantizes the weights and is relatively expensive, so it
  happens before the server starts listening.
- The response reports each detection's type, byte offsets, and the exact
  matched text.

## Setup

Copy `example.env` to `.env.local` and set your Arcjet site key:

```sh
cp example.env .env.local
# edit .env.local and set ARCJET_KEY
```

Then run the server. There is no built-in env-file loader in the Go standard
library — either export the variables or use `env`:

```sh
set -a && source .env.local && set +a
go run .
```

Or, in one line:

```sh
env $(grep -v '^#' .env.local | xargs) go run .
```

The server listens on `:3000`.

## Try it

```sh
# Allowed.
curl 'http://localhost:3000/'

# Trip the rate limit (3+ requests within 10 seconds).
for i in {1..5}; do curl -s -o /dev/null -w "%{http_code}\n" 'http://localhost:3000/'; done

# Submit a clean body — accepted.
curl -X POST 'http://localhost:3000/submit' --data 'Hello, this is my feedback.'

# Submit a body containing an email — rejected with the detected entity types.
curl -X POST 'http://localhost:3000/submit' --data 'Reach me at alice@example.com'

# Scan with the on-device NER backend — detects names, cities, SSNs, and more.
curl -X POST 'http://localhost:3000/submit-ner' \
  --data 'My name is Sarah Connor, I live in London, SSN 123-45-6789, sarah@example.com'
```

The `/submit-ner` request above returns each detection with its type, offsets,
and matched text:

```json
{
  "error": "Sensitive information detected",
  "detected": [
    { "type": "GIVEN_NAME", "start": 11, "end": 16, "match": "Sarah" },
    { "type": "SURNAME", "start": 17, "end": 23, "match": "Connor" },
    { "type": "CITY", "start": 35, "end": 41, "match": "London" },
    { "type": "SSN", "start": 53, "end": 64, "match": "123-45-6789" },
    { "type": "EMAIL", "start": 75, "end": 92, "match": "sarah@example.com" }
  ]
}
```

The denied responses include the reason on `decision.reason` so you can see
which rule fired; the `/submit` sensitive-info rejection lists the `detected`
entity types, and `/submit-ner` lists the matched spans shown above.

## Behind a proxy?

If you're running behind a load balancer or reverse proxy, set
`Config.Proxies` so Arcjet trusts the right `X-Forwarded-For` hops. See the
[main README](../../README.md#proxy-configuration).
