# Arcjet Go SDK example — `net/http`

A minimal HTTP server built on the Go standard library and protected by the
Arcjet Go SDK. The server exposes one endpoint, `GET /`, and runs the request
through:

- **Shield** — common attacks (SQLi, XSS, path traversal).
- **Bot detection** — allows verified search engines, blocks everything else.
- **Token bucket rate limiting** — refills 5 tokens every 10 seconds, capacity
  10; each request deducts 5 tokens (so the third request inside 10 seconds is
  rate-limited).

> Sensitive-info detection is exposed by the SDK but is currently a no-op
> pending a WebAssembly analyzer; it's intentionally not wired up here.

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
```

The denied responses include the reason on `decision.reason` so you can see
which rule fired.

## Behind a proxy?

If you're running behind a load balancer or reverse proxy, set
`Config.Proxies` so Arcjet trusts the right `X-Forwarded-For` hops. See the
[main README](../../README.md#proxy-configuration).
