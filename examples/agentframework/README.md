# Arcjet Go SDK example: Microsoft Agent Framework

An agent with two tools, both guarded by Arcjet:

- `lookup_order` is read-only. A per-user token bucket limits it, and it
  fails open so lookups keep working during an Arcjet outage.
- `issue_refund` is irreversible. A tighter bucket limits it, and it fails
  closed: if Arcjet cannot judge the call, the refund does not run and the
  model is told why.

Every incoming message is screened for prompt injection by `GuardMiddleware`
before the model runs. The conversation shares one correlation ID, so all of
its decisions appear as one Sequence in the Arcjet console.

## Run

Copy `example.env` to `.env.local` and fill in the keys:

```sh
cp example.env .env.local
```

Then run the agent:

```sh
set -a; source .env.local; set +a
go run .
```

The fourth prompt is rate limited and the fifth is blocked before the model
sees it. The agent explains each denial rather than retrying, because the
tool result it receives is an `arcjetDenied` payload, not an error.
