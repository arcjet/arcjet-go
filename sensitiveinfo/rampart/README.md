# Rampart sensitive-info backend

An optional, on-device sensitive-information detection backend for
[`github.com/arcjet/arcjet-go`](https://github.com/arcjet/arcjet-go). It plugs
into the SDK's `SensitiveInfo` and `GuardSensitiveInfo` rules and detects many
more entity types than the bundled analyzer — names, addresses, SSNs, tax and
government IDs, and more — using a quantized BERT named-entity-recognition model
that is **embedded in the binary** and runs entirely in-process.

It is a separate Go module so the ~15 MB of model weights only ship with
applications that opt in; `go get github.com/arcjet/arcjet-go` is unaffected.

## Install

```
go get github.com/arcjet/arcjet-go/sensitiveinfo/rampart
```

## Usage

Create one backend at startup (loading is relatively expensive) and share it;
it is safe for concurrent use.

```go
backend, err := rampart.New(rampart.Options{})
if err != nil {
	log.Fatal(err)
}

client, err := arcjet.NewClient(arcjet.Config{
	Rules: []arcjet.Rule{
		arcjet.SensitiveInfo(arcjet.SensitiveInfoOptions{
			Mode:    arcjet.ModeLive,
			Deny:    []arcjet.EntityType{arcjet.SensitiveInfoGivenName, arcjet.SensitiveInfoEmail},
			Backend: backend,
		}),
	},
})
```

The scanned text never leaves the process. As with the built-in analyzer, the
SDK sends only a SHA-256 hash of the text plus the locally-computed result to
Arcjet.

## Detected entity types

The NER model detects: `GIVEN_NAME`, `SURNAME`, `EMAIL`, `PHONE_NUMBER`, `URL`,
`TAX_ID`, `BANK_ACCOUNT`, `ROUTING_NUMBER`, `GOVERNMENT_ID`, `PASSPORT`,
`DRIVERS_LICENSE`, `BUILDING_NUMBER`, `STREET_NAME`, `SECONDARY_ADDRESS`,
`CITY`, `STATE`, `ZIP_CODE`. Deterministic recognizers additionally cover
`EMAIL`, `URL`, `IP_ADDRESS`, `PHONE_NUMBER`, `SSN`, and `CREDIT_CARD_NUMBER`
(recognizer results take precedence over the model on overlapping text).

`rampart.Entities()` returns the full set, handy for
`Deny: rampart.Entities()`.

Listing any of these non-native types on a `SensitiveInfo`/`GuardSensitiveInfo`
rule **without** a backend is a configuration error
(`arcjet.ErrUnsupportedEntityType`).

## Performance

Detection runs on the request hot path. Inference is pure Go (no cgo, no SIMD
assembly), parallelized across CPU cores. Cost scales with input length: input
is scanned in 480-character windows and each window is a full forward pass.

On a 10-core machine, a single window is roughly 25–70 ms. Typical short request
fields are a single window.

Two mechanisms bound worst-case cost so large input cannot become a
denial-of-service vector:

- **`Options.MaxInputChars`** (default `4096`) is the hard character ceiling;
  input beyond it is truncated. The default keeps the worst case to roughly ten
  windows (well under a second) even with no caller timeout — deliberately lower
  than the JavaScript/Python SDKs' `100_000`, whose ONNX-runtime inference is
  much faster. Raise it if you need to scan larger payloads and can afford the
  latency.
- **Context cancellation** — `Detect` checks the context between windows, so a
  request deadline (`context.WithTimeout`, or the incoming `*http.Request`
  context) caps total inference regardless of input length. On cancellation the
  rule fails open, like any other scan error.

Inference is memory-bound rather than compute-bound at high core counts, so it
scales sublinearly with cores; per-window latency, not throughput, is what
`MaxInputChars` and the context deadline bound.

## The model

Bundled model:
[`nationaldesignstudio/rampart`](https://huggingface.co/nationaldesignstudio/rampart)
— a `BertForTokenClassification` network (MiniLM-L6-H384, 6 layers, hidden 384),
int4 block-quantized, fine-tuned for multilingual PII detection (en, es, fr, de,
it, pt, nl).

The Go source is Apache-2.0. The bundled model artifacts (`weights.bin`,
`vocab.txt`) are CC BY 4.0, © National Design Studio — see [`NOTICE`](./NOTICE).

## Regenerating the weights

`weights.bin` is produced offline from the model's int4 ONNX by
`internal/modelgen` (a minimal, dependency-free ONNX reader that repackages the
`MatMulNBits` weights and uint8 embeddings). See
[`testdata/README.md`](./testdata/README.md) for the full procedure and how the
golden validation vectors are captured from ONNX Runtime.
