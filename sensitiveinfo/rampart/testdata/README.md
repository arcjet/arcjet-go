# Golden test vectors

`golden.json` holds the numerical correctness gate for the pure-Go inference
engine. Each record is:

- `text` — an input string.
- `ids` — the token ids the package tokenizer produced for `text`.
- `labels` — the per-token argmax label id produced by the **reference ONNX
  Runtime** running the bundled `model_q4.onnx` on those `ids`.
- `scores` — the per-token softmax probability of that argmax label, from ONNX
  Runtime.

`model_golden_test.go` asserts the pure-Go tokenizer reproduces `ids` and the
pure-Go forward pass reproduces `labels` exactly and `scores` within tolerance.
When authored, the Go forward pass matched ONNX Runtime to a maximum absolute
logit difference of ~1e-5 with 100% argmax agreement.

## Regenerating

The vectors are committed so CI needs no model download or ONNX runtime. To
regenerate after a model or tokenizer change:

1. Download the model: `onnx/model_q4.onnx` from
   https://huggingface.co/nationaldesignstudio/rampart into
   `internal/modelgen/`.
2. Rebuild `weights.bin`: `go run ./internal/modelgen -onnx internal/modelgen/model_q4.onnx -out weights.bin`.
3. Dump the tokenizer ids for the input set (a small throwaway that calls the
   package tokenizer), then run the reference model with `onnxruntime` (Python)
   over those ids and write `{text, ids, labels, scores}` — labels = argmax over
   the `[seq,35]` logits, scores = softmax max.
