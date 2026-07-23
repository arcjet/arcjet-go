// Command modelgen converts the quantized Rampart ONNX model into the compact
// weights.bin that the rampart package embeds. It is a development tool, run
// only when refreshing the bundled weights; the produced weights.bin is what
// ships.
//
// It reads the int4-quantized ONNX with a minimal, purpose-built protobuf
// reader (only the ModelProto -> GraphProto -> {NodeProto, TensorProto} fields
// it needs) so the shipped module carries no ONNX dependency. The int4
// MatMulNBits weights and uint8-quantized embeddings are repackaged as-is
// (dequantization happens once at load time in the rampart package), keeping
// the embedded blob to roughly the size of the ONNX (~15 MB).
//
// Usage:
//
//	go run ./internal/modelgen -onnx model_q4.onnx -out ../weights.bin
//
// The ONNX is fetched from https://huggingface.co/nationaldesignstudio/rampart
// (onnx/model_q4.onnx) and is not committed to the repository.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/arcjet/arcjet-go/sensitiveinfo/rampart/internal/blob"
)

func main() {
	onnxPath := flag.String("onnx", "model_q4.onnx", "path to the quantized Rampart ONNX model")
	outPath := flag.String("out", "../weights.bin", "path to write the packed weights blob")
	flag.Parse()
	if err := run(*onnxPath, *outPath); err != nil {
		log.Fatal(err)
	}
}

func run(onnxPath, outPath string) error {
	data, err := os.ReadFile(onnxPath)
	if err != nil {
		return fmt.Errorf("read onnx: %w", err)
	}
	g, err := parseGraph(data)
	if err != nil {
		return fmt.Errorf("parse onnx: %w", err)
	}
	tensors, err := buildTensors(g)
	if err != nil {
		return fmt.Errorf("build tensors: %w", err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create out: %w", err)
	}
	writeErr := blob.Write(out, tensors)
	closeErr := out.Close()
	if writeErr != nil {
		return fmt.Errorf("write blob: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close out: %w", closeErr)
	}

	var total int
	for _, t := range tensors {
		total += len(t.Data)
	}
	fmt.Printf("wrote %d tensors, %d bytes of tensor data to %s\n", len(tensors), total, outPath)
	return nil
}

// matMulRole maps a MatMulNBits node name to the canonical weight name used in
// the blob (and by the loader).
var layerRe = regexp.MustCompile(`^/bert/encoder/layer\.(\d+)/(.+)$`)

func matMulRole(nodeName string) (string, bool) {
	// Node names carry a "/MatMul_Q4" suffix (the quantized MatMul op).
	nodeName = strings.TrimSuffix(nodeName, "/MatMul_Q4")
	if nodeName == "/classifier" {
		return "classifier.weight", true
	}
	m := layerRe.FindStringSubmatch(nodeName)
	if m == nil {
		return "", false
	}
	layer, sub := m[1], m[2]
	switch sub {
	case "attention/self/query":
		return "layer." + layer + ".attn.query.weight", true
	case "attention/self/key":
		return "layer." + layer + ".attn.key.weight", true
	case "attention/self/value":
		return "layer." + layer + ".attn.value.weight", true
	case "attention/output/dense":
		return "layer." + layer + ".attn.output.weight", true
	case "intermediate/dense":
		return "layer." + layer + ".intermediate.weight", true
	case "output/dense":
		return "layer." + layer + ".output.weight", true
	}
	return "", false
}

// biasRole maps a "*.bias" or "*.LayerNorm.*" ONNX initializer name to the
// canonical blob name, or returns false to skip it.
func biasRole(name string) (string, bool) {
	switch name {
	case "bert.embeddings.LayerNorm.weight":
		return "embeddings.ln.weight", true
	case "bert.embeddings.LayerNorm.bias":
		return "embeddings.ln.bias", true
	case "classifier.bias":
		return "classifier.bias", true
	}
	m := regexp.MustCompile(`^bert\.encoder\.layer\.(\d+)\.(.+)$`).FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	layer, sub := m[1], m[2]
	switch sub {
	case "attention.self.query.bias":
		return "layer." + layer + ".attn.query.bias", true
	case "attention.self.key.bias":
		return "layer." + layer + ".attn.key.bias", true
	case "attention.self.value.bias":
		return "layer." + layer + ".attn.value.bias", true
	case "attention.output.dense.bias":
		return "layer." + layer + ".attn.output.bias", true
	case "attention.output.LayerNorm.weight":
		return "layer." + layer + ".attn.ln.weight", true
	case "attention.output.LayerNorm.bias":
		return "layer." + layer + ".attn.ln.bias", true
	case "intermediate.dense.bias":
		return "layer." + layer + ".intermediate.bias", true
	case "output.dense.bias":
		return "layer." + layer + ".output.bias", true
	case "output.LayerNorm.weight":
		return "layer." + layer + ".output.ln.weight", true
	case "output.LayerNorm.bias":
		return "layer." + layer + ".output.ln.bias", true
	}
	return "", false
}

// embeddingRole maps a quantized embedding initializer name to its canonical
// blob name and role suffix.
func embeddingRole(name string) (string, bool) {
	switch name {
	case "bert.embeddings.word_embeddings.weight_quantized":
		return "embeddings.word", true
	case "bert.embeddings.position_embeddings.weight_quantized":
		return "embeddings.position", true
	case "bert.embeddings.token_type_embeddings.weight_quantized":
		return "embeddings.token_type", true
	}
	return "", false
}

func buildTensors(g *graph) ([]blob.Tensor, error) {
	var out []blob.Tensor

	// int4 linear weights from MatMulNBits nodes.
	for _, n := range g.nodes {
		if n.opType != "MatMulNBits" {
			continue
		}
		role, ok := matMulRole(n.name)
		if !ok {
			return nil, fmt.Errorf("unmapped MatMulNBits node %q", n.name)
		}
		if len(n.inputs) < 3 {
			return nil, fmt.Errorf("MatMulNBits %q: want >=3 inputs, got %d", n.name, len(n.inputs))
		}
		wq := g.init[n.inputs[1]]
		scales := g.init[n.inputs[2]]
		if wq == nil || scales == nil {
			return nil, fmt.Errorf("MatMulNBits %q: missing weight/scales initializers", n.name)
		}
		k := n.attrInt("K")
		nOut := n.attrInt("N")
		blockSize := n.attrInt("block_size")
		if k == 0 || nOut == 0 || blockSize == 0 {
			return nil, fmt.Errorf("MatMulNBits %q: missing K/N/block_size attrs", n.name)
		}
		out = append(out,
			blob.Tensor{
				Name:      role,
				DType:     blob.DTypeU4,
				Dims:      []int32{int32(nOut), int32(k)},
				BlockSize: int32(blockSize),
				Data:      wq.raw,
			},
			blob.Tensor{
				Name:  role + ".scales",
				DType: blob.DTypeF32,
				Dims:  int32s(scales.dims),
				Data:  scales.raw,
			})
	}

	// fp32 biases and LayerNorm parameters.
	for name, t := range g.init {
		role, ok := biasRole(name)
		if !ok {
			continue
		}
		raw, err := t.f32Raw()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, blob.Tensor{Name: role, DType: blob.DTypeF32, Dims: int32s(t.dims), Data: raw})
	}

	// uint8-quantized embeddings + their scalar scale and zero point.
	for name, t := range g.init {
		role, ok := embeddingRole(name)
		if !ok {
			continue
		}
		out = append(out, blob.Tensor{Name: role, DType: blob.DTypeU8, Dims: int32s(t.dims), Data: t.raw})
		base := embeddingBase(name)
		scale := g.init[base+"_scale"]
		zp := g.init[base+"_zero_point"]
		if scale == nil || zp == nil {
			return nil, fmt.Errorf("%s: missing scale/zero_point", name)
		}
		scaleRaw, err := scale.f32Raw()
		if err != nil {
			return nil, fmt.Errorf("%s scale: %w", name, err)
		}
		out = append(out,
			blob.Tensor{Name: role + ".scale", DType: blob.DTypeF32, Dims: int32s(scale.dims), Data: scaleRaw},
			blob.Tensor{Name: role + ".zp", DType: blob.DTypeU8, Dims: int32s(zp.dims), Data: zp.u8Raw()})
	}

	// Sort by name for a deterministic, reproducible blob (map iteration above
	// is unordered). The loader reads by name, so order does not affect it.
	slices.SortFunc(out, func(a, b blob.Tensor) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func embeddingBase(quantizedName string) string {
	// "bert.embeddings.word_embeddings.weight_quantized" -> ".weight" base.
	return quantizedName[:len(quantizedName)-len("_quantized")]
}

func int32s(dims []int64) []int32 {
	out := make([]int32, len(dims))
	for i, d := range dims {
		out[i] = int32(d)
	}
	return out
}
