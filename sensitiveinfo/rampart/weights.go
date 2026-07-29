package rampart

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/arcjet/arcjet-go/sensitiveinfo/rampart/internal/blob"
)

// weightsBin is the bundled Rampart model, produced by internal/modelgen from
// the CC BY 4.0 model at https://huggingface.co/nationaldesignstudio/rampart.
// See NOTICE for attribution.
//
//go:embed weights.bin
var weightsBin []byte

// Model hyperparameters, from the Rampart config.json.
const (
	hiddenSize    = 384
	numLayers     = 6
	numHeads      = 12
	headDim       = hiddenSize / numHeads // 32
	intermediate  = 1536
	maxPositions  = 512
	layerNormEps  = 1e-12
	int4ZeroPoint = 8 // MatMulNBits default zero point for 4-bit weights
)

// linear is a dense layer with weights dequantized to float32. w is row-major
// [N*K]: w[n*K + k] is the weight from input k to output n (PyTorch Linear
// layout), matching Y[m][n] = sum_k A[m][k]*w[n*K+k] + bias[n].
type linear struct {
	n    int
	k    int
	w    []float32
	bias []float32
}

// layerNorm holds the gain and bias of a LayerNormalization over hiddenSize.
type layerNorm struct {
	weight []float32
	bias   []float32
}

// quantEmbedding is a uint8 per-tensor quantized embedding table, dequantized
// lazily per gathered row: emb[i][d] = (q[i*dim+d] - zp) * scale.
type quantEmbedding struct {
	rows  int
	dim   int
	q     []byte
	scale float32
	zp    float32
}

// row dequantizes embedding row i into dst (len dim).
func (e *quantEmbedding) row(i int, dst []float32) {
	base := i * e.dim
	for d := range e.dim {
		dst[d] = (float32(e.q[base+d]) - e.zp) * e.scale
	}
}

type encoderLayer struct {
	query, key, value, attnOutput linear
	attnLN                        layerNorm
	intermediate, output          linear
	outputLN                      layerNorm
}

// model is the loaded, dequantized Rampart network. It is read-only after
// load and shared across all inference calls.
type model struct {
	wordEmb    quantEmbedding
	posEmb     quantEmbedding
	typeEmb    quantEmbedding
	embLN      layerNorm
	layers     [numLayers]encoderLayer
	classifier linear
}

// weightLoader assembles a model from the tensor table, tracking the first
// error so callers check once at the end rather than after every field.
type weightLoader struct {
	byName map[string]blob.Tensor
	err    error
}

func (l *weightLoader) get(name string) blob.Tensor {
	if l.err != nil {
		return blob.Tensor{}
	}
	t, ok := l.byName[name]
	if !ok {
		l.err = fmt.Errorf("rampart: missing tensor %q", name)
	}
	return t
}

func (l *weightLoader) f32(name string) []float32 {
	t := l.get(name)
	if l.err != nil {
		return nil
	}
	if t.DType != blob.DTypeF32 {
		l.err = fmt.Errorf("rampart: tensor %q is not f32", name)
		return nil
	}
	return bytesToF32(t.Data)
}

func (l *weightLoader) ln(prefix string) layerNorm {
	return layerNorm{weight: l.f32(prefix + ".weight"), bias: l.f32(prefix + ".bias")}
}

func (l *weightLoader) lin(prefix string) linear {
	wt := l.get(prefix + ".weight")
	if l.err != nil {
		return linear{}
	}
	if wt.DType != blob.DTypeU4 {
		l.err = fmt.Errorf("rampart: tensor %q is not int4", prefix+".weight")
		return linear{}
	}
	scales := l.f32(prefix + ".weight.scales")
	bias := l.f32(prefix + ".bias")
	if l.err != nil {
		return linear{}
	}
	n := int(wt.Dims[0])
	k := int(wt.Dims[1])
	return linear{n: n, k: k, w: dequantInt4(wt.Data, scales, n, k, int(wt.BlockSize)), bias: bias}
}

func (l *weightLoader) emb(prefix string) quantEmbedding {
	t := l.get(prefix)
	scale := l.f32(prefix + ".scale")
	zpT := l.get(prefix + ".zp")
	if l.err != nil {
		return quantEmbedding{}
	}
	if len(scale) == 0 || len(zpT.Data) == 0 {
		l.err = fmt.Errorf("rampart: %q missing scale/zp", prefix)
		return quantEmbedding{}
	}
	return quantEmbedding{
		rows:  int(t.Dims[0]),
		dim:   int(t.Dims[1]),
		q:     t.Data,
		scale: scale[0],
		zp:    float32(zpT.Data[0]),
	}
}

// loadModel decodes the embedded weights blob into a model, dequantizing the
// int4 linear weights to float32 once (the hot path is then plain float32
// arithmetic). Embeddings are kept uint8 and dequantized per gathered row.
func loadModel() (*model, error) {
	tensors, err := blob.Read(bytes.NewReader(weightsBin))
	if err != nil {
		return nil, fmt.Errorf("rampart: read weights: %w", err)
	}
	l := &weightLoader{byName: make(map[string]blob.Tensor, len(tensors))}
	for _, t := range tensors {
		l.byName[t.Name] = t
	}

	m := &model{
		wordEmb: l.emb("embeddings.word"),
		posEmb:  l.emb("embeddings.position"),
		typeEmb: l.emb("embeddings.token_type"),
		embLN:   l.ln("embeddings.ln"),
	}
	for i := range numLayers {
		p := fmt.Sprintf("layer.%d", i)
		m.layers[i] = encoderLayer{
			query:        l.lin(p + ".attn.query"),
			key:          l.lin(p + ".attn.key"),
			value:        l.lin(p + ".attn.value"),
			attnOutput:   l.lin(p + ".attn.output"),
			attnLN:       l.ln(p + ".attn.ln"),
			intermediate: l.lin(p + ".intermediate"),
			output:       l.lin(p + ".output"),
			outputLN:     l.ln(p + ".output.ln"),
		}
	}
	m.classifier = l.lin("classifier")
	if l.err != nil {
		return nil, l.err
	}
	return m, nil
}

// dequantInt4 dequantizes ONNX MatMulNBits int4 block-quantized weights to a
// dense float32 [N*K] array. data is [N, nBlocks, blockSize/2] packed nibbles
// (low nibble first); scales is [N*nBlocks]; the zero point is the 4-bit
// default of 8. w[n*K+k] = (nibble - 8) * scale[n*nBlocks + k/blockSize].
func dequantInt4(data []byte, scales []float32, n, k, blockSize int) []float32 {
	nBlocks := (k + blockSize - 1) / blockSize
	blobBytes := blockSize / 2
	w := make([]float32, n*k)
	for row := range n {
		rowBase := row * nBlocks * blobBytes
		scaleBase := row * nBlocks
		for kk := range k {
			block := kk / blockSize
			within := kk % blockSize
			b := data[rowBase+block*blobBytes+within/2]
			var nib byte
			if within%2 == 0 {
				nib = b & 0x0f
			} else {
				nib = b >> 4
			}
			w[row*k+kk] = (float32(nib) - int4ZeroPoint) * scales[scaleBase+block]
		}
	}
	return w
}

// bytesToF32 reinterprets little-endian float32 bytes as a []float32.
func bytesToF32(b []byte) []float32 {
	out := make([]float32, len(b)/4)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[4*i:]))
	}
	return out
}
