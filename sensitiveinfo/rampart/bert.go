package rampart

import (
	"math"
	"runtime"
	"sync"
)

// parallelFor splits [0,n) across up to GOMAXPROCS workers, calling fn with
// each disjoint [lo,hi) sub-range and waiting for all to finish. Used to
// parallelize the independent rows of the matmul-heavy layers across cores.
func parallelFor(n int, fn func(lo, hi int)) {
	workers := min(runtime.GOMAXPROCS(0), n)
	if workers <= 1 {
		fn(0, n)
		return
	}
	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for lo := 0; lo < n; lo += chunk {
		hi := min(lo+chunk, n)
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			fn(lo, hi)
		}(lo, hi)
	}
	wg.Wait()
}

// dot computes the dot product of two equal-length slices, unrolled by four to
// give the compiler independent accumulators (Go does not auto-vectorize).
func dot(a, b []float32) float32 {
	var s0, s1, s2, s3 float32
	n := len(a)
	i := 0
	for ; i <= n-4; i += 4 {
		s0 += a[i] * b[i]
		s1 += a[i+1] * b[i+1]
		s2 += a[i+2] * b[i+2]
		s3 += a[i+3] * b[i+3]
	}
	for ; i < n; i++ {
		s0 += a[i] * b[i]
	}
	return s0 + s1 + s2 + s3
}

// forwardBuffers holds the scratch slices one forward pass needs, sized for the
// model's maximum sequence length so a single set serves any call. They are
// pooled and reused across calls to keep the request hot path allocation-free
// (a full window otherwise churns several megabytes of float32 per pass).
type forwardBuffers struct {
	h, q, k, v, ctx, attnOut, ffnOut []float32 // maxPositions*hiddenSize
	inter                            []float32 // maxPositions*intermediate
}

func newForwardBuffers() *forwardBuffers {
	return &forwardBuffers{
		h:       make([]float32, maxPositions*hiddenSize),
		q:       make([]float32, maxPositions*hiddenSize),
		k:       make([]float32, maxPositions*hiddenSize),
		v:       make([]float32, maxPositions*hiddenSize),
		ctx:     make([]float32, maxPositions*hiddenSize),
		attnOut: make([]float32, maxPositions*hiddenSize),
		ffnOut:  make([]float32, maxPositions*hiddenSize),
		inter:   make([]float32, maxPositions*intermediate),
	}
}

// forwardBufPool pools forwardBuffers across all inference calls. sync.Pool is
// safe for concurrent use, matching the read-only, concurrently-shared model.
var forwardBufPool = sync.Pool{New: func() any { return newForwardBuffers() }}

// forward runs the BERT token-classification network over a single sequence of
// token ids and returns per-token logits, flattened row-major as
// [seq*numLabels]. token_type is 0 for every token and positions are 0..seq-1,
// matching a single-segment encode. The math is plain float32. Scratch buffers
// come from forwardBufPool and are returned on completion; every buffer is
// fully overwritten before it is read, so a recycled (dirty) buffer is safe.
// The returned logits slice is freshly allocated so the caller may read it
// after the scratch buffers are recycled. seq must not exceed maxPositions;
// the tokenizer enforces that (see tokenizer.encode).
func (m *model) forward(ids []int) []float32 {
	seq := len(ids)
	if seq == 0 {
		return nil
	}

	bufs, ok := forwardBufPool.Get().(*forwardBuffers)
	if !ok {
		bufs = newForwardBuffers()
	}
	defer forwardBufPool.Put(bufs)

	// Embeddings: word + position + token_type, then LayerNorm.
	h := bufs.h[:seq*hiddenSize]
	var pos, typ [hiddenSize]float32
	m.typeEmb.row(0, typ[:])
	for t := range seq {
		row := h[t*hiddenSize : (t+1)*hiddenSize]
		m.wordEmb.row(ids[t], row)
		m.posEmb.row(t, pos[:])
		for d := range hiddenSize {
			row[d] += pos[d] + typ[d]
		}
	}
	layerNormInPlace(h, seq, m.embLN)

	// Scratch buffers reused across layers.
	q := bufs.q[:seq*hiddenSize]
	k := bufs.k[:seq*hiddenSize]
	v := bufs.v[:seq*hiddenSize]
	ctx := bufs.ctx[:seq*hiddenSize]
	attnOut := bufs.attnOut[:seq*hiddenSize]
	inter := bufs.inter[:seq*intermediate]
	ffnOut := bufs.ffnOut[:seq*hiddenSize]

	for li := range m.layers {
		layer := &m.layers[li]

		linearForward(h, seq, hiddenSize, &layer.query, q)
		linearForward(h, seq, hiddenSize, &layer.key, k)
		linearForward(h, seq, hiddenSize, &layer.value, v)

		attention(q, k, v, ctx, seq)

		linearForward(ctx, seq, hiddenSize, &layer.attnOutput, attnOut)
		// Residual + LayerNorm.
		addInPlace(attnOut, h)
		layerNormInPlace(attnOut, seq, layer.attnLN)

		linearForward(attnOut, seq, hiddenSize, &layer.intermediate, inter)
		geluInPlace(inter)
		linearForward(inter, seq, intermediate, &layer.output, ffnOut)
		addInPlace(ffnOut, attnOut)
		layerNormInPlace(ffnOut, seq, layer.outputLN)

		copy(h, ffnOut)
	}

	logits := make([]float32, seq*numLabels)
	linearForward(h, seq, hiddenSize, &m.classifier, logits)
	return logits
}

// linearForward computes out[t*l.n + n] = bias[n] + sum_k in[t*inDim+k]*w[n*l.k+k]
// for every token t. inDim must equal l.k. Tokens are processed in parallel;
// each token's outputs are independent, so no synchronization is needed.
func linearForward(in []float32, seq, inDim int, l *linear, out []float32) {
	// Parallelize over output neurons and keep the inner loop over tokens, so
	// each weight row is loaded once and reused across every token (the weight
	// matrix, not the activations, dominates memory traffic here).
	parallelFor(l.n, func(lo, hi int) {
		for n := lo; n < hi; n++ {
			wRow := l.w[n*l.k : n*l.k+l.k]
			bias := l.bias[n]
			for t := range seq {
				out[t*l.n+n] = dot(in[t*inDim:t*inDim+inDim], wRow) + bias
			}
		}
	})
}

// attention computes multi-head self-attention. q, k, v are [seq*hiddenSize];
// ctx receives the concatenated per-head context [seq*hiddenSize]. Heads are
// independent and run in parallel; each gets its own scores scratch.
func attention(q, k, v, ctx []float32, seq int) {
	scale := float32(1.0 / math.Sqrt(float64(headDim)))
	parallelFor(numHeads, func(lo, hi int) {
		scores := make([]float32, seq)
		for head := lo; head < hi; head++ {
			off := head * headDim
			for i := range seq {
				attendQuery(q, k, v, ctx, scores, seq, off, i, scale)
			}
		}
	})
}

// attendQuery computes the attention output for query position i of one head
// (columns [off,off+headDim)) into ctx, using scores as scratch.
func attendQuery(q, k, v, ctx, scores []float32, seq, off, i int, scale float32) {
	qRow := q[i*hiddenSize+off : i*hiddenSize+off+headDim]
	// Scaled dot-product scores against every key, tracking the max for a
	// stable softmax.
	maxScore := float32(math.Inf(-1))
	for j := range seq {
		kRow := k[j*hiddenSize+off : j*hiddenSize+off+headDim]
		s := dot(qRow, kRow) * scale
		scores[j] = s
		if s > maxScore {
			maxScore = s
		}
	}
	var sum float32
	for j := range seq {
		e := float32(math.Exp(float64(scores[j] - maxScore)))
		scores[j] = e
		sum += e
	}
	inv := 1.0 / sum
	// Weighted sum of values into the context row for this head/query.
	ctxRow := ctx[i*hiddenSize+off : i*hiddenSize+off+headDim]
	for d := range headDim {
		ctxRow[d] = 0
	}
	for j := range seq {
		w := scores[j] * inv
		vRow := v[j*hiddenSize+off : j*hiddenSize+off+headDim]
		for d := range headDim {
			ctxRow[d] += w * vRow[d]
		}
	}
}

// layerNormInPlace applies LayerNorm over the hiddenSize dimension of each of
// the seq rows of x, in place.
func layerNormInPlace(x []float32, seq int, ln layerNorm) {
	for t := range seq {
		row := x[t*hiddenSize : (t+1)*hiddenSize]
		var mean float32
		for _, val := range row {
			mean += val
		}
		mean /= hiddenSize
		var variance float32
		for _, val := range row {
			d := val - mean
			variance += d * d
		}
		variance /= hiddenSize
		inv := float32(1.0 / math.Sqrt(float64(variance)+layerNormEps))
		for d := range row {
			row[d] = (row[d]-mean)*inv*ln.weight[d] + ln.bias[d]
		}
	}
}

// addInPlace adds src into dst element-wise.
func addInPlace(dst, src []float32) {
	for i := range dst {
		dst[i] += src[i]
	}
}

// geluInPlace applies the exact GELU activation in place:
// 0.5*x*(1+erf(x/sqrt2)).
func geluInPlace(x []float32) {
	const invSqrt2 = 0.7071067811865476
	for i, val := range x {
		x[i] = 0.5 * val * float32(1+math.Erf(float64(val)*invSqrt2))
	}
}
