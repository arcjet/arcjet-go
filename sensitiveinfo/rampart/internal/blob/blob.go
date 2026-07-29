// Package blob defines the compact on-disk format for the bundled Rampart
// model weights. The offline modelgen tool writes it from the quantized ONNX;
// the rampart package embeds and reads it. Keeping the reader and writer in one
// place stops the two from drifting.
//
// The format is a tiny tag-length-value stream: an 8-byte magic, a uint32
// tensor count, then each tensor as name, dtype, dims, block size, and raw
// bytes. All integers are little-endian.
package blob

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Magic identifies the blob format and version.
var Magic = [8]byte{'A', 'J', 'R', 'M', 'P', 'T', '0', '1'}

// Tensor dtypes.
const (
	// DTypeF32 is little-endian float32 data (4 bytes per element).
	DTypeF32 uint8 = 0
	// DTypeU8 is raw uint8 data (per-tensor quantized embeddings).
	DTypeU8 uint8 = 1
	// DTypeU4 is int4 block-quantized weight data in ONNX MatMulNBits layout:
	// Dims is the logical [N, K] weight shape, BlockSize is the quant block
	// size along K, and Data is [N, ceil(K/BlockSize), BlockSize/2] packed
	// nibbles (low nibble first). The matching per-block scales are stored as a
	// separate DTypeF32 tensor named Name+".scales".
	DTypeU4 uint8 = 2
)

// Tensor is one named weight tensor.
type Tensor struct {
	Name      string
	DType     uint8
	Dims      []int32
	BlockSize int32
	Data      []byte
}

// Write serializes tensors to w.
func Write(w io.Writer, tensors []Tensor) error {
	bw := bufio.NewWriter(w)
	if _, err := bw.Write(Magic[:]); err != nil {
		return err
	}
	if err := binary.Write(bw, binary.LittleEndian, uint32(len(tensors))); err != nil {
		return err
	}
	for _, t := range tensors {
		if err := writeString(bw, t.Name); err != nil {
			return err
		}
		if err := bw.WriteByte(t.DType); err != nil {
			return err
		}
		if err := binary.Write(bw, binary.LittleEndian, uint8(len(t.Dims))); err != nil {
			return err
		}
		for _, d := range t.Dims {
			if err := binary.Write(bw, binary.LittleEndian, d); err != nil {
				return err
			}
		}
		if err := binary.Write(bw, binary.LittleEndian, t.BlockSize); err != nil {
			return err
		}
		if err := binary.Write(bw, binary.LittleEndian, uint32(len(t.Data))); err != nil {
			return err
		}
		if _, err := bw.Write(t.Data); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// Read deserializes tensors written by Write.
func Read(r io.Reader) ([]Tensor, error) {
	br := bufio.NewReader(r)
	var magic [8]byte
	if _, err := io.ReadFull(br, magic[:]); err != nil {
		return nil, err
	}
	if magic != Magic {
		return nil, fmt.Errorf("blob: bad magic %q", magic)
	}
	var count uint32
	if err := binary.Read(br, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	tensors := make([]Tensor, count)
	for i := range tensors {
		name, err := readString(br)
		if err != nil {
			return nil, err
		}
		dtype, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		var ndim uint8
		if err := binary.Read(br, binary.LittleEndian, &ndim); err != nil {
			return nil, err
		}
		dims := make([]int32, ndim)
		for j := range dims {
			if err := binary.Read(br, binary.LittleEndian, &dims[j]); err != nil {
				return nil, err
			}
		}
		var blockSize int32
		if err := binary.Read(br, binary.LittleEndian, &blockSize); err != nil {
			return nil, err
		}
		var dataLen uint32
		if err := binary.Read(br, binary.LittleEndian, &dataLen); err != nil {
			return nil, err
		}
		data := make([]byte, dataLen)
		if _, err := io.ReadFull(br, data); err != nil {
			return nil, err
		}
		tensors[i] = Tensor{Name: name, DType: dtype, Dims: dims, BlockSize: blockSize, Data: data}
	}
	return tensors, nil
}

func writeString(w *bufio.Writer, s string) error {
	if err := binary.Write(w, binary.LittleEndian, uint16(len(s))); err != nil {
		return err
	}
	_, err := w.WriteString(s)
	return err
}

func readString(r *bufio.Reader) (string, error) {
	var n uint16
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
