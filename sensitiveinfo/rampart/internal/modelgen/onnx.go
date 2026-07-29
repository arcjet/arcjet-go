package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Minimal ONNX protobuf reader. It decodes only the handful of fields the
// converter needs: ModelProto.graph, GraphProto.{node,initializer}, and the
// NodeProto / TensorProto / AttributeProto fields referenced below. The
// protobuf wire format is simple enough (varints + length-delimited records)
// that a focused reader avoids pulling in a protobuf dependency.

type tensorProto struct {
	name      string
	dims      []int64
	dataType  int32
	raw       []byte
	floatData []float32
	int32Data []int32
}

type attribute struct {
	name string
	i    int64
}

type node struct {
	opType     string
	name       string
	inputs     []string
	outputs    []string
	attributes []attribute
}

func (n *node) attrInt(name string) int64 {
	for _, a := range n.attributes {
		if a.name == name {
			return a.i
		}
	}
	return 0
}

type graph struct {
	nodes []*node
	init  map[string]*tensorProto
}

// f32Raw returns the tensor's float32 elements as little-endian bytes,
// whether stored in raw_data or float_data.
func (t *tensorProto) f32Raw() ([]byte, error) {
	if len(t.raw) > 0 {
		return t.raw, nil
	}
	if len(t.floatData) > 0 {
		buf := make([]byte, 4*len(t.floatData))
		for i, v := range t.floatData {
			binary.LittleEndian.PutUint32(buf[4*i:], math.Float32bits(v))
		}
		return buf, nil
	}
	return nil, errors.New("tensor has no float data")
}

// u8Raw returns the tensor's uint8 bytes, whether stored in raw_data or
// int32_data (protobuf stores uint8 tensors in int32_data).
func (t *tensorProto) u8Raw() []byte {
	if len(t.raw) > 0 {
		return t.raw
	}
	buf := make([]byte, len(t.int32Data))
	for i, v := range t.int32Data {
		buf[i] = byte(v)
	}
	return buf
}

type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) eof() bool { return c.pos >= len(c.b) }

func (c *cursor) varint() (uint64, error) {
	var res uint64
	var shift uint
	for {
		if c.pos >= len(c.b) {
			return 0, errors.New("varint: unexpected eof")
		}
		x := c.b[c.pos]
		c.pos++
		res |= uint64(x&0x7f) << shift
		if x&0x80 == 0 {
			return res, nil
		}
		shift += 7
	}
}

// field reads one wire field, returning its number, wire type, and payload.
// For length-delimited fields payload is the bytes; for varint fields it is
// nil and the integer is returned in n.
func (c *cursor) field() (num, wire int, payload []byte, n uint64, err error) {
	key, err := c.varint()
	if err != nil {
		return 0, 0, nil, 0, err
	}
	num = int(key >> 3)
	wire = int(key & 7)
	switch wire {
	case 0: // varint
		n, err = c.varint()
	case 2: // length-delimited
		var ln uint64
		ln, err = c.varint()
		if err == nil {
			if c.pos+int(ln) > len(c.b) {
				err = errors.New("length-delimited: overrun")
			} else {
				payload = c.b[c.pos : c.pos+int(ln)]
				c.pos += int(ln)
			}
		}
	case 1: // 64-bit
		if c.pos+8 > len(c.b) {
			err = errors.New("fixed64: overrun")
		} else {
			payload = c.b[c.pos : c.pos+8]
			c.pos += 8
		}
	case 5: // 32-bit
		if c.pos+4 > len(c.b) {
			err = errors.New("fixed32: overrun")
		} else {
			payload = c.b[c.pos : c.pos+4]
			c.pos += 4
		}
	default:
		err = fmt.Errorf("unsupported wire type %d", wire)
	}
	return num, wire, payload, n, err
}

func parseGraph(data []byte) (*graph, error) {
	// ModelProto.graph = field 7.
	c := &cursor{b: data}
	var graphBytes []byte
	for !c.eof() {
		num, wire, payload, _, err := c.field()
		if err != nil {
			return nil, err
		}
		if num == 7 && wire == 2 {
			graphBytes = payload
		}
	}
	if graphBytes == nil {
		return nil, errors.New("no graph in model")
	}

	g := &graph{init: map[string]*tensorProto{}}
	gc := &cursor{b: graphBytes}
	for !gc.eof() {
		num, wire, payload, _, err := gc.field()
		if err != nil {
			return nil, err
		}
		switch {
		case num == 1 && wire == 2: // node
			n, err := parseNode(payload)
			if err != nil {
				return nil, err
			}
			g.nodes = append(g.nodes, n)
		case num == 5 && wire == 2: // initializer
			t, err := parseTensor(payload)
			if err != nil {
				return nil, err
			}
			g.init[t.name] = t
		}
	}
	return g, nil
}

func parseNode(b []byte) (*node, error) {
	n := &node{}
	name := ""
	c := &cursor{b: b}
	for !c.eof() {
		num, wire, payload, _, err := c.field()
		if err != nil {
			return nil, err
		}
		switch {
		case num == 1 && wire == 2:
			n.inputs = append(n.inputs, string(payload))
		case num == 2 && wire == 2:
			n.outputs = append(n.outputs, string(payload))
		case num == 3 && wire == 2:
			n.name = string(payload)
		case num == 4 && wire == 2:
			n.opType = string(payload)
		case num == 5 && wire == 2:
			a, err := parseAttribute(payload)
			if err != nil {
				return nil, err
			}
			n.attributes = append(n.attributes, a)
		}
	}
	_ = name
	return n, nil
}

func parseAttribute(b []byte) (attribute, error) {
	a := attribute{}
	c := &cursor{b: b}
	for !c.eof() {
		num, wire, payload, val, err := c.field()
		if err != nil {
			return a, err
		}
		switch {
		case num == 1 && wire == 2: // name
			a.name = string(payload)
		case num == 3 && wire == 0: // i (int64)
			a.i = int64(val)
		}
	}
	return a, nil
}

// tensorProto field numbers:
//
//	1 dims (int64, repeated; packed or not)
//	2 data_type (int32)
//	4 float_data (float, packed)
//	5 int32_data (int32, packed)
//	8 name (string)
//	9 raw_data (bytes)
func parseTensor(b []byte) (*tensorProto, error) {
	t := &tensorProto{}
	c := &cursor{b: b}
	for !c.eof() {
		num, wire, payload, val, err := c.field()
		if err != nil {
			return nil, err
		}
		switch {
		case num == 1 && wire == 0: // single dim
			t.dims = append(t.dims, int64(val))
		case num == 1 && wire == 2: // packed dims
			pc := &cursor{b: payload}
			for !pc.eof() {
				v, err := pc.varint()
				if err != nil {
					return nil, err
				}
				t.dims = append(t.dims, int64(v))
			}
		case num == 2 && wire == 0:
			t.dataType = int32(val)
		case num == 4 && wire == 2: // float_data packed
			for i := 0; i+4 <= len(payload); i += 4 {
				t.floatData = append(t.floatData, math.Float32frombits(binary.LittleEndian.Uint32(payload[i:])))
			}
		case num == 5 && wire == 2: // int32_data packed
			pc := &cursor{b: payload}
			for !pc.eof() {
				v, err := pc.varint()
				if err != nil {
					return nil, err
				}
				t.int32Data = append(t.int32Data, int32(v))
			}
		case num == 8 && wire == 2:
			t.name = string(payload)
		case num == 9 && wire == 2:
			t.raw = payload
		}
	}
	return t, nil
}
