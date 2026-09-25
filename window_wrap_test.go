package rardecode

import (
	"bytes"
	"io"
	"testing"
)

// scriptDecoder writes a fixed sequence of literals and copies.
type scriptDecoder struct {
	ops []scriptOp
}

type scriptOp struct {
	lit            []byte
	length, offset int
}

func (s *scriptDecoder) init(byteReader, bool, int64, int) {}
func (s *scriptDecoder) version() int                      { return decode29Ver }

func (s *scriptDecoder) fill(dr *decodeReader) error {
	for dr.notFull() {
		if len(s.ops) == 0 {
			return io.EOF
		}
		op := &s.ops[0]
		if op.lit != nil {
			dr.writeByte(op.lit[0])
			if op.lit = op.lit[1:]; len(op.lit) > 0 {
				continue
			}
		} else {
			dr.copyBytes(op.length, op.offset)
		}
		s.ops = s.ops[1:]
	}
	return nil
}

// A copy that runs past the end of the window has to continue at its start
// once the window wraps. It used to stop at the end of the window, so the
// rest of it was lost and everything after it came out shifted. Real
// archives hit this in solid mode: a small first file leaves the window at a
// position that is not a multiple of its size.
func TestCopyAcrossWindowEnd(t *testing.T) {
	lit := make([]byte, minWindowSize-10)
	for i := range lit {
		lit[i] = byte(i*7 + i>>8)
	}
	ops := []scriptOp{
		{lit: lit},
		{length: 30, offset: 1000}, // 10 bytes before the end, 20 after the wrap
		{lit: []byte("tail")},
		{length: 12, offset: 5000},
	}
	// what the output should be
	var want []byte
	for _, op := range ops {
		if op.lit != nil {
			want = append(want, op.lit...)
			continue
		}
		for i := 0; i < op.length; i++ {
			want = append(want, want[len(want)-op.offset])
		}
	}

	d := &decodeReader{dec: &scriptDecoder{ops: ops}}
	if err := d.init(nil, decode29Ver, minWindowSize, true, false, int64(len(want))); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		i := 0
		for i < len(got) && i < len(want) && got[i] == want[i] {
			i++
		}
		t.Fatalf("output differs from byte %d of %d (got %d bytes)", i, len(want), len(got))
	}
}
