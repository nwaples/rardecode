package rardecode

import (
	"bytes"
	"io"
	"testing"
)

// stubOp is a literal when length is zero, otherwise a match.
type stubOp struct {
	literal byte
	length  int
	offset  int
}

// stubDecoder replays a fixed program so decodeReader's window handling can
// be exercised without a real compressed stream.
type stubDecoder struct {
	ops  []stubOp
	next int
}

func (s *stubDecoder) init(byteReader, bool, int64, int) {}

func (s *stubDecoder) version() int { return decode50Ver }

func (s *stubDecoder) fill(dr *decodeReader) error {
	for dr.notFull() {
		if s.next == len(s.ops) {
			return io.EOF
		}
		o := s.ops[s.next]
		s.next++
		if o.length == 0 {
			dr.writeByte(o.literal)
			continue
		}
		dr.copyBytes(o.length, o.offset)
	}
	return nil
}

// A match whose length runs past the end of the decode window used to be
// silently truncated at the window boundary, so the bytes that did not fit
// were never emitted and the file decoded short.
func TestCopyBytesAcrossWindowWrap(t *testing.T) {
	const (
		size     = minWindowSize
		matchLen = 64
		offset   = 32
		// Leave room for half the match, so the rest lands after the wrap.
		lead = size - matchLen/2
	)

	ops := make([]stubOp, 0, lead+1)
	want := make([]byte, 0, lead+matchLen)
	for i := 0; i < lead; i++ {
		c := byte(i)
		ops = append(ops, stubOp{literal: c})
		want = append(want, c)
	}
	ops = append(ops, stubOp{length: matchLen, offset: offset})
	for i := 0; i < matchLen; i++ {
		want = append(want, want[len(want)-offset])
	}

	d := &decodeReader{win: make([]byte, size), size: size, dec: &stubDecoder{ops: ops}}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d bytes, want %d", len(got), len(want))
	}
	if !bytes.Equal(got, want) {
		t.Error("decoded data differs from the expected match expansion")
	}
}
