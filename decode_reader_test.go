package rardecode

import (
	"bytes"
	"io"
	"testing"
)

// chunkDecoder writes total bytes (0, 1, 2, ...) into the window, at most
// chunk bytes per fill call, and queues a 4 byte filter at write position
// queueAt.
type chunkDecoder struct {
	n, chunk, total, queueAt int
}

func (d *chunkDecoder) init(f archiveFile, reset bool, size int64, ver int) {}
func (d *chunkDecoder) version() int                                        { return decode50Ver }

func (d *chunkDecoder) fill(dr *decodeReader) error {
	for i := 0; i < d.chunk && dr.notFull() && d.n < d.total; i++ {
		if d.n == d.queueAt {
			err := dr.queueFilter(&filterBlock{length: 4, filter: invertFilter})
			if err != nil {
				return err
			}
		}
		dr.writeByte(byte(d.n))
		d.n++
	}
	if d.n == d.total {
		return io.EOF
	}
	return nil
}

func identityFilter(b []byte, offset int64) ([]byte, error) { return b, nil }

func invertFilter(b []byte, offset int64) ([]byte, error) {
	for i := range b {
		b[i] = ^b[i]
	}
	return b, nil
}

// A filter queued by the decoder while bufBytes is still collecting the
// block of a previous filter must be placed relative to the start of that
// block, not relative to the already advanced read index.
func TestQueueFilterDuringBufBytes(t *testing.T) {
	dec := &chunkDecoder{chunk: 10, total: 30, queueAt: 18}
	d := &decodeReader{dec: dec, win: make([]byte, 64), size: 64}
	// 16 byte filter block at the start of the output; it needs two fill calls.
	d.fl = []*filterBlock{{length: 16, filter: identityFilter}}

	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, dec.total)
	for i := range want {
		want[i] = byte(i)
		if i >= dec.queueAt && i < dec.queueAt+4 {
			want[i] = ^want[i]
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}
