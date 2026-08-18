package rardecode

import (
	"bytes"
	"io"
	"testing"
)

// A crafted RAR 5.0 archive whose compressed stream encodes an LZ
// back-reference offset larger than the decode window. Before the fix
// this made the source index in copyBytes negative and panicked with a
// slice bounds out of range. Decoding malformed input must return an
// error, not panic.
func TestCopyBytesNegativeOffsetNoPanic(t *testing.T) {
	archive := []byte{82, 97, 114, 33, 26, 7, 1, 0, 243, 225, 130, 235, 11, 1, 5, 7, 0, 6, 1, 1, 128, 128, 128, 0, 102, 220, 119, 193, 35, 2, 3, 11, 158, 0, 4, 164, 0, 180, 131, 2, 105, 46, 107, 110, 128, 5, 1, 5, 97, 46, 116, 120, 116, 10, 3, 19, 24, 30, 132, 106, 141, 65, 52, 36, 198, 135, 27, 52, 67, 47, 179, 45, 196, 85, 92, 97, 32, 121, 37, 48, 48, 127, 33, 170, 243, 95, 1, 33, 88, 42, 42, 48, 48, 65}
	r, err := NewReader(bytes.NewReader(archive))
	if err != nil {
		return
	}
	for {
		if _, err := r.Next(); err != nil {
			break
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			break
		}
	}
}
