package rardecode

import (
	"io"
	"testing"
)

type fakeVolume struct {
	blocks []*fileBlockHeader
	data   [][]byte
	idx    int   // next block index for nextBlock
	cur    int   // current block index for Read
	off    int64 // offset within current block
}

func (v *fakeVolume) nextBlock() (*fileBlockHeader, error) {
	if v.idx >= len(v.blocks) {
		return nil, io.EOF
	}
	h := v.blocks[v.idx]
	v.cur = v.idx
	v.off = 0
	v.idx++
	return h, nil
}

func (v *fakeVolume) openBlock(volnum int, offset, size int64) error {
	// find the requested block by volnum in our list and set current
	for i, h := range v.blocks {
		if h.volnum == volnum {
			v.cur = i
			v.off = offset - h.dataOff
			if v.off < 0 {
				v.off = 0
			}
			return nil
		}
	}
	return io.EOF
}

func (v *fakeVolume) canSeek() bool { return true }

func (v *fakeVolume) Read(p []byte) (int, error) {
	b := v.data[v.cur]
	if v.off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[v.off:])
	v.off += int64(n)
	if v.off >= int64(len(b)) {
		return n, io.EOF
	}
	return n, nil
}

func (v *fakeVolume) ReadByte() (byte, error) {
	b := v.data[v.cur]
	if v.off >= int64(len(b)) {
		return 0, io.EOF
	}
	by := b[v.off]
	v.off++
	if v.off >= int64(len(b)) {
		return by, io.EOF
	}
	return by, nil
}

func TestMultiVolumeSeek_Stored_NoEncryption(t *testing.T) {
	part1 := []byte("Hello ")
	part2 := []byte("World!")
	name := "file.bin"

	h0 := &fileBlockHeader{
		first:     true,
		last:      false,
		dataOff:   0,
		packedOff: 0,
		blocknum:  0,
		volnum:    0,
		decVer:    0,
		FileHeader: FileHeader{
			Name:         name,
			PackedSize:   int64(len(part1)),
			UnPackedSize: int64(len(part1) + len(part2)),
			UnKnownSize:  false,
			Solid:        false,
		},
	}
	h1 := &fileBlockHeader{
		first:     false,
		last:      true,
		dataOff:   0,
		packedOff: int64(len(part1)),
		blocknum:  1,
		volnum:    1,
		decVer:    0,
		FileHeader: FileHeader{
			Name:         name,
			PackedSize:   int64(len(part2)),
			UnPackedSize: int64(len(part1) + len(part2)),
			UnKnownSize:  false,
			Solid:        false,
		},
	}

	fv := &fakeVolume{
		blocks: []*fileBlockHeader{h0, h1},
		data:   [][]byte{part1, part2},
	}

	opts := getOptions(nil)
	r := newReader(fv, opts)

	fh, err := r.Next()
	if err != nil {
		t.Fatalf("Next error: %v", err)
	}
	if fh.Name != name {
		t.Fatalf("unexpected name: %s", fh.Name)
	}

	// Read all content
	buf := make([]byte, fh.UnPackedSize)
	n, err := io.ReadFull(&r, buf)
	if err != nil {
		t.Fatalf("read full: %v", err)
	}
	if got, want := string(buf[:n]), string(append(part1, part2...)); got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	// Seek to position inside second volume and read rest
	if _, err = r.Seek(7, io.SeekStart); err != nil {
		t.Fatalf("seek start: %v", err)
	}
	rem, _ := io.ReadAll(&r)
	if got, want := string(rem), string(append(part1, part2...)[7:]); got != want {
		t.Fatalf("after seek got %q want %q", got, want)
	}

	// Seek from end
	if _, err = r.Seek(-3, io.SeekEnd); err != nil {
		t.Fatalf("seek end: %v", err)
	}
	last, _ := io.ReadAll(&r)
	if got, want := string(last), string(append(part1, part2...)[len(part1)+len(part2)-3:]); got != want {
		t.Fatalf("seek from end got %q want %q", got, want)
	}
}
