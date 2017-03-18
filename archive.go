package rardecode

import (
	"bufio"
	"errors"
	"hash"
	"io"
)

const (
	_ = iota
	decode29Ver
	decode50Ver
)

var (
	errCorruptHeader     = errors.New("rardecode: corrupt block header")
	errCorruptFileHeader = errors.New("rardecode: corrupt file header")
	errBadHeaderCrc      = errors.New("rardecode: bad header crc")
	errUnknownDecoder    = errors.New("rardecode: unknown decoder version")
	errDecoderOutOfData  = errors.New("rardecode: decoder expected more data than is in packed file")
)

type readBuf []byte

func (b *readBuf) byte() byte {
	v := (*b)[0]
	*b = (*b)[1:]
	return v
}

func (b *readBuf) uint16() uint16 {
	v := uint16((*b)[0]) | uint16((*b)[1])<<8
	*b = (*b)[2:]
	return v
}

func (b *readBuf) uint32() uint32 {
	v := uint32((*b)[0]) | uint32((*b)[1])<<8 | uint32((*b)[2])<<16 | uint32((*b)[3])<<24
	*b = (*b)[4:]
	return v
}

func (b *readBuf) bytes(n int) []byte {
	v := (*b)[:n]
	*b = (*b)[n:]
	return v
}

func (b *readBuf) uvarint() uint64 {
	var x uint64
	var s uint
	for i, n := range *b {
		if n < 0x80 {
			*b = (*b)[i+1:]
			return x | uint64(n)<<s
		}
		x |= uint64(n&0x7f) << s
		s += 7

	}
	// if we run out of bytes, just return 0
	*b = (*b)[len(*b):]
	return 0
}

// sliceReader implements the readSlice and peek functions.
// The slices returned are only valid till the next readSlice or peek call.
// If n bytes arent available no slice will be returned with the error value set.
// The error is io.EOF only of 0 bytes were found, otherwise io.ErrUnexpectedEOF
// will be returned on a short read.
// The capacity of the slice returned by readSlice must reflect how much data was read
// to return the n bytes (eg. an encrypted reader has to decrypt in multiples of a
// block size so may need to read more than n bytes).
type sliceReader interface {
	readSlice(n int) ([]byte, error) // return the next n bytes
	peek(n int) ([]byte, error)      // return the next n bytes withough advancing reader
}

// blockReader provides access to a block of data on a volume
type blockReader struct {
	n int64 // bytes left in current data block
	v *volume
	r fileBlockReader
}

// init initializes a cloned volume
func (l *blockReader) init() error { return l.v.init() }

func (l *blockReader) clone() *blockReader {
	nr := &blockReader{n: l.n}
	nr.r = l.r.clone()
	nr.v = l.v.clone()
	return nr
}

func (l *blockReader) Close() error { return l.v.Close() }

// Read reads from v and stops with io.EOF after n bytes.
// If v returns an io.EOF before reading n bytes, io.ErrUnexpectedEOF is returned.
func (l *blockReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[0:l.n]
	}
	n, err := l.v.Read(p)
	l.n -= int64(n)
	if err == io.EOF && l.n > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// next advances to the next file block in the archive.
func (l *blockReader) next() (*fileBlockHeader, error) {
	if l.r == nil {
		return nil, io.EOF
	}
	if l.n > 0 {
		// discard current block data
		if err := l.v.discard(l.n); err != nil {
			return nil, err
		}
		l.n = 0
	}
	// get next file block
	h, err := l.r.next(l.v)
	if h != nil {
		l.n = h.PackedSize
	}
	return h, err
}

// bytes returns a byte slice from the current volume.
// bytes will only return up to l.n bytes before returning io.EOF.
func (l *blockReader) bytes() ([]byte, error) {
	if l.n == 0 {
		return nil, io.EOF
	}
	n := maxInt
	if l.n < int64(n) {
		n = int(l.n)
	}
	if k := l.v.br.Buffered(); k > 0 {
		if k < n {
			n = k
		}
	} else {
		b, err := l.v.peek(n)
		if err != nil && err != bufio.ErrBufferFull {
			return nil, err
		}
		n = len(b)
	}
	b, err := l.v.readSlice(n)
	l.n -= int64(len(b))
	return b, err
}

// fileBlockHeader represents a file block in a RAR archive.
// Files may comprise one or more file blocks.
// Solid files retain decode tables and dictionary from previous solid files in the archive.
type fileBlockHeader struct {
	first    bool      // first block in file
	last     bool      // last block in file
	arcSolid bool      // archive is solid
	winSize  uint      // log base 2 of decode window size
	hash     hash.Hash // hash used for file checksum
	hashKey  []byte    // optional hmac key to be used calculate file checksum
	sum      []byte    // expected checksum for file contents
	decVer   int       // decoder to use for file
	key      []byte    // key for AES, non-empty if file encrypted
	iv       []byte    // iv for AES, non-empty if file encrypted
	FileHeader
}

// fileBlockReader returns the next fileBlockHeader in a volume.
type fileBlockReader interface {
	next(v *volume) (*fileBlockHeader, error) // reads the volume and returns the next fileBlockHeader
	clone() fileBlockReader                   // makes a copy of the fileBlockReader
}

func newFileBlockReader(v *volume, pass string) (*blockReader, error) {
	runes := []rune(pass)
	if len(runes) > maxPassword {
		pass = string(runes[:maxPassword])
	}
	b := &blockReader{v: v}
	switch v.ver {
	case 0:
		b.r = newArchive15(pass)
	case 1:
		b.r = newArchive50(pass)
	default:
		return nil, errUnknownArc
	}
	return b, nil
}

func newArchive(r io.Reader, pass string) (*blockReader, error) {
	v, err := newVolume(r)
	if err != nil {
		return nil, err
	}
	return newFileBlockReader(v, pass)
}

func openArchive(name string, pass string) (*blockReader, error) {
	v, err := openVolume(name)
	if err != nil {
		return nil, err
	}
	return newFileBlockReader(v, pass)
}
