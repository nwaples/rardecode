package rardecode

import (
	"errors"
	"hash"
)

const (
	_ = iota
	decode20Ver
	decode29Ver
	decode50Ver
	decode70Ver

	archiveVersion15 = 0
	archiveVersion50 = 1
)

var (
	ErrCorruptBlockHeader    = errors.New("rardecode: corrupt block header")
	ErrCorruptFileHeader     = errors.New("rardecode: corrupt file header")
	ErrBadHeaderCRC          = errors.New("rardecode: bad header crc")
	ErrUnknownDecoder        = errors.New("rardecode: unknown decoder version")
	ErrDecoderOutOfData      = errors.New("rardecode: decoder expected more data than is in packed file")
	ErrArchiveEncrypted      = errors.New("rardecode: archive encrypted, password required")
	ErrArchivedFileEncrypted = errors.New("rardecode: archived files encrypted, password required")
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

func (b *readBuf) uint64() uint64 {
	v := uint64((*b)[0]) | uint64((*b)[1])<<8 | uint64((*b)[2])<<16 | uint64((*b)[3])<<24 |
		uint64((*b)[4])<<32 | uint64((*b)[5])<<40 | uint64((*b)[6])<<48 | uint64((*b)[7])<<56
	*b = (*b)[8:]
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

// fileBlockHeader represents a file block in a RAR archive.
// Files may comprise one or more file blocks.
// Solid files retain decode tables and dictionary from previous solid files in the archive.
type fileBlockHeader struct {
	first    bool             // first block in file
	last     bool             // last block in file
	arcSolid bool             // archive is solid
	winSize  int              // decode window size
	hash     func() hash.Hash // hash used for file checksum
	hashKey  []byte           // optional hmac key to be used calculate file checksum
	sum      []byte           // expected checksum for file contents
	decVer   int              // decoder to use for file
	key      []byte           // key for AES, non-empty if file encrypted
	iv       []byte           // iv for AES, non-empty if file encrypted
	genKeys  func() error     // generates key & iv fields
	FileHeader
}

func (f *fileBlockHeader) getKeys() (key, iv []byte, err error) {
	if f.key == nil {
		err := f.genKeys()
		if err != nil {
			return nil, nil, err
		}
	}
	return f.key, f.iv, nil
}

// fileBlockReader returns the next fileBlockHeader in a volume.
type fileBlockReader interface {
	next(v *volume) (*fileBlockHeader, error) // reads the volume and returns the next fileBlockHeader
	clone() fileBlockReader                   // makes a copy of the fileBlockReader
}
