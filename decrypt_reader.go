package rardecode

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"io/fs"
)

// cipherBlockReader implements Block Mode decryption of an io.Reader object.
type cipherBlockReader struct {
	byteReader
	mode   cipher.BlockMode
	blk    cipher.Block
	initIV []byte
	bs     int
	inbuf  []byte // raw input blocks not yet decrypted
	outbuf []byte // output buffer used when output slice < block size
	block  []byte // input/output buffer for a single block
	off    int64  // plaintext offset from start
}

func (cr *cipherBlockReader) reset(iv []byte) {
	cr.mode = cipher.NewCBCDecrypter(cr.blk, iv)
	cr.inbuf = nil
	cr.outbuf = nil
}

func (cr *cipherBlockReader) fillOutbuf() error {
	l := len(cr.inbuf)
	_, err := io.ReadFull(cr.byteReader, cr.block[l:])
	if err != nil {
		return err
	}
	cr.mode.CryptBlocks(cr.block, cr.block)
	cr.outbuf = cr.block
	return nil
}

func (cr *cipherBlockReader) ReadByte() (byte, error) {
	if len(cr.outbuf) == 0 {
		err := cr.fillOutbuf()
		if err != nil {
			return 0, err
		}
	}
	b := cr.outbuf[0]
	cr.outbuf = cr.outbuf[1:]
	cr.off++
	return b, nil
}

// Read reads and decrypts data into p.
// If the input is not a multiple of the cipher block size,
// the trailing bytes will be ignored.
func (cr *cipherBlockReader) Read(p []byte) (int, error) {
	var n int
	if len(cr.outbuf) > 0 {
		n = copy(p, cr.outbuf)
		cr.outbuf = cr.outbuf[n:]
		cr.off += int64(n)
		return n, nil
	}
	blockSize := cr.bs
	if len(p) < blockSize {
		// use cr.block as buffer
		err := cr.fillOutbuf()
		if err != nil {
			return 0, err
		}
		n = copy(p, cr.outbuf)
		cr.outbuf = cr.outbuf[n:]
		cr.off += int64(n)
		return n, nil
	}
	// use p as buffer (but round down to multiple of block size)
	p = p[:len(p)-(len(p)%blockSize)]
	l := len(cr.inbuf)
	if l > 0 {
		copy(p, cr.inbuf)
		cr.inbuf = nil
	}
	n, err := io.ReadAtLeast(cr.byteReader, p[l:], blockSize-l)
	if err != nil {
		return 0, err
	}
	n += l
	p = p[:n]
	n -= n % blockSize
	if n != len(p) {
		l = copy(cr.block, p[n:])
		cr.inbuf = cr.block[:l]
		p = p[:n]
	}
	cr.mode.CryptBlocks(p, p)
	cr.off += int64(n)
	return n, nil
}

func newCipherBlockReader(r byteReader, mode cipher.BlockMode, blk cipher.Block, iv []byte) *cipherBlockReader {
	return &cipherBlockReader{
		byteReader: r,
		mode:       mode,
		blk:        blk,
		initIV:     append([]byte(nil), iv...),
		bs:         mode.BlockSize(),
		block:      make([]byte, mode.BlockSize()),
	}
}

// newAesDecryptReader returns a cipherBlockReader that decrypts input from a given io.Reader using AES.
func newAesDecryptReader(r byteReader, key, iv []byte) (*cipherBlockReader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	return newCipherBlockReader(r, mode, block, iv), nil
}

type cipherBlockFileReader struct {
	archiveFile
	cbr *cipherBlockReader
}

func (cr *cipherBlockFileReader) ReadByte() (byte, error) {
	return cr.cbr.ReadByte()
}

func (cr *cipherBlockFileReader) Read(p []byte) (int, error) {
	return cr.cbr.Read(p)
}

// Seek repositions the decrypt reader to the given plaintext offset when the underlying reader supports seeking.
func (cr *cipherBlockFileReader) Seek(offset int64, whence int) (int64, error) {
	s, ok := cr.archiveFile.(io.Seeker)
	if !ok {
		return 0, fs.ErrInvalid
	}
	// determine absolute target offset in plaintext
	switch whence {
	case io.SeekStart:
		// offset as is
	case io.SeekCurrent:
		offset += cr.cbr.off
	case io.SeekEnd:
		// not supported here; should be handled by outer limitedReadSeeker.
		return 0, fs.ErrInvalid
	default:
		return 0, fs.ErrInvalid
	}
	if offset < 0 {
		return 0, fs.ErrInvalid
	}
	bs := int64(cr.cbr.bs)
	blockIdx := offset / bs
	inBlock := int(offset % bs)
	// position underlying to the start of blockIdx and reset CBC IV appropriately
	if blockIdx == 0 {
		_, err := s.Seek(0, io.SeekStart)
		if err != nil {
			return 0, err
		}
		cr.cbr.reset(append([]byte(nil), cr.cbr.initIV...))
	} else {
		prevPos := (blockIdx - 1) * bs
		_, err := s.Seek(prevPos, io.SeekStart)
		if err != nil {
			return 0, err
		}
		// read previous ciphertext block to use as IV
		iv := make([]byte, cr.cbr.bs)
		if _, err = io.ReadFull(cr.cbr.byteReader, iv); err != nil {
			return 0, err
		}
		cr.cbr.reset(iv)
	}
	// now positioned at the start of desired block
	// set the reader position to the start of this block (if we read prev block, we're already there)
	if blockIdx == 0 {
		// already at 0
	} else {
		// after reading prev block, we're at desired block start
	}
	cr.cbr.off = blockIdx * bs
	if inBlock > 0 {
		// decrypt one block and skip inBlock bytes
		if err := cr.cbr.fillOutbuf(); err != nil {
			return 0, err
		}
		if inBlock < len(cr.cbr.outbuf) {
			cr.cbr.outbuf = cr.cbr.outbuf[inBlock:]
		} else {
			cr.cbr.outbuf = nil
		}
		cr.cbr.off += int64(inBlock)
	}
	return cr.cbr.off, nil
}

func newAesDecryptFileReader(r archiveFile, key, iv []byte) (*cipherBlockFileReader, error) {
	cbr, err := newAesDecryptReader(r, key, iv)
	if err != nil {
		return nil, err
	}
	return &cipherBlockFileReader{archiveFile: r, cbr: cbr}, nil
}
