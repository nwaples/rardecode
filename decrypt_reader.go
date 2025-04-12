package rardecode

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

// cipherBlockSliceReader is a sliceReader that users a cipher.BlockMode to decrypt the input.
type cipherBlockSliceReader struct {
	r    sliceReader
	mode cipher.BlockMode
	n    int // bytes encrypted but not read
}

func (c *cipherBlockSliceReader) sizeInBlocks(n int) int {
	bs := c.mode.BlockSize()
	if rem := n % bs; rem > 0 {
		n += bs - rem
	}
	return n
}

func (c *cipherBlockSliceReader) peek(n int) ([]byte, error) {
	bn := c.sizeInBlocks(n)
	b, err := c.r.peek(bn)
	if err != nil {
		if err == io.EOF && len(b) > 0 {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if c.n < bn {
		c.mode.CryptBlocks(b[c.n:], b[c.n:])
		c.n = bn
	}
	return b[:n], nil
}

// readSlice returns the next n bytes of decrypted input.
// If n is not a multiple of the block size, the trailing bytes
// of the last decrypted block will be discarded.
func (c *cipherBlockSliceReader) readSlice(n int) ([]byte, error) {
	bn := c.sizeInBlocks(n)
	b, err := c.r.readSlice(bn)
	if err != nil {
		return nil, err
	}
	if c.n < bn {
		c.mode.CryptBlocks(b[c.n:], b[c.n:])
		c.n = 0
	} else {
		c.n -= bn
	}
	// ignore padding at end of last block
	b = b[:n]
	return b, nil
}

// newAesSliceReader creates a sliceReader that uses AES to decrypt the input
func newAesSliceReader(r sliceReader, key, iv []byte) *cipherBlockSliceReader {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	return &cipherBlockSliceReader{r: r, mode: mode}
}

// cipherBlockReader implements Block Mode decryption of an io.Reader object.
type cipherBlockReader struct {
	r       byteReader
	mode    cipher.BlockMode
	getMode func() (cipher.BlockMode, error)
	inbuf   []byte // raw input blocks not yet decrypted
	outbuf  []byte // output buffer used when output slice < block size
	block   []byte // input/output buffer for a single block
}

func (cr *cipherBlockReader) fillOutbuf() error {
	if cr.mode == nil {
		var err error
		cr.mode, err = cr.getMode()
		if err != nil {
			return err
		}
		cr.block = make([]byte, cr.mode.BlockSize())
	}
	l := len(cr.inbuf)
	_, err := io.ReadFull(cr.r, cr.block[l:])
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
		return n, nil
	}
	if cr.mode == nil {
		var err error
		cr.mode, err = cr.getMode()
		if err != nil {
			return 0, err
		}
		cr.block = make([]byte, cr.mode.BlockSize())
	}
	blockSize := cr.mode.BlockSize()
	if len(p) < blockSize {
		// use cr.block as buffer
		err := cr.fillOutbuf()
		if err != nil {
			return 0, err
		}
		n = copy(p, cr.outbuf)
		cr.outbuf = cr.outbuf[n:]
		return n, nil
	}
	// use p as buffer (but round down to multiple of block size)
	p = p[:len(p)-(len(p)%blockSize)]
	l := len(cr.inbuf)
	if l > 0 {
		copy(p, cr.inbuf)
		cr.inbuf = nil
	}
	n, err := io.ReadAtLeast(cr.r, p[l:], blockSize-l)
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
	return n, nil
}

func newCipherBlockReader(r byteReader, getMode func() (cipher.BlockMode, error)) *cipherBlockReader {
	c := &cipherBlockReader{r: r, getMode: getMode}
	return c
}

// newAesDecryptReader returns a cipherBlockReader that decrypts input from a given io.Reader using AES.
func newAesDecryptReader(r byteReader, h *fileBlockHeader) *cipherBlockReader {
	getMode := func() (cipher.BlockMode, error) {
		if h.key == nil {
			err := h.genKeys()
			if err != nil {
				return nil, err
			}
		}
		block, err := aes.NewCipher(h.key)
		if err != nil {
			return nil, err
		}
		return cipher.NewCBCDecrypter(block, h.iv), nil
	}
	return newCipherBlockReader(r, getMode)
}
