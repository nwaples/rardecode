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
// If n is not a mulitple of the block size, the trailing bytes
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
	r      *packedFileReader
	mode   cipher.BlockMode
	inbuf  []byte // raw input blocks not yet decrypted
	outbuf []byte // output buffer used when output slice < block size
	err    error
}

// Read reads and decrypts data into p.
// If the input is not a multiple of the cipher block size,
// the trailing bytes will be ignored.
func (cr *cipherBlockReader) Read(p []byte) (int, error) {
	bs := cr.mode.BlockSize()
	if len(cr.outbuf) > 0 {
		n := copy(p, cr.outbuf)
		cr.outbuf = cr.outbuf[n:]
		return n, nil
	}
	// get input blocks
	for len(cr.inbuf) == 0 {
		var err error
		cr.inbuf, err = cr.r.blocks(bs)
		if err != nil {
			return 0, err
		}
	}
	if len(p) < bs {
		// output slice is smaller than block size, so decrypt one
		// block and save the remaining bytes in outbuf.
		cr.outbuf = cr.inbuf[:bs]
		cr.inbuf = cr.inbuf[bs:]
		cr.mode.CryptBlocks(cr.outbuf, cr.outbuf)
		n := copy(p, cr.outbuf)
		cr.outbuf = cr.outbuf[n:]
		return n, nil
	}
	// round p down to a multiple of block size
	n := len(p)
	n = n - n%bs
	if nn := len(cr.inbuf); nn < n {
		n = nn
	}
	cr.mode.CryptBlocks(p[:n], cr.inbuf[:n])
	cr.inbuf = cr.inbuf[n:]
	return n, nil
}

// ReadByte returns the next decrypted byte.
func (cr *cipherBlockReader) ReadByte() (byte, error) {
	bs := cr.mode.BlockSize()
	if len(cr.outbuf) == 0 {
		for len(cr.inbuf) == 0 {
			var err error
			cr.inbuf, err = cr.r.blocks(bs)
			if err != nil {
				return 0, err
			}
		}
		// decrypt one block and save to outbuf
		cr.outbuf = cr.inbuf[:bs]
		cr.inbuf = cr.inbuf[bs:]
		cr.mode.CryptBlocks(cr.outbuf, cr.outbuf)
	}
	c := cr.outbuf[0]
	cr.outbuf = cr.outbuf[1:]
	return c, nil
}

// bytes returns a byte slice of decrypted data.
func (cr *cipherBlockReader) bytes() ([]byte, error) {
	if len(cr.outbuf) > 0 {
		b := cr.outbuf
		cr.outbuf = nil
		return b, nil
	}
	b := cr.inbuf
	cr.inbuf = nil
	for len(b) == 0 {
		var err error
		b, err = cr.r.blocks(cr.mode.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	cr.mode.CryptBlocks(b, b)
	return b, nil
}

// newAesDecryptReader returns a cipherBlockReader that decrypts input from a given io.Reader using AES.
// It will panic if the provided key is invalid.
func newAesDecryptReader(r *packedFileReader, key, iv []byte) *cipherBlockReader {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	return &cipherBlockReader{r: r, mode: mode}
}
