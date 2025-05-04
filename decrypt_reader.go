package rardecode

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

// cipherBlockReader implements Block Mode decryption of an io.Reader object.
type cipherBlockReader struct {
	byteReader
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
	return n, nil
}

func newCipherBlockReader(r byteReader, getMode func() (cipher.BlockMode, error)) *cipherBlockReader {
	return &cipherBlockReader{byteReader: r, getMode: getMode}
}

// newAesDecryptReader returns a cipherBlockReader that decrypts input from a given io.Reader using AES.
func newAesDecryptReader(r byteReader, getKeys func() ([]byte, []byte, error)) *cipherBlockReader {
	getMode := func() (cipher.BlockMode, error) {
		key, iv, err := getKeys()
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewCBCDecrypter(block, iv), nil
	}
	return newCipherBlockReader(r, getMode)
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

func newAesDecryptFileReader(r archiveFile, getKeys func() ([]byte, []byte, error)) *cipherBlockFileReader {
	cbr := newAesDecryptReader(r, getKeys)
	return &cipherBlockFileReader{archiveFile: r, cbr: cbr}
}
