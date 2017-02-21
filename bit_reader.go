package rardecode

import "io"

type bitReader interface {
	readBits(n uint8) (int, error) // read n bits of data
	unreadBits(n uint8)            // revert the reading of the last n bits read
}

// limitedBitReader is a bitReader that reads from rarBitReader and stops with io.EOF after l bits.
// If rarBitReader returns an io.EOF before reading l bits, err is returned.
type limitedBitReader struct {
	*rarBitReader
	l   int
	err error
}

func (l *limitedBitReader) readBits(n uint8) (int, error) {
	for n > l.n {
		if l.l == 0 {
			// reached bits limit
			return 0, io.EOF
		}
		if len(l.b) == 0 {
			var err error
			l.b, err = l.r.bytes()
			if err != nil {
				if err == io.EOF {
					// io.EOF before we reached bit limit
					err = l.err
				}
				return 0, err
			}
		}
		l.v = l.v<<8 | int(l.b[0])
		l.b = l.b[1:]
		l.n += 8
		l.l -= 8
		if l.l < 0 {
			// overshot, remove the extra bits
			bits := uint8(-l.l)
			l.l = 0
			l.v >>= bits
			l.n -= bits
		}
	}
	l.n -= n
	return (l.v >> l.n) & ((1 << n) - 1), nil
}

// rarBitReader wraps an io.ByteReader to perform various bit and byte
// reading utility functions used in RAR file processing.
type rarBitReader struct {
	r byteReader
	v int
	n uint8
	b []byte
}

func (r *rarBitReader) reset(br byteReader) {
	r.r = br
	r.n = 0
	r.v = 0
	r.b = nil
}

func (r *rarBitReader) readBits(n uint8) (int, error) {
	for n > r.n {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		r.v = r.v<<8 | int(c)
		r.n += 8
	}
	r.n -= n
	return (r.v >> r.n) & ((1 << n) - 1), nil
}

func (r *rarBitReader) unreadBits(n uint8) {
	r.n += n
}

// alignByte aligns the current bit reading input to the next byte boundary.
func (r *rarBitReader) alignByte() {
	r.n -= r.n % 8
}

// readUint32 reads a RAR V3 encoded uint32
func (r *rarBitReader) readUint32() (uint32, error) {
	n, err := r.readBits(2)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		n, err = r.readBits(4 << uint(n))
		return uint32(n), err
	}
	n, err = r.readBits(4)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		n, err = r.readBits(8)
		n |= -1 << 8
		return uint32(n), err
	}
	nlow, err := r.readBits(4)
	n = n<<4 | nlow
	return uint32(n), err
}

// ReadByte() returns a byte directly from buf b or the io.ByteReader r.
// Current bit offsets are ignored.
func (r *rarBitReader) ReadByte() (byte, error) {
	if len(r.b) == 0 {
		if r.r == nil {
			return 0, io.EOF
		}
		var err error
		r.b, err = r.r.bytes()
		if err != nil {
			return 0, err
		}
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c, nil
}

// readFull reads len(p) bytes into p. If fewer bytes are read an error is returned.
func (r *rarBitReader) readFull(p []byte) error {
	if r.n == 0 && len(r.b) > 0 {
		n := copy(p, r.b)
		p = p[n:]
		r.b = r.b[n:]
	}
	for i := range p {
		n, err := r.readBits(8)
		if err != nil {
			return err
		}
		p[i] = byte(n)
	}
	return nil
}

func newRarBitReader(r byteReader) *rarBitReader {
	return &rarBitReader{r: r}
}
