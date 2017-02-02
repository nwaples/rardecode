package rardecode

import (
	"errors"
	"io"
)

const (
	minWindowSize    = 0x40000
	maxQueuedFilters = 8192
)

var (
	errTooManyFilters = errors.New("rardecode: too many filters")
	errInvalidFilter  = errors.New("rardecode: invalid filter")
)

// filter functions take a byte slice, the current output offset and
// returns transformed data.
type filter func(b []byte, offset int64) ([]byte, error)

// filterBlock is a block of data to be processed by a filter.
type filterBlock struct {
	length int    // length of block
	offset int    // bytes to be read before start of block
	filter filter // filter function
}

// decoder is the interface for decoding compressed data
type decoder interface {
	init(r io.ByteReader, reset bool) error // initialize decoder for current file
	fill(w *window) ([]*filterBlock, error) // fill window with decoded data, returning any filters
	version() int                           // decoder version
}

// window is a sliding window buffer.
// Writes will not be allowed to wrap around until all bytes have been read.
type window struct {
	buf  []byte
	size int // buf length
	mask int // buf length mask
	r    int // index in buf for reads (beginning)
	w    int // index in buf for writes (end)
	l    int // length of bytes to be processed by copyBytes
	o    int // offset of bytes to be processed by copyBytes
}

// buffered returns the number of bytes yet to be read from window
func (w *window) buffered() int { return w.w - w.r }

// available returns the number of bytes that can be written before the window is full
func (w *window) available() int { return w.size - w.w }

func (w *window) reset(log2size uint, clear bool) {
	size := 1 << log2size
	if size < minWindowSize {
		size = minWindowSize
	}
	if size > len(w.buf) {
		b := make([]byte, size)
		if clear {
			w.w = 0
		} else if len(w.buf) > 0 {
			n := copy(b, w.buf[w.w:])
			n += copy(b[n:], w.buf[:w.w])
			w.w = n
		}
		w.buf = b
		w.size = size
		w.mask = size - 1
	} else if clear {
		for i := range w.buf {
			w.buf[i] = 0
		}
		w.w = 0
	}
	w.r = w.w
}

// writeByte writes c to the end of the window
func (w *window) writeByte(c byte) {
	w.buf[w.w] = c
	w.w++
}

// copyBytes copies len bytes at off distance from the end
// to the end of the window.
func (w *window) copyBytes(length, offset int) {
	w.l = length & w.mask
	w.o = offset

	i := (w.w - w.o) & w.mask
	iend := i + w.l
	if i > w.w {
		if iend > w.size {
			iend = w.size
		}
		n := copy(w.buf[w.w:], w.buf[i:iend])
		w.w += n
		w.l -= n
		if w.l == 0 {
			return
		}
		iend = w.l
		i = 0
	}
	if iend <= w.w {
		n := copy(w.buf[w.w:], w.buf[i:iend])
		w.w += n
		w.l -= n
		return
	}
	for w.l > 0 && w.w < w.size {
		w.buf[w.w] = w.buf[i]
		w.w++
		i++
		w.l--
	}
}

func (w *window) bytes() []byte {
	if w.l > 0 && w.w < w.size {
		// if there is any space available, copy any
		// leftover data from a previous copyBytes.
		w.copyBytes(w.l, w.o)
	}
	b := w.buf[w.r:w.w]
	if w.w == w.size {
		// start from beginning of window again
		w.w = 0
	}
	w.r = w.w
	return b
}

// decodeReader implements io.Reader for decoding compressed data in RAR archives.
type decodeReader struct {
	win     window  // sliding window buffer used as decode dictionary
	dec     decoder // decoder being used to unpack file
	tot     int64   // total bytes read
	buf     []byte  // filter input/output buffer
	outbuf  []byte  // output not yet read
	winbuf  []byte  // unprocessed window bytes output
	err     error
	filters []*filterBlock // list of filterBlock's, each with offset relative to previous in list
}

func (d *decodeReader) init(r io.ByteReader, ver int, winsize uint, reset bool) error {
	if reset {
		d.filters = nil
	}
	d.err = nil
	if cap(d.buf) > 0 {
		d.buf = d.buf[:0]
	}
	d.outbuf = nil
	d.winbuf = nil
	d.tot = 0
	d.win.reset(winsize, reset)
	if d.dec == nil {
		switch ver {
		case decode29Ver:
			d.dec = new(decoder29)
		case decode50Ver:
			d.dec = new(decoder50)
		default:
			return errUnknownDecoder
		}
	} else if d.dec.version() != ver {
		return errMultipleDecoders
	}
	return d.dec.init(r, reset)
}

func (d *decodeReader) readErr() error {
	err := d.err
	d.err = nil
	return err
}

// queueFilter adds a filterBlock to the end decodeReader's filters.
func (d *decodeReader) queueFilter(f *filterBlock) error {
	if len(d.filters) >= maxQueuedFilters {
		return errTooManyFilters
	}
	// offset & length must be < window size
	f.offset &= d.win.mask
	f.length &= d.win.mask
	// make offset relative to previous filter in list
	for _, fb := range d.filters {
		if f.offset < fb.offset {
			// filter block must not start before previous filter
			return errInvalidFilter
		}
		f.offset -= fb.offset
	}
	d.filters = append(d.filters, f)
	return nil
}

// processFilters processes any filters valid at the current read index
// and stores the output in outbuf.
func (d *decodeReader) processFilters() (err error) {
	f := d.filters[0]
	if f.offset > 0 {
		return nil
	}
	d.filters = d.filters[1:]

	n := f.length
	d.outbuf = d.buf
	d.buf = d.buf[:0]
	for {
		// run filter passing buffer and total bytes read so far
		d.outbuf, err = f.filter(d.outbuf, d.tot)
		if err != nil {
			return err
		}
		if cap(d.outbuf) > cap(d.buf) {
			// Filter returned a bigger buffer, save it for future filters.
			d.buf = d.outbuf[:0]
		}
		if len(d.filters) == 0 {
			return nil
		}
		f = d.filters[0]

		if f.offset != 0 {
			// next filter not at current offset
			f.offset -= n
			return nil
		}
		if f.length != len(d.outbuf) {
			return errInvalidFilter
		}
		d.filters = d.filters[1:]

		if cap(d.outbuf) < cap(d.buf) {
			// Filter returned a smaller buffer. Copy it back to the saved buffer
			// so the next filter can make use of the larger buffer if needed.
			d.outbuf = append(d.buf[:0], d.outbuf...)
		}
	}
}

// fill fills the decodeReader's window
func (d *decodeReader) fill() {
	if d.err != nil {
		return
	}
	var fl []*filterBlock
	fl, d.err = d.dec.fill(&d.win) // fill window using decoder
	for _, f := range fl {
		err := d.queueFilter(f)
		if err != nil {
			d.err = err
			return
		}
	}
}

// readBytes returns a byte slice of upto n bytes,
func (d *decodeReader) readBytes(n int) ([]byte, error) {
	for len(d.outbuf) == 0 {
		l := len(d.winbuf)
		if l == 0 {
			// get new window buffer
			d.winbuf = d.win.bytes()
			if l = len(d.winbuf); l == 0 {
				d.fill()
				d.winbuf = d.win.bytes()
				if l = len(d.winbuf); l == 0 {
					return nil, d.readErr()
				}
			}
		}
		// process window buffer
		if len(d.filters) == 0 {
			// no filters so can direct output
			d.outbuf = d.winbuf
			d.winbuf = nil
		} else {
			f := d.filters[0]
			if f.offset > 0 {
				// move window bytes before filter to output buffer
				if f.offset < l {
					l = f.offset
				}
				d.outbuf, d.winbuf = d.winbuf[:l], d.winbuf[l:]
				f.offset -= l
			} else {
				if cap(d.buf) < f.length {
					d.buf = make([]byte, 0, f.length)
				}
				nn := f.length - len(d.buf)
				if l >= nn {
					d.buf = append(d.buf, d.winbuf[:nn]...)
					d.winbuf = d.winbuf[nn:]
					if err := d.processFilters(); err != nil {
						return nil, err
					}
				} else {
					// not enough bytes for filter, copy to buffer and loop to get more
					d.buf = append(d.buf, d.winbuf...)
				}
			}
		}
	}
	if l := len(d.outbuf); l < n {
		n = l
	}
	b := d.outbuf[:n]
	d.outbuf = d.outbuf[n:]
	d.tot += int64(len(b))
	return b, nil
}

// Read decodes data and stores it in p.
func (d *decodeReader) Read(p []byte) (int, error) {
	b, err := d.readBytes(len(p))
	n := copy(p, b)
	return n, err
}
