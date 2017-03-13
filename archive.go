package rardecode

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxSfxSize = 0x100000 // maximum number of bytes to read when searching for RAR signature
	sigPrefix  = "Rar!\x1A\x07"

	fileFmt15 = iota + 1 // Version 1.5 archive file format
	fileFmt50            // Version 5.0 archive file format

	maxInt = int(^uint(0) >> 1)
)

var (
	errNoSig             = errors.New("rardecode: RAR signature not found")
	errVerMismatch       = errors.New("rardecode: volume version mistmatch")
	errCorruptHeader     = errors.New("rardecode: corrupt block header")
	errCorruptFileHeader = errors.New("rardecode: corrupt file header")
	errBadHeaderCrc      = errors.New("rardecode: bad header crc")
	errUnknownArc        = errors.New("rardecode: unknown archive version")
	errUnknownDecoder    = errors.New("rardecode: unknown decoder version")
	errArchiveContinues  = errors.New("rardecode: archive continues in next volume")
	errArchiveEnd        = errors.New("rardecode: archive end reached")
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

// findSig searches for the RAR signature and version at the beginning of a file.
// It searches no more than maxSfxSize bytes.
func (v *volume) findSig() error {
	v.off = 0
	for v.off <= maxSfxSize {
		b, err := v.br.ReadSlice(sigPrefix[0])
		v.off += int64(len(b))
		if err == bufio.ErrBufferFull {
			continue
		} else if err != nil {
			if err == io.EOF {
				err = errNoSig
			}
			return err
		}

		b, err = v.br.Peek(len(sigPrefix[1:]) + 2)
		if err != nil {
			if err == io.EOF {
				err = errNoSig
			}
			return err
		}
		if !bytes.HasPrefix(b, []byte(sigPrefix[1:])) {
			continue
		}
		b = b[len(sigPrefix)-1:]

		var ver int
		switch {
		case b[0] == 0:
			ver = fileFmt15
		case b[0] == 1 && b[1] == 0:
			ver = fileFmt50
		default:
			continue
		}
		b, err = v.br.ReadSlice('\x00')
		v.off += int64(len(b))
		if v.ver == 0 {
			v.ver = ver
		} else if v.ver != ver {
			return errVerMismatch
		}
		return err
	}
	return errNoSig
}

// volume extends a fileBlockReader to be used across multiple
// files in a multi-volume archive
type volume struct {
	fbr  fileBlockReader
	f    *os.File      // current file handle
	br   *bufio.Reader // buffered reader for current volume file
	name string        // current volume file name
	num  int           // volume number
	old  bool          // uses old naming scheme
	off  int64         // current file offset
	ver  int           // archive file format version
}

func (v *volume) clone() *volume {
	nv := new(volume)
	*nv = *v
	nv.f = nil
	nv.br = nil
	nv.fbr = v.fbr.clone()
	return nv
}

func (v *volume) discard(n int64) error {
	var err error
	v.off += n
	l := int64(v.br.Buffered())
	if n <= l {
		_, err = v.br.Discard(int(n))
	} else if v.f != nil {
		n -= l
		_, err = v.f.Seek(n, io.SeekCurrent)
		v.br.Reset(v.f)
	} else {
		for n > int64(maxInt) && err == nil {
			_, err = v.br.Discard(maxInt)
			n -= int64(maxInt)
		}
		if err == nil && n > 0 {
			_, err = v.br.Discard(int(n))
		}
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (v *volume) peek(n int) ([]byte, error) {
	b, err := v.br.Peek(n)
	if err == io.EOF && len(b) > 0 {
		err = io.ErrUnexpectedEOF
	}
	return b, err
}

func (v *volume) readSlice(n int) ([]byte, error) {
	b, err := v.br.Peek(n)
	if err == nil {
		n, err = v.br.Discard(n)
		v.off += int64(n)
		return b[:n:n], err
	}
	if err != bufio.ErrBufferFull {
		if err == io.EOF && len(b) > 0 {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	// bufio.Reader buffer is too small, create a new slice and copy to it
	b = make([]byte, n)
	if _, err = io.ReadFull(v.br, b); err != nil {
		return nil, err
	}
	v.off += int64(n)
	return b, nil
}

func (v *volume) Read(p []byte) (int, error) {
	n, err := v.br.Read(p)
	v.off += int64(n)
	return n, err
}

func nextNewVolName(file string) string {
	var inDigit bool
	var m []int
	for i, c := range file {
		if c >= '0' && c <= '9' {
			if !inDigit {
				m = append(m, i)
				inDigit = true
			}
		} else if inDigit {
			m = append(m, i)
			inDigit = false
		}
	}
	if inDigit {
		m = append(m, len(file))
	}
	if l := len(m); l >= 4 {
		// More than 1 match so assume name.part###of###.rar style.
		// Take the last 2 matches where the first is the volume number.
		m = m[l-4 : l]
		if strings.Contains(file[m[1]:m[2]], ".") || !strings.Contains(file[:m[0]], ".") {
			// Didn't match above style as volume had '.' between the two numbers or didnt have a '.'
			// before the first match. Use the second number as volume number.
			m = m[2:]
		}
	}
	// extract and increment volume number
	lo, hi := m[0], m[1]
	n, err := strconv.Atoi(file[lo:hi])
	if err != nil {
		n = 0
	} else {
		n++
	}
	// volume number must use at least the same number of characters as previous volume
	vol := fmt.Sprintf("%0"+fmt.Sprint(hi-lo)+"d", n)
	return file[:lo] + vol + file[hi:]
}

func nextOldVolName(file string) string {
	// old style volume naming
	i := strings.LastIndex(file, ".")
	// get file extension
	b := []byte(file[i+1:])

	// If 2nd and 3rd character of file extension is not a digit replace
	// with "00" and ignore any trailing characters.
	if len(b) < 3 || b[1] < '0' || b[1] > '9' || b[2] < '0' || b[2] > '9' {
		return file[:i+2] + "00"
	}

	// start incrementing volume number digits from rightmost
	for j := 2; j >= 0; j-- {
		if b[j] != '9' {
			b[j]++
			break
		}
		// digit overflow
		if j == 0 {
			// last character before '.'
			b[j] = 'A'
		} else {
			// set to '0' and loop to next character
			b[j] = '0'
		}
	}
	return file[:i+1] + string(b)
}

// nextVolName updates name to the next filename in the archive.
func (v *volume) nextVolName() {
	dir, file := filepath.Split(v.name)
	if v.num == 0 {
		// check file extensions
		i := strings.LastIndex(file, ".")
		if i < 0 {
			// no file extension, add one
			file += ".rar"
		} else {
			ext := strings.ToLower(file[i+1:])
			// replace with .rar for empty extensions & self extracting archives
			if ext == "" || ext == "exe" || ext == "sfx" {
				file = file[:i+1] + "rar"
			}
		}
		if a, ok := v.fbr.(*archive15); ok {
			v.old = a.old
		}
		// new naming scheme must have volume number in filename
		if !v.old {
			v.old = true
			for _, c := range file {
				if c >= '0' && c <= '9' {
					v.old = false
					break
				}
			}
		}
	}
	if v.old {
		file = nextOldVolName(file)
	} else {
		file = nextNewVolName(file)
	}
	v.name = dir + file
}

func (v *volume) next() (*fileBlockHeader, error) {
	if v.fbr == nil {
		return nil, io.EOF
	}
	for {
		var atEOF bool

		h, err := v.fbr.next(v)
		if len(v.name) == 0 {
			return h, err
		}

		switch err {
		case errArchiveContinues:
		case io.EOF:
			// Read all of volume without finding an end block. The only way
			// to tell if the archive continues is to try to open the next volume.
			atEOF = true
		default:
			return h, err
		}

		err = v.f.Close()
		if err != nil {
			return nil, err
		}
		v.nextVolName()
		v.f, err = os.Open(v.name) // Open next volume file
		if err != nil {
			if atEOF && os.IsNotExist(err) {
				// volume not found so assume that the archive has ended
				return nil, io.EOF
			}
			return nil, err
		}
		v.num++
		v.br.Reset(v.f)
		err = v.findSig()
		if err != nil {
			return nil, err
		}
		v.fbr.reset() // reset encryption
	}
}

func (v *volume) Close() error {
	// may be nil if os.Open fails in next()
	if v.f == nil {
		return nil
	}
	return v.f.Close()
}

func openVolume(name, password string) (*volume, error) {
	var err error
	v := &volume{name: name}
	v.f, err = os.Open(name)
	if err != nil {
		return nil, err
	}
	v.br = bufio.NewReader(v.f)
	v.fbr, err = newFileBlockReader(v, password)
	if err != nil {
		_ = v.f.Close() // can only return one error so ignore Close error
		return nil, err
	}
	return v, nil
}

func newFileBlockReader(v *volume, pass string) (fileBlockReader, error) {
	runes := []rune(pass)
	if len(runes) > maxPassword {
		pass = string(runes[:maxPassword])
	}
	err := v.findSig()
	if err != nil {
		return nil, err
	}
	switch v.ver {
	case fileFmt15:
		return newArchive15(pass), nil
	case fileFmt50:
		return newArchive50(pass), nil
	}
	return nil, errUnknownArc
}
