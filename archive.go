package rardecode

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
	errNoSig              = errors.New("rardecode: RAR signature not found")
	errVerMismatch        = errors.New("rardecode: volume version mistmatch")
	errCorruptHeader      = errors.New("rardecode: corrupt block header")
	errCorruptFileHeader  = errors.New("rardecode: corrupt file header")
	errBadHeaderCrc       = errors.New("rardecode: bad header crc")
	errUnknownArc         = errors.New("rardecode: unknown archive version")
	errUnknownDecoder     = errors.New("rardecode: unknown decoder version")
	errUnsupportedDecoder = errors.New("rardecode: unsupported decoder version")
	errArchiveContinues   = errors.New("rardecode: archive continues in next volume")
	errArchiveEnd         = errors.New("rardecode: archive end reached")
	errDecoderOutOfData   = errors.New("rardecode: decoder expected more data than is in packed file")
	errOffsetNotSupported = errors.New("rardecode: volume doesn't support file offset")

	reDigits = regexp.MustCompile(`\d+`)
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
type sliceReader interface {
	readSlice(n int) ([]byte, error) // return the next n bytes
	peek(n int) ([]byte, error)      // return the next n bytes withough advancing reader
}

type discardReader struct {
	*bufio.Reader
	rs io.ReadSeeker
}

func (dr *discardReader) discard(n int64) error {
	var err error
	l := int64(dr.Buffered())
	if n <= l {
		_, err = dr.Discard(int(n))
	} else if dr.rs != nil {
		n -= l
		_, err = dr.rs.Seek(n, io.SeekCurrent)
		dr.Reset(dr.rs)
	} else {
		for n > int64(maxInt) && err == nil {
			_, err = dr.Discard(maxInt)
			n -= int64(maxInt)
		}
		if err == nil && n > 0 {
			_, err = dr.Discard(int(n))
		}
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (dr *discardReader) peek(n int) ([]byte, error) {
	b, err := dr.Peek(n)
	if err == io.EOF && len(b) > 0 {
		err = io.ErrUnexpectedEOF
	}
	return b, err
}

func (dr *discardReader) readSlice(n int) ([]byte, error) {
	b, err := dr.Peek(n)
	if err == nil {
		_, _ = dr.Discard(n)
		return b, nil
	}
	if err != bufio.ErrBufferFull {
		if err == io.EOF && len(b) > 0 {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	// bufio.Reader buffer is too small, create a new slice and copy to it
	b = make([]byte, n)
	if _, err = io.ReadFull(dr, b); err != nil {
		return nil, err
	}
	return b, nil
}

// findSig searches for the RAR signature and version at the beginning of a file.
// It searches no more than maxSfxSize bytes.
func findSig(br *bufio.Reader) (int, error) {
	for n := 0; n <= maxSfxSize; {
		b, err := br.ReadSlice(sigPrefix[0])
		n += len(b)
		if err == bufio.ErrBufferFull {
			continue
		} else if err != nil {
			if err == io.EOF {
				err = errNoSig
			}
			return 0, err
		}

		b, err = br.Peek(len(sigPrefix[1:]) + 2)
		if err != nil {
			if err == io.EOF {
				err = errNoSig
			}
			return 0, err
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
		_, _ = br.ReadSlice('\x00')

		return ver, nil
	}
	return 0, errNoSig
}

// volume extends a fileBlockReader to be used across multiple
// files in a multi-volume archive
type volume struct {
	fbr  fileBlockReader
	f    *os.File      // current file handle
	br   *bufio.Reader // buffered reader for current volume file
	dir  string        // volume directory
	file string        // current volume file
	num  int           // volume number
	old  bool          // uses old naming scheme
}

func (v *volume) clone() *volume {
	nv := &volume{dir: v.dir, file: v.file, num: v.num, old: v.old}
	nv.fbr = v.fbr.clone()
	return nv
}

func (v *volume) offset() (int64, error) {
	// offset should only be called on volumes with v.f set.
	if v.f == nil {
		return 0, errOffsetNotSupported
	}
	n, err := v.f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	n -= int64(v.br.Buffered())
	return n, nil
}

// nextVolName updates name to the next filename in the archive.
func (v *volume) nextVolName() {
	if v.num == 0 {
		// check file extensions
		i := strings.LastIndex(v.file, ".")
		if i < 0 {
			// no file extension, add one
			i = len(v.file)
			v.file += ".rar"
		} else {
			ext := strings.ToLower(v.file[i+1:])
			// replace with .rar for empty extensions & self extracting archives
			if ext == "" || ext == "exe" || ext == "sfx" {
				v.file = v.file[:i+1] + "rar"
			}
		}
		if a, ok := v.fbr.(*archive15); ok {
			v.old = a.old
		}
		// new naming scheme must have volume number in filename
		if !v.old && reDigits.FindStringIndex(v.file) == nil {
			v.old = true
		}
		// For old style naming if 2nd and 3rd character of file extension is not a digit replace
		// with "00" and ignore any trailing characters.
		if v.old && (len(v.file) < i+4 || v.file[i+2] < '0' || v.file[i+2] > '9' || v.file[i+3] < '0' || v.file[i+3] > '9') {
			v.file = v.file[:i+2] + "00"
			return
		}
	}
	// new style volume naming
	if !v.old {
		// find all numbers in volume name
		m := reDigits.FindAllStringIndex(v.file, -1)
		if l := len(m); l > 1 {
			// More than 1 match so assume name.part###of###.rar style.
			// Take the last 2 matches where the first is the volume number.
			m = m[l-2 : l]
			if strings.Contains(v.file[m[0][1]:m[1][0]], ".") || !strings.Contains(v.file[:m[0][0]], ".") {
				// Didn't match above style as volume had '.' between the two numbers or didnt have a '.'
				// before the first match. Use the second number as volume number.
				m = m[1:]
			}
		}
		// extract and increment volume number
		lo, hi := m[0][0], m[0][1]
		n, err := strconv.Atoi(v.file[lo:hi])
		if err != nil {
			n = 0
		} else {
			n++
		}
		// volume number must use at least the same number of characters as previous volume
		vol := fmt.Sprintf("%0"+fmt.Sprint(hi-lo)+"d", n)
		v.file = v.file[:lo] + vol + v.file[hi:]
		return
	}
	// old style volume naming
	i := strings.LastIndex(v.file, ".")
	// get file extension
	b := []byte(v.file[i+1:])
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
	v.file = v.file[:i+1] + string(b)
}

func (v *volume) next() (*fileBlockHeader, error) {
	if v.fbr == nil {
		return nil, io.EOF
	}
	for {
		var atEOF bool

		dr := &discardReader{v.br, v.f}
		h, err := v.fbr.next(dr)
		if len(v.file) == 0 {
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
		v.f, err = os.Open(v.dir + v.file) // Open next volume file
		if err != nil {
			if atEOF && os.IsNotExist(err) {
				// volume not found so assume that the archive has ended
				return nil, io.EOF
			}
			return nil, err
		}
		v.num++
		v.br.Reset(v.f)
		ver, err := findSig(v.br)
		if err != nil {
			return nil, err
		}
		if v.fbr.version() != ver {
			return nil, errVerMismatch
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
	v := new(volume)
	v.dir, v.file = filepath.Split(name)
	v.f, err = os.Open(name)
	if err != nil {
		return nil, err
	}
	v.br = bufio.NewReader(v.f)
	v.fbr, err = newFileBlockReader(v.br, password)
	if err != nil {
		_ = v.f.Close() // can only return one error so ignore Close error
		return nil, err
	}
	return v, nil
}

func newFileBlockReader(br *bufio.Reader, pass string) (fileBlockReader, error) {
	runes := []rune(pass)
	if len(runes) > maxPassword {
		pass = string(runes[:maxPassword])
	}
	ver, err := findSig(br)
	if err != nil {
		return nil, err
	}
	switch ver {
	case fileFmt15:
		return newArchive15(br, pass), nil
	case fileFmt50:
		return newArchive50(br, pass), nil
	}
	return nil, errUnknownArc
}
