package rardecode

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxSfxSize = 0x100000 // maximum number of bytes to read when searching for RAR signature
	sigPrefix  = "Rar!\x1A\x07"

	maxInt = int(^uint(0) >> 1)
)

var (
	errNoSig            = errors.New("rardecode: RAR signature not found")
	errVerMismatch      = errors.New("rardecode: volume version mistmatch")
	errArchiveNameEmpty = errors.New("rardecode: archive name empty")
	errFileNameRequired = errors.New("rardecode: filename required for multi volume archive")
)

// volume extends a fileBlockReader to be used across multiple
// files in a multi-volume archive
type volume struct {
	fs   http.FileSystem // file system for accessing the next file
	f    io.Reader       // current file handle
	br   *bufio.Reader   // buffered reader for current volume file
	name string          // current volume file name
	num  int             // volume number
	old  bool            // uses old naming scheme
	off  int64           // current file offset
	ver  int             // archive file format version
}

func (v *volume) init() error {
	if len(v.name) == 0 {
		return errArchiveNameEmpty
	}
	f, err := v.fs.Open(v.name)
	if err != nil {
		return err
	}
	v.f = f
	v.br = bufio.NewReader(v.f)
	err = v.discard(v.off)
	if err != nil {
		_ = v.Close()
	}
	return err
}

func (v *volume) clone() *volume {
	nv := new(volume)
	*nv = *v
	nv.f = nil
	nv.br = nil
	return nv
}

func (v *volume) Close() error {
	// v.f may be nil if os.Open fails in next().
	// We only close if we opened it (ie. v.name provided).
	if v.f != nil && len(v.name) > 0 {
		if c, ok := v.f.(io.Closer); ok {
			err := c.Close()
			v.f = nil // set to nil so we can only close v.f once
			return err
		}
	}
	return nil
}

func (v *volume) discard(n int64) error {
	var err error
	v.off += n
	l := int64(v.br.Buffered())
	if n <= l {
		_, err = v.br.Discard(int(n))
	} else if sr, ok := v.f.(io.Seeker); ok {
		n -= l
		_, err = sr.Seek(n, io.SeekCurrent)
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

		ver := int(b[0])
		if b[0] != 0 && b[1] != 0 {
			continue
		}
		b, err = v.br.ReadSlice('\x00')
		v.off += int64(len(b))
		if v.num == 0 {
			v.ver = ver
		} else if v.ver != ver {
			return errVerMismatch
		}
		return err
	}
	return errNoSig
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

func (v *volume) next() error {
	if len(v.name) == 0 {
		return errFileNameRequired
	}
	err := v.Close()
	if err != nil {
		return err
	}
	v.f = nil
	v.nextVolName()
	v.num++
	f, err := v.fs.Open(v.name) // Open next volume file
	if err != nil {
		return err
	}
	v.f = f
	v.br.Reset(v.f)
	err = v.findSig()
	if err != nil {
		_ = v.Close()
	}
	return err
}

func newVolume(r io.Reader) (*volume, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	v := &volume{f: r, br: br}
	return v, v.findSig()
}

func openVolume(fs http.FileSystem, name string) (*volume, error) {
	f, err := fs.Open(name)
	if err != nil {
		return nil, err
	}
	v := &volume{fs: fs, f: f, name: name, br: bufio.NewReader(f)}
	err = v.findSig()
	if err != nil {
		_ = v.Close()
		return nil, err
	}
	return v, nil
}
