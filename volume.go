package rardecode

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	maxSfxSize = 0x100000 // maximum number of bytes to read when searching for RAR signature
	sigPrefix  = "Rar!\x1A\x07"
)

var (
	ErrNoSig            = errors.New("rardecode: RAR signature not found")
	ErrVerMismatch      = errors.New("rardecode: volume version mistmatch")
	ErrArchiveNameEmpty = errors.New("rardecode: archive name empty")
	ErrFileNameRequired = errors.New("rardecode: filename required for multi volume archive")

	defaultFS      = osFS{}
	defaultBufSize = 4096
)

type osFS struct{}

func (fs osFS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

type options struct {
	bsize int     // size to be use for bufio.Reader
	fs    fs.FS   // filesystem to use to open files
	pass  *string // password for encrypted volumes
	file  string  // filename for volume
}

// An Option is used for optional archive extraction settings.
type Option func(*options)

// BufferSize sets the size of the bufio.Reader used in reading the archive.
func BufferSize(size int) Option {
	return func(o *options) { o.bsize = size }
}

// FileSystem sets the fs.FS to be used for opening archive volumes.
func FileSystem(fs fs.FS) Option {
	return func(o *options) { o.fs = fs }
}

// Password sets the password to use for decrypting archives.
func Password(pass string) Option {
	return func(o *options) { o.pass = &pass }
}

func getOptions(opts []Option) options {
	opt := options{bsize: defaultBufSize}
	for _, f := range opts {
		f(&opt)
	}
	// truncate password
	if opt.pass != nil {
		runes := []rune(*opt.pass)
		if len(runes) > maxPassword {
			pw := string(runes[:maxPassword])
			opt.pass = &pw
		}
	}
	return opt
}

// volume extends a fileBlockReader to be used across multiple
// files in a multi-volume archive
type volume struct {
	f     io.Reader     // current file handle
	br    *bufio.Reader // buffered reader for current volume file
	dir   string        // current volume directory path
	files []string      // file names for each volume
	num   int           // volume number
	old   bool          // uses old naming scheme
	off   int64         // current file offset
	ver   int           // archive file format version
	fs    fs.FS         // filesystem to use to open files
}

func (v *volume) openFile(file string, volnum int) error {
	f, err := v.fs.Open(v.dir + file)
	if err != nil {
		return err
	}
	v.f = f
	v.num = volnum
	v.off = 0
	v.br.Reset(v.f)
	if volnum == len(v.files) {
		v.files = append(v.files, file)
	}
	version, err := v.findSig()
	if err != nil {
		_ = v.Close()
		return err
	}
	if version != v.ver {
		return ErrVerMismatch
	}
	return nil
}

func (v *volume) init() error {
	off := v.off
	err := v.openFile(v.files[v.num], v.num)
	if err != nil {
		return err
	}
	return v.discard(off - v.off)
}

func (v *volume) clone() *volume {
	nv := new(volume)
	*nv = *v
	nv.f = nil
	nv.br = bufio.NewReaderSize(bytes.NewReader(nil), nv.br.Size())
	nv.files = slices.Clone(nv.files)
	return nv
}

func (v *volume) Close() error {
	// v.f may be nil if os.Open fails in next().
	// We only close if we opened it (ie. name in v.files).
	if v.f != nil && len(v.files) > 0 {
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
		for n > math.MaxInt && err == nil {
			_, err = v.br.Discard(math.MaxInt)
			n -= math.MaxInt
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

func (v *volume) Read(p []byte) (int, error) {
	n, err := v.br.Read(p)
	v.off += int64(n)
	return n, err
}

func (v *volume) ReadByte() (byte, error) {
	b, err := v.br.ReadByte()
	v.off++
	return b, err
}

// findSig searches for the RAR signature and version at the beginning of a file.
// It searches no more than maxSfxSize bytes.
func (v *volume) findSig() (int, error) {
	v.off = 0
	for v.off <= maxSfxSize {
		b, err := v.br.ReadSlice(sigPrefix[0])
		v.off += int64(len(b))
		if err == bufio.ErrBufferFull {
			continue
		} else if err != nil {
			if err == io.EOF {
				err = ErrNoSig
			}
			return 0, err
		}

		b, err = v.br.Peek(len(sigPrefix[1:]) + 2)
		if err != nil {
			if err == io.EOF {
				err = ErrNoSig
			}
			return 0, err
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
		if err != nil {
			return 0, err
		}
		v.off += int64(len(b))
		return ver, nil
	}
	return 0, ErrNoSig
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

func hasDigits(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

func fixFileExtension(file string) string {
	// check file extensions
	i := strings.LastIndex(file, ".")
	if i < 0 {
		// no file extension, add one
		return file + ".rar"
	}
	ext := strings.ToLower(file[i+1:])
	// replace with .rar for empty extensions & self extracting archives
	if ext == "" || ext == "exe" || ext == "sfx" {
		file = file[:i+1] + "rar"
	}
	return file
}

// next opens the next volume file in the archive.
func (v *volume) next() error {
	if len(v.files) == 0 {
		return ErrFileNameRequired
	}
	err := v.Close()
	if err != nil {
		return err
	}

	nextVolNum := v.num + 1
	// check for cached volume name
	if nextVolNum < len(v.files) {
		return v.openFile(v.files[nextVolNum], nextVolNum)
	}

	file := v.files[v.num]
	if nextVolNum == 1 {
		file = fixFileExtension(file)
		// new naming scheme must have volume number in filename
		if !v.old && hasDigits(file) {
			// found digits, try using new naming scheme
			err = v.openFile(nextNewVolName(file), nextVolNum)
			if err == nil || !os.IsNotExist(err) {
				return err
			}
			// file didn't exist, try old naming scheme
			oldErr := v.openFile(nextOldVolName(file), nextVolNum)
			if oldErr == nil || !os.IsNotExist(err) {
				v.old = true
				return oldErr
			}
			return err
		}
		v.old = true
	}
	if v.old {
		file = nextOldVolName(file)
	} else {
		file = nextNewVolName(file)
	}
	return v.openFile(file, nextVolNum)
}

func newVolume(r io.Reader, options options) (*volume, error) {
	v := &volume{
		f:  r,
		br: bufio.NewReaderSize(r, options.bsize),
		fs: options.fs,
	}
	if options.file != "" {
		dir, file := filepath.Split(options.file)
		v.dir = dir
		v.files = []string{file}
	}
	var err error
	v.ver, err = v.findSig()
	if err != nil {
		_ = v.Close()
		return nil, err
	}
	return v, nil
}
