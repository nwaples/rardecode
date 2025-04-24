package rardecode

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var (
	ErrVerMismatch      = errors.New("rardecode: volume version mistmatch")
	ErrArchiveNameEmpty = errors.New("rardecode: archive name empty")
	ErrFileNameRequired = errors.New("rardecode: filename required for multi volume archive")
	ErrInvalidHeaderOff = errors.New("rardecode: invalid filed header offset")

	defaultFS = osFS{}
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

func getOptions(opts []Option) *options {
	opt := &options{}
	for _, f := range opts {
		f(opt)
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

// volume extends a archiveBlockReader to be used across multiple
// files in a multi-volume archive
type volume struct {
	br  *bufVolumeReader // buffered reader for current volume file
	num int              // current volume number
	ver int              // archive file format version
	cl  io.Closer
	arc archiveBlockReader
	vm  *volumeManager
	opt *options
}

func (v *volume) init(r io.Reader, volnum int) error {
	var err error
	if v.br == nil {
		v.br, err = newBufVolumeReader(r, v.opt.bsize)
	} else {
		err = v.br.Reset(r)
	}
	if err != nil {
		return err
	}
	if v.arc == nil {
		switch v.br.ver {
		case archiveVersion15:
			v.arc = newArchive15(v.opt.pass)
		case archiveVersion50:
			v.arc = newArchive50(v.opt.pass)
		default:
			return ErrUnknownVersion
		}
		v.ver = v.br.ver
	} else if v.ver != v.br.ver {
		return ErrVerMismatch
	}
	n, err := v.arc.init(v.br)
	if err != nil {
		return err
	}
	v.num = volnum
	if n >= 0 && n != volnum {
		return ErrBadVolumeNumber
	}
	return nil
}

func (v *volume) Close() error {
	if v.cl != nil {
		err := v.cl.Close()
		v.cl = nil
		return err
	}
	return nil
}

func (v *volume) discard(n int64) error {
	return v.br.Discard(n)
}

func (v *volume) open(volnum int) error {
	if v.vm == nil {
		return ErrFileNameRequired
	}
	err := v.Close()
	if err != nil {
		return err
	}
	f, err := v.vm.openVolumeFile(volnum)
	if err != nil {
		return err
	}
	err = v.init(f, volnum)
	if err != nil {
		f.Close()
		return err
	}
	v.cl = f
	return nil
}

func (v *volume) nextBlock() (*fileBlockHeader, error) {
	for {
		f, err := v.arc.nextBlock(v.br)
		if err == nil {
			f.volnum = v.num
			f.dataOff = v.br.off
			return f, nil
		}
		nextVol := v.num + 1
		if err == errVolumeEnd {
			err = v.open(nextVol)
			if err != nil {
				return nil, err
			}
		} else if err == errVolumeOrArchiveEnd {
			err = v.open(nextVol)
			if err != nil {
				// new volume doesnt exist, assume end of archive
				if errors.Is(err, fs.ErrNotExist) {
					return nil, io.EOF
				}
				return nil, err
			}
		} else {
			return nil, err
		}
	}
}

func (v *volume) Read(p []byte) (int, error) {
	n, err := v.br.Read(p)
	return n, err
}

func (v *volume) ReadByte() (byte, error) {
	b, err := v.br.ReadByte()
	return b, err
}

func newVolume(r io.Reader, opt *options, volnum int) (*volume, error) {
	v := &volume{opt: opt}
	err := v.init(r, volnum)
	if err != nil {
		return nil, err
	}
	return v, nil
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

type volumeManager struct {
	dir   string   // current volume directory path
	files []string // file names for each volume
	old   bool     // uses old naming scheme
	opt   *options
	mu    sync.Mutex
}

func (vm *volumeManager) tryNewName(file string) (fs.File, error) {
	// try using new naming scheme
	name := nextNewVolName(file)
	f, err := vm.opt.fs.Open(vm.dir + name)
	if !errors.Is(err, fs.ErrNotExist) {
		vm.files = append(vm.files, name)
		return f, err
	}
	// file didn't exist, try old naming scheme
	name = nextOldVolName(file)
	f, oldErr := vm.opt.fs.Open(vm.dir + name)
	if !errors.Is(oldErr, fs.ErrNotExist) {
		vm.old = true
		vm.files = append(vm.files, name)
		return f, oldErr
	}
	return nil, err
}

// next opens the next volume file in the archive.
func (vm *volumeManager) openVolumeFile(volnum int) (fs.File, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	var file string
	// check for cached volume name
	if volnum < len(vm.files) {
		return vm.opt.fs.Open(vm.dir + vm.files[volnum])
	}
	file = vm.files[len(vm.files)-1]
	if len(vm.files) == 1 {
		file = fixFileExtension(file)
		if !vm.old && hasDigits(file) {
			return vm.tryNewName(file)
		}
		vm.old = true
	}
	for len(vm.files) <= volnum {
		if vm.old {
			file = nextOldVolName(file)
		} else {
			file = nextNewVolName(file)
		}
		vm.files = append(vm.files, file)
	}
	return vm.opt.fs.Open(vm.dir + file)
}

func (vm *volumeManager) newVolume(volnum int) (*volume, error) {
	f, err := vm.openVolumeFile(volnum)
	if err != nil {
		return nil, err
	}
	v, err := newVolume(f, vm.opt, volnum)
	if err != nil {
		f.Close()
		return nil, err
	}
	v.cl = f
	v.vm = vm
	return v, nil
}

func (vm *volumeManager) openVolumeOffset(volnum int, offset int64) (*volume, error) {
	v, err := vm.newVolume(volnum)
	if err != nil {
		return nil, err
	}
	if offset == 0 || offset == v.br.off {
		return v, nil
	}
	if offset < v.br.off {
		v.Close()
		return nil, ErrInvalidHeaderOff
	}
	err = v.br.Discard(offset - v.br.off)
	if err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

func newVolumeManager(opt *options) *volumeManager {
	dir, file := filepath.Split(opt.file)
	return &volumeManager{
		dir:   dir,
		files: []string{file},
		opt:   opt,
	}
}

func openVolume(opt *options) (*volume, error) {
	vm := newVolumeManager(opt)
	v, err := vm.newVolume(0)
	if err != nil {
		return nil, err
	}
	vm.old = v.arc.useOldNaming()
	return v, nil
}
