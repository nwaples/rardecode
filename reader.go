package rardecode

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"time"
)

// FileHeader HostOS types
const (
	HostOSUnknown = 0
	HostOSMSDOS   = 1
	HostOSOS2     = 2
	HostOSWindows = 3
	HostOSUnix    = 4
	HostOSMacOS   = 5
	HostOSBeOS    = 6
)

const (
	maxPassword = int(128)
)

var (
	ErrShortFile        = errors.New("rardecode: decoded file too short")
	ErrInvalidFileBlock = errors.New("rardecode: invalid file block")
	ErrUnexpectedArcEnd = errors.New("rardecode: unexpected end of archive")
	ErrBadFileChecksum  = errors.New("rardecode: bad file checksum")
	ErrSolidOpen        = errors.New("rardecode: solid files don't support Open")
	ErrUnknownVersion   = errors.New("rardecode: unknown archive version")
)

// FileHeader represents a single file in a RAR archive.
type FileHeader struct {
	Name             string    // file name using '/' as the directory separator
	IsDir            bool      // is a directory
	Solid            bool      // is a solid file
	Encrypted        bool      // file contents are encrypted
	HeaderEncrypted  bool      // file header is encrypted
	HostOS           byte      // Host OS the archive was created on
	Attributes       int64     // Host OS specific file attributes
	PackedSize       int64     // packed file size (or first block if the file spans volumes)
	UnPackedSize     int64     // unpacked file size
	UnKnownSize      bool      // unpacked file size is not known
	ModificationTime time.Time // modification time (non-zero if set)
	CreationTime     time.Time // creation time (non-zero if set)
	AccessTime       time.Time // access time (non-zero if set)
	Version          int       // file version
}

// Mode returns an os.FileMode for the file, calculated from the Attributes field.
func (f *FileHeader) Mode() os.FileMode {
	var m os.FileMode

	if f.IsDir {
		m = os.ModeDir
	}
	if f.HostOS == HostOSWindows {
		if f.IsDir {
			m |= 0777
		} else if f.Attributes&1 > 0 {
			m |= 0444 // readonly
		} else {
			m |= 0666
		}
		return m
	}
	// assume unix perms for all remaining os types
	m |= os.FileMode(f.Attributes) & os.ModePerm

	// only check other bits on unix host created archives
	if f.HostOS != HostOSUnix {
		return m
	}

	if f.Attributes&0x200 != 0 {
		m |= os.ModeSticky
	}
	if f.Attributes&0x400 != 0 {
		m |= os.ModeSetgid
	}
	if f.Attributes&0x800 != 0 {
		m |= os.ModeSetuid
	}

	// Check for additional file types.
	if f.Attributes&0xF000 == 0xA000 {
		m |= os.ModeSymlink
	}
	return m
}

type byteReader interface {
	io.Reader
	io.ByteReader
}

type archiveFile interface {
	byteReader
	nextFile() (*fileBlockHeader, error)
	Close() error
	Stat() (fs.FileInfo, error)
}

// packedFileReader provides sequential access to packed files in a RAR archive.
type packedFileReader struct {
	v *volume
	h *fileBlockHeader // current file header
}

func (f *packedFileReader) init(h *fileBlockHeader) error {
	if !h.first {
		return ErrInvalidFileBlock
	}
	h.packedOff = 0
	f.h = h
	return nil
}

func (f *packedFileReader) Close() error { return f.v.Close() }

func (f *packedFileReader) Stat() (fs.FileInfo, error) {
	if f.h == nil {
		return nil, fs.ErrInvalid
	}
	return fileInfo{h: f.h}, nil
}

// nextBlock reads the next file block in the current file at the current
// archive file position, or returns an error if there is a problem.
// It is invalid to call this when already at the last block in the current file.
func (f *packedFileReader) nextBlock() error {
	if f.h == nil {
		return io.EOF
	}
	if f.h.last {
		return io.EOF
	}
	h, err := f.v.nextBlock()
	if err != nil {
		if err == io.EOF {
			// archive ended, but file hasn't
			return ErrUnexpectedArcEnd
		}
		return err
	}
	if h.first || h.Name != f.h.Name {
		return ErrInvalidFileBlock
	}
	h.packedOff = f.h.packedOff + f.h.PackedSize
	f.h = h
	return nil
}

// next advances to the next packed file in the RAR archive.
func (f *packedFileReader) nextFile() (*fileBlockHeader, error) {
	// skip to last block in current file
	var err error
	for err == nil {
		err = f.nextBlock()
	}
	if err != io.EOF {
		return nil, err
	}
	h, err := f.v.nextBlock() // get next file block
	if err != nil {
		return nil, err
	}
	err = f.init(h)
	if err != nil {
		return nil, err
	}
	return f.h, nil
}

// Read reads the packed data for the current file into p.
func (f *packedFileReader) Read(p []byte) (int, error) {
	for {
		n, err := f.v.Read(p)
		if err == io.EOF {
			err = f.nextBlock()
		}
		if n > 0 || err != nil {
			return n, err
		}
	}
}

func (f *packedFileReader) ReadByte() (byte, error) {
	for {
		b, err := f.v.ReadByte()
		if err == nil {
			return b, nil
		}
		if err == io.EOF {
			err = f.nextBlock()
			if err == nil {
				continue
			}
		}
		return b, err
	}
}

func newPackedFileReader(v *volume) *packedFileReader {
	return &packedFileReader{v: v}
}

type limitedReader struct {
	archiveFile
	n        int64 // bytes remaining
	shortErr error // error returned when r returns io.EOF with n > 0
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[0:l.n]
	}
	n, err := l.archiveFile.Read(p)
	l.n -= int64(n)
	if err == io.EOF && l.n > 0 {
		return n, l.shortErr
	}
	return n, err
}

func (l *limitedReader) ReadByte() (byte, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	b, err := l.archiveFile.ReadByte()
	if err != nil {
		if err == io.EOF && l.n > 0 {
			return 0, l.shortErr
		}
		return 0, err
	}
	l.n--
	return b, nil
}

type checksumReader struct {
	archiveFile
	hash hash.Hash
	pr   *packedFileReader
}

func (cr *checksumReader) eofError() error {
	// calculate file checksum
	h := cr.pr.h
	sum := cr.hash.Sum(nil)
	if !h.first && h.genKeys != nil {
		if err := h.genKeys(); err != nil {
			return err
		}
	}
	if len(h.hashKey) > 0 {
		mac := hmac.New(sha256.New, h.hashKey)
		_, _ = mac.Write(sum) // ignore error, should always succeed
		sum = mac.Sum(sum[:0])
		if len(h.sum) == 4 {
			// CRC32
			for i, v := range sum[4:] {
				sum[i&3] ^= v
			}
			sum = sum[:4]
		}
	}
	if !bytes.Equal(sum, h.sum) {
		return ErrBadFileChecksum
	}
	return io.EOF
}

func (cr *checksumReader) Read(p []byte) (int, error) {
	n, err := cr.archiveFile.Read(p)
	if n > 0 {
		if n, err = cr.hash.Write(p[:n]); err != nil {
			return n, err
		}
	}
	if err != io.EOF {
		return n, err
	}
	return n, cr.eofError()
}

func (cr *checksumReader) ReadByte() (byte, error) {
	b, err := cr.archiveFile.ReadByte()
	if err != nil {
		if err != io.EOF {
			return 0, err
		}
		return 0, cr.eofError()
	}
	_, err = cr.hash.Write([]byte{b})
	if err != nil {
		return 0, err
	}
	return b, err
}

func newArchiveFile(pr *packedFileReader, dr *decodeReader, h *fileBlockHeader) (archiveFile, error) {
	if h == nil {
		return nil, io.EOF
	}
	err := pr.init(h)
	if err != nil {
		return nil, err
	}
	// start with packed file reader
	r := archiveFile(pr)
	// check for encryption
	if h.genKeys != nil {
		r = newAesDecryptFileReader(r, h.getKeys) // decrypt
	}
	// check for compression
	if h.decVer > 0 {
		if dr == nil {
			dr = new(decodeReader)
		}
		err := dr.init(r, h.decVer, h.winSize, !h.Solid, h.arcSolid, h.UnPackedSize)
		if err != nil {
			return nil, err
		}
		r = dr
	}
	if h.UnPackedSize >= 0 && !h.UnKnownSize {
		// Limit reading to UnPackedSize as there may be padding
		r = &limitedReader{r, h.UnPackedSize, ErrShortFile}
	}
	if h.hash != nil {
		r = &checksumReader{r, h.hash(), pr}
	}
	return r, nil
}

func openArchiveFile(vm *volumeManager, h *fileBlockHeader) (archiveFile, error) {
	if h.Solid {
		return nil, ErrSolidOpen
	}
	v, err := vm.openBlockOffset(h, 0)
	if err != nil {
		return nil, err
	}
	pr := newPackedFileReader(v)
	f, err := newArchiveFile(pr, nil, h)
	if err != nil {
		v.Close()
		return nil, err
	}
	return f, nil
}

// Reader provides sequential access to files in a RAR archive.
type Reader struct {
	f  archiveFile
	pr *packedFileReader
	dr *decodeReader
}

func (r *Reader) Read(p []byte) (int, error) { return r.f.Read(p) }
func (r *Reader) ReadByte() (byte, error)    { return r.f.ReadByte() }

// Next advances to the next file in the archive.
func (r *Reader) Next() (*FileHeader, error) {
	h, err := r.f.nextFile()
	if err != nil {
		return nil, err
	}
	r.f, err = newArchiveFile(r.pr, r.dr, h)
	if err != nil {
		return nil, err
	}
	return &h.FileHeader, nil
}

func newReader(v *volume) Reader {
	pr := newPackedFileReader(v)
	return Reader{pr: pr, dr: &decodeReader{}, f: pr}
}

// NewReader creates a Reader reading from r.
// NewReader only supports single volume archives.
// Multi-volume archives must use OpenReader.
func NewReader(r io.Reader, opts ...Option) (*Reader, error) {
	options := getOptions(opts)
	v, err := newVolume(r, options, 0)
	if err != nil {
		return nil, err
	}
	rdr := newReader(v)
	return &rdr, nil
}

// ReadCloser is a Reader that allows closing of the rar archive.
type ReadCloser struct {
	Reader
	vm *volumeManager
}

// Close closes the rar file.
func (rc *ReadCloser) Close() error { return rc.f.Close() }

// Volumes returns the volume filenames that have been used in decoding the archive
// up to this point. This will include the current open volume if the archive is still
// being processed.
func (rc *ReadCloser) Volumes() []string {
	return rc.vm.files
}

// OpenReader opens a RAR archive specified by the name and returns a ReadCloser.
func OpenReader(name string, opts ...Option) (*ReadCloser, error) {
	v, err := openVolume(name, opts)
	if err != nil {
		return nil, err
	}
	rc := &ReadCloser{vm: v.vm}
	rc.Reader = newReader(v)
	return rc, nil
}

// File represents a file in a RAR archive
type File struct {
	FileHeader
	h  *fileBlockHeader
	vm *volumeManager
}

// Open returns an io.ReadCloser that provides access to the File's contents.
// Open is not supported on Solid File's as their contents depend on the decoding
// of the preceding files in the archive. Use OpenReader and Next to access Solid file
// contents instead.
func (f *File) Open() (io.ReadCloser, error) {
	return openArchiveFile(f.vm, f.h)
}

// List returns a list of File's in the RAR archive specified by name.
func List(name string, opts ...Option) ([]*File, error) {
	v, err := openVolume(name, opts)
	if err != nil {
		return nil, err
	}
	pr := newPackedFileReader(v)
	defer pr.Close()

	var fl []*File
	for {
		// get next file
		h, err := pr.nextFile()
		if err != nil {
			if err == io.EOF {
				return fl, nil
			}
			return nil, err
		}

		// save information for File
		f := &File{
			FileHeader: h.FileHeader,
			h:          h,
			vm:         v.vm,
		}
		fl = append(fl, f)
	}
}
