package rardecode

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"io/ioutil"
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
	maxPassword = 128

	decodeNoneVer = iota
	decode29Ver
	decode50Ver
)

var (
	errShortFile        = errors.New("rardecode: decoded file too short")
	errInvalidFileBlock = errors.New("rardecode: invalid file block")
	errUnexpectedArcEnd = errors.New("rardecode: unexpected end of archive")
	errBadFileChecksum  = errors.New("rardecode: bad file checksum")
)

type byteReader interface {
	io.Reader
	io.ByteReader
}

type limitedReader struct {
	r        io.Reader
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
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if err == io.EOF && l.n > 0 {
		return n, l.shortErr
	}
	return n, err
}

type limitedByteReader struct {
	limitedReader
	br *discardReader
}

func (l *limitedByteReader) ReadByte() (byte, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	c, err := l.br.ReadByte()
	if err == nil {
		l.n--
	} else if err == io.EOF && l.n > 0 {
		return 0, l.shortErr
	}
	return c, err
}

func (l *limitedByteReader) skip() error {
	return l.br.discard(l.n)
}

// blocks returns a byte slice whose size is a multiple of blockSize.
// If there is less than blockSize bytes available before EOF, then those
// bytes will be returned. If oneBlock is set, then no more than one block
// will be returned.
func (l *limitedByteReader) blocks(blockSize int, oneBlock bool) ([]byte, error) {
	if l.n == 0 {
		return nil, io.EOF
	}
	var n int
	if l.n < int64(blockSize) {
		n = int(l.n)
	} else if oneBlock {
		n = blockSize
	} else {
		if _, err := l.br.Peek(blockSize); err != nil {
			return nil, err
		}
		n = l.br.Buffered()
		if int64(n) > l.n {
			n = int(l.n)
		}
		n -= n % blockSize
	}
	b, err := l.br.readSlice(n)
	l.n -= int64(len(b))
	return b, err
}

// limitByteReader returns a limitedByteReader that reads from r and stops with
// io.EOF after n bytes.
// If r returns an io.EOF before reading n bytes, io.ErrUnexpectedEOF is returned.
func limitByteReader(r *discardReader, n int64) *limitedByteReader {
	return &limitedByteReader{limitedReader{r, n, io.ErrUnexpectedEOF}, r}
}

// FileHeader represents a single file in a RAR archive.
type FileHeader struct {
	Name             string    // file name using '/' as the directory separator
	IsDir            bool      // is a directory
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

// fileBlockHeader represents a file block in a RAR archive.
// Files may comprise one or more file blocks.
// Solid files retain decode tables and dictionary from previous solid files in the archive.
type fileBlockHeader struct {
	first    bool      // first block in file
	last     bool      // last block in file
	solid    bool      // file is solid
	arcSolid bool      // archive is solid
	winSize  uint      // log base 2 of decode window size
	hash     hash.Hash // hash used for file checksum
	hashKey  []byte    // optional hmac key to be used calculate file checksum
	sum      []byte    // expected checksum for file contents
	decVer   int       // decoder to use for file
	key      []byte    // key for AES, non-empty if file encrypted
	iv       []byte    // iv for AES, non-empty if file encrypted
	FileHeader
}

// fileBlockReader provides sequential access to file blocks in a RAR archive.
type fileBlockReader interface {
	next(br *discardReader) (*fileBlockHeader, error) // reads the next file block header at current position
	reset()                                           // resets encryption
	version() int                                     // returns current archive format version
}

// packedFileReader provides sequential access to packed files in a RAR archive.
type packedFileReader struct {
	v *volume
	h *fileBlockHeader   // current file header
	r *limitedByteReader // reader for current file data block
}

// nextBlockInFile reads the next file block in the current file at the current
// archive file position, or returns an error if there is a problem.
// It is invalid to call this when already at the last block in the current file.
func (f *packedFileReader) nextBlockInFile() error {
	h, err := f.v.next()
	if err != nil {
		if err == io.EOF {
			// archive ended, but file hasn't
			return errUnexpectedArcEnd
		}
		return err
	}
	if h.first || h.Name != f.h.Name {
		return errInvalidFileBlock
	}
	f.h = h
	f.r = limitByteReader(&discardReader{f.v.br, f.v.f}, h.PackedSize)
	return nil
}

// skip advances to the end of the packed file in the RAR archive.
func (f *packedFileReader) skip() error {
	if f.h == nil {
		return nil
	}
	// skip to last block in current file
	for !f.h.last {
		// discard remaining block data
		if err := f.r.skip(); err != nil {
			return err
		}
		if err := f.nextBlockInFile(); err != nil {
			return err
		}
	}
	// discard last block data
	return f.r.skip()
}

// Read reads the packed data for the current file into p.
func (f *packedFileReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p) // read current block data
	for err == io.EOF {   // current block empty
		if n > 0 {
			return n, nil
		}
		if f.h == nil || f.h.last {
			return 0, io.EOF // last block so end of file
		}
		if err := f.nextBlockInFile(); err != nil {
			return 0, err
		}
		n, err = f.r.Read(p) // read new block data
	}
	return n, err
}

func (f *packedFileReader) ReadByte() (byte, error) {
	c, err := f.r.ReadByte()                       // read current block data
	for err == io.EOF && f.h != nil && !f.h.last { // current block empty
		if err := f.nextBlockInFile(); err != nil {
			return 0, err
		}
		c, err = f.r.ReadByte() // read new block data
	}
	return c, err
}

// blocks returns a byte slice whose size is always a multiple of blockSize.
func (f *packedFileReader) blocks(blockSize int) ([]byte, error) {
	b, err := f.r.blocks(blockSize, false)
	for err == io.EOF {
		if f.h == nil || f.h.last {
			return nil, io.EOF
		}
		if err = f.nextBlockInFile(); err != nil {
			return nil, err
		}
		b, err = f.r.blocks(blockSize, false) // read new block data
	}
	if len(b) >= blockSize {
		return b, err
	}

	// slice returned is smaller than blockSize. Try to get the rest
	// from the following file blocks.
	buf := make([]byte, 0, blockSize)
	buf = append(buf, b...)
	for len(buf) < blockSize {
		// read a single small block of the remaining bytes
		b, err = f.r.blocks(blockSize-len(buf), true)
		switch err {
		case nil:
			buf = append(buf, b...)
		case io.EOF:
			if f.h == nil || f.h.last {
				// not enough bytes available, return io.EOF
				return nil, io.EOF
			}
			if err = f.nextBlockInFile(); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
	}
	return buf, nil
}

func (f *packedFileReader) bytes() ([]byte, error) { return f.blocks(1) }

func newPackedFileReader(v *volume) (*packedFileReader, error) {
	h, err := v.next() // get next file block
	if err != nil {
		if err == errArchiveEnd {
			return nil, io.EOF
		}
		return nil, err
	}
	if !h.first {
		return nil, errInvalidFileBlock
	}
	br := limitByteReader(&discardReader{v.br, v.f}, h.PackedSize)
	return &packedFileReader{v, h, br}, nil
}

type checksumReader struct {
	r    io.Reader
	hash hash.Hash
	pr   *packedFileReader
}

func (cr *checksumReader) eofError() error {
	// calculate file checksum
	h := cr.pr.h
	sum := cr.hash.Sum(nil)
	if len(h.hashKey) > 0 {
		mac := hmac.New(sha256.New, h.hashKey)
		mac.Write(sum)
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
		return errBadFileChecksum
	}
	return io.EOF
}

func (cr *checksumReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
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

// Reader provides sequential access to files in a RAR archive.
type Reader struct {
	r      io.Reader // reader for current unpacked file
	v      *volume
	pr     *packedFileReader // reader for current packed file
	dr     decodeReader      // reader for decoding and filters if file is compressed
	solidr io.Reader         // reader for solid file
}

// Read reads from the current file in the RAR archive.
func (r *Reader) Read(p []byte) (int, error) {
	if r.r == nil {
		return 0, io.EOF
	}
	return r.r.Read(p)
}

// Next advances to the next file in the archive.
func (r *Reader) Next() (*FileHeader, error) {
	var err error
	if r.solidr != nil {
		// solid files must be read fully to update decoder information
		if _, err = io.Copy(ioutil.Discard, r.solidr); err != nil {
			return nil, err
		}
	}
	if r.pr != nil {
		if err = r.pr.skip(); err != nil {
			return nil, err
		}
	}

	r.pr, err = newPackedFileReader(r.v) // open next file
	if err != nil {
		return nil, err
	}
	h := r.pr.h
	r.solidr = nil

	br := byteReader(r.pr) // start with packed file reader

	// check for encryption
	if len(h.key) > 0 && len(h.iv) > 0 {
		br = newAesDecryptReader(r.pr, h.key, h.iv) // decrypt
	}
	r.r = br
	// check for compression
	if h.decVer > 0 {
		err = r.dr.init(br, h.decVer, h.winSize, !h.solid)
		if err != nil {
			return nil, err
		}
		r.r = &r.dr
		if h.arcSolid {
			r.solidr = r.r
		}
	}
	if h.UnPackedSize >= 0 && !h.UnKnownSize {
		// Limit reading to UnPackedSize as there may be padding
		r.r = &limitedReader{r.r, h.UnPackedSize, errShortFile}
	}
	if h.hash != nil {
		r.r = &checksumReader{r.r, h.hash, r.pr}
	}
	fh := new(FileHeader)
	*fh = h.FileHeader
	return fh, nil
}

// NewReader creates a Reader reading from r.
// NewReader only supports single volume archives.
// Multi-volume archives must use OpenReader.
func NewReader(r io.Reader, password string) (*Reader, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	fbr, err := newFileBlockReader(br, password)
	if err != nil {
		return nil, err
	}
	v := &volume{fbr: fbr, br: br}
	return &Reader{v: v}, nil
}

type ReadCloser struct {
	Reader
}

// Close closes the rar file.
func (rc *ReadCloser) Close() error {
	return rc.v.Close()
}

// OpenReader opens a RAR archive specified by the name and returns a ReadCloser.
func OpenReader(name, password string) (*ReadCloser, error) {
	v, err := openVolume(name, password)
	if err != nil {
		return nil, err
	}
	rc := &ReadCloser{Reader{v: v}}
	return rc, nil
}
