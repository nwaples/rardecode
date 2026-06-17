package rardecode

import "io"

// Iter provides iteration over files in a RAR archive.
// It follows the scanner pattern: call Next() in a loop, then check Err().
type Iter struct {
	f           archiveFile
	header      *FileHeader
	err         error
	headersOnly bool
	skipped     bool
}

// Next advances to the next file in the archive.
// It returns true if there is a file to process, false if iteration
// is complete or an error occurred. When Next returns false, call Err
// to check for errors.
//
// If the previous file's content was not fully read (via Read, WriteTo,
// or Skip), Next will automatically skip remaining content. For solid
// archives, this requires decompressing the skipped data internally.
func (i *Iter) Next() bool {
	if i.err != nil {
		return false
	}

	if i.header != nil && !i.skipped {
		if err := i.skipContent(); err != nil {
			i.err = err
			return false
		}
	}

	blocks, err := i.f.nextFile()
	if err != nil {
		if err != io.EOF {
			i.err = err
		}
		return false
	}

	// Prepare header
	blocks.mu.RLock()
	header := blocks.blocks[0].FileHeader
	for _, block := range blocks.blocks[1:] {
		header.PackedSize += block.PackedSize
	}
	blocks.mu.RUnlock()

	i.header = &header
	i.skipped = false

	if !i.headersOnly {
		i.f, err = i.f.newArchiveFile(blocks)
		if err != nil {
			i.err = err
			return false
		}
	} else {
		i.skipped = true
	}

	return true
}

// Header returns the FileHeader for the current file.
// It returns nil if Next has not been called or returned false.
func (i *Iter) Header() *FileHeader {
	return i.header
}

// Read reads decompressed content from the current file.
// It implements io.Reader.
func (i *Iter) Read(p []byte) (int, error) {
	if i.skipped {
		return 0, io.EOF
	}
	n, err := i.f.Read(p)
	if err == io.EOF {
		i.skipped = true
	}
	return n, err
}

// ReadByte reads and returns a single byte from the current file.
// It implements io.ByteReader.
func (i *Iter) ReadByte() (byte, error) {
	if i.skipped {
		return 0, io.EOF
	}
	b, err := i.f.ReadByte()
	if err == io.EOF {
		i.skipped = true
	}
	return b, err
}

// WriteTo writes all remaining content of the current file to w.
// It implements io.WriterTo for efficient copying.
func (i *Iter) WriteTo(w io.Writer) (int64, error) {
	if i.skipped {
		return 0, nil
	}
	n, err := i.f.WriteTo(w)
	if err == nil || err == io.EOF {
		i.skipped = true
		err = nil
	}
	return n, err
}

// Skip marks the current file's content as consumed without reading it.
//
// For non-solid archives, Skip avoids decompression:
//   - Seekable readers (e.g., *os.File, *bytes.Reader): Uses Seek to skip packed data (most efficient)
//   - Non-seekable readers (e.g., net.Conn, io.Pipe): Reads and discards packed bytes (no decompression)
//
// For solid archives:
//   - Must decompress all content to maintain decoder state for subsequent files
//
// Skip is automatically called by Next() if content was not fully consumed.
// Calling Skip explicitly is useful to document intent.
func (i *Iter) Skip() error {
	if i.skipped {
		return nil
	}
	return i.skipContent()
}

func (i *Iter) skipContent() error {
	// For non-solid files, we don't need to decompress.
	// The next call to nextFile() will efficiently skip packed data
	// via Seek (for file-based archives) or Discard (for streams).
	if i.header != nil && !i.header.Solid {
		i.skipped = true
		return nil
	}

	// For solid files, we must decompress to maintain decoder state
	// (dictionary and decode tables carry over to subsequent files).
	_, err := io.Copy(io.Discard, i.f)
	if err == nil || err == io.EOF {
		i.skipped = true
		err = nil
	}
	return err
}

// Err returns the first error encountered during iteration.
// If iteration completed successfully (io.EOF), Err returns nil.
func (i *Iter) Err() error {
	return i.err
}

func newIter(v volume, opts *options) Iter {
	pr := newPackedFileReader(v, opts)
	return Iter{
		f:           pr,
		headersOnly: opts.iterHeadersOnly,
	}
}

// NewIter creates an Iter reading from r.
// NewIter only supports single volume archives.
// Multi-volume archives must use OpenIter.
func NewIter(r io.Reader, opts ...Option) (*Iter, error) {
	options := getOptions(opts)
	v, err := newVolume(r, options, 0)
	if err != nil {
		return nil, err
	}
	iter := newIter(v, options)
	return &iter, nil
}

// IterCloser is an Iter that must be closed when done.
type IterCloser struct {
	Iter
	closer io.Closer
	vm     *volumeManager
}

// Close closes the archive file.
// It must be called when done with the iterator.
func (ic *IterCloser) Close() error {
	return ic.closer.Close()
}

// Volumes returns the volume filenames that have been used in decoding the archive
// up to this point. This will include the current open volume if the archive is still
// being processed.
func (ic *IterCloser) Volumes() []string {
	if ic.vm == nil {
		return nil
	}
	return ic.vm.Files()
}

// OpenIter opens a RAR archive file and returns an IterCloser.
// The caller must call Close when finished.
func OpenIter(name string, opts ...Option) (*IterCloser, error) {
	options := getOptions(opts)
	v, err := openVolume(name, options)
	if err != nil {
		return nil, err
	}
	ic := &IterCloser{vm: v.vm, closer: v}
	ic.Iter = newIter(v, options)
	return ic, nil
}
