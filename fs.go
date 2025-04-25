package rardecode

import (
	"io"
	"io/fs"
	"path/filepath"
	"time"
)

type fileInfo struct {
	h *fileBlockHeader
}

func (f fileInfo) Name() string       { return filepath.Base(f.h.Name) }
func (f fileInfo) Size() int64        { return f.h.UnPackedSize }
func (f fileInfo) Mode() fs.FileMode  { return f.h.Mode() }
func (f fileInfo) ModTime() time.Time { return f.h.ModificationTime }
func (f fileInfo) IsDir() bool        { return f.h.IsDir }
func (f fileInfo) Sys() any           { return nil }

type file struct {
	reader
}

func (rc *file) Stat() (fs.FileInfo, error) {
	return fileInfo{h: rc.pr.h}, nil
}

func (rc *file) Close() error {
	return rc.pr.Close()
}

type RarFS struct {
	vm    *volumeManager
	files map[string]*fileBlockHeader
}

func (rfs *RarFS) Open(name string) (fs.File, error) {
	h := rfs.files[name]
	if h == nil {
		return nil, fs.ErrNotExist
	}
	if h.Solid {
		return nil, ErrSolidOpen
	}
	v, err := rfs.vm.openBlockOffset(h, 0)
	if err != nil {
		return nil, err
	}
	f := &file{}
	f.reader = newReader(v)
	err = f.reader.init(h)
	if err != nil {
		v.Close()
		return nil, err
	}
	return f, nil
}

func (rfs *RarFS) Stat(name string) (fs.FileInfo, error) {
	h := rfs.files[name]
	if h == nil {
		return nil, fs.ErrNotExist
	}
	return fileInfo{h: h}, nil
}

func OpenFS(name string, opts ...Option) (*RarFS, error) {
	r, err := OpenReader(name, opts...)
	if err != nil {
		return nil, err
	}
	pr := r.pr
	defer pr.Close()

	fs := &RarFS{
		files: map[string]*fileBlockHeader{},
		vm:    pr.v.vm,
	}
	for {
		h, err := pr.nextFile()
		if err != nil {
			if err == io.EOF {
				return fs, nil
			}
			return nil, err
		}
		fs.files[h.Name] = h
	}
}
