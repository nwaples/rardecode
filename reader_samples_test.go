package rardecode

import (
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func sampleArchives(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(".tests-files", "*.rar"))
	if err != nil {
		t.Fatalf("glob sample archives: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("no .tests-files/*.rar archives found")
	}
	sort.Strings(paths)
	return paths
}

func readArchiveSequentially(t *testing.T, path string) []string {
	t.Helper()

	rc, err := OpenReader(path)
	if err != nil {
		t.Fatalf("OpenReader(%q): %v", path, err)
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil {
			t.Fatalf("Close(%q): %v", path, cerr)
		}
	}()

	var names []string
	for {
		h, err := rc.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next(%q): %v", path, err)
		}
		if h.Name == "" {
			t.Fatalf("Next(%q): empty file name", path)
		}

		n, err := io.Copy(io.Discard, rc)
		if err != nil {
			t.Fatalf("reading %q in %q: %v", h.Name, path, err)
		}
		if !h.IsDir && !h.UnKnownSize && n != h.UnPackedSize {
			t.Fatalf("size mismatch for %q in %q: got %d, want %d", h.Name, path, n, h.UnPackedSize)
		}

		names = append(names, h.Name)
	}

	if len(names) == 0 {
		t.Fatalf("archive %q had no entries", path)
	}
	if len(rc.Volumes()) == 0 {
		t.Fatalf("Volumes(%q): expected at least one volume after reading", path)
	}
	return names
}

func TestSampleArchivesSequentialRead(t *testing.T) {
	for _, path := range sampleArchives(t) {
		t.Run(path, func(t *testing.T) {
			names := readArchiveSequentially(t, path)
			if len(names) == 0 {
				t.Fatalf("archive %q had no files", path)
			}
		})
	}
}

func TestSampleArchivesListMatchesSequential(t *testing.T) {
	for _, path := range sampleArchives(t) {
		t.Run(path, func(t *testing.T) {
			sequentialNames := readArchiveSequentially(t, path)

			files, err := List(path)
			if err != nil {
				t.Fatalf("List(%q): %v", path, err)
			}
			if len(files) == 0 {
				t.Fatalf("List(%q): expected at least one file", path)
			}

			listNames := make([]string, 0, len(files))
			for _, f := range files {
				if f == nil {
					t.Fatalf("List(%q): returned nil file", path)
				}
				if f.Name == "" {
					t.Fatalf("List(%q): returned file with empty name", path)
				}
				listNames = append(listNames, f.Name)
			}

			if !reflect.DeepEqual(listNames, sequentialNames) {
				t.Fatalf("entry order mismatch for %q: list=%v sequential=%v", path, listNames, sequentialNames)
			}
		})
	}
}
