package rardecode

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func firstVolumeFromFixtures(t *testing.T) string {
	t.Helper()
	p := filepath.Join("fixtures", "test.part001.rar")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	t.Skipf("fixture not found: %s", p)
	return ""
}

func verifyMultiVolumeSeek(t *testing.T, first string) {
	rc, err := OpenReader(first)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer rc.Close()

	// advance to first non-directory file and ensure it's test.txt
	var fh *FileHeader
	for {
		fh, err = rc.Next()
		if err != nil {
			if err == io.EOF {
				t.Fatal("no files in archive")
			}
			t.Fatalf("Next: %v", err)
		}
		if !fh.IsDir {
			break
		}
	}
	if !strings.HasSuffix(fh.Name, "test.txt") {
		t.Fatalf("unexpected file name: %q", fh.Name)
	}

	// expected content from fixtures/test.txt
	exp, err := os.ReadFile(filepath.Join("fixtures", "test.txt"))
	if err != nil {
		t.Fatalf("read expected content: %v", err)
	}
	if len(exp) == 0 {
		t.Fatal("expected content is empty")
	}

	// read all contents and compare to expected
	all, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if string(all) != string(exp) {
		t.Fatalf("unexpected content: got %q want %q", string(all), string(exp))
	}

	// seek to middle and read remainder
	mid := int64(len(exp) / 2)
	pos, err := rc.Seek(mid, io.SeekStart)
	if err != nil {
		t.Fatalf("seek start(mid): %v", err)
	}
	if pos != mid {
		t.Fatalf("seek pos=%d want %d", pos, mid)
	}
	rem, _ := io.ReadAll(rc)
	if got, want := string(rem), string(exp[mid:]); got != want {
		t.Fatalf("after seek got %q want %q", got, want)
	}

	// seek from end by 3 (or up to len)
	trail := 3
	if len(exp) < trail {
		trail = len(exp)
	}
	_, err = rc.Seek(int64(-trail), io.SeekEnd)
	if err != nil {
		t.Fatalf("seek end: %v", err)
	}
	last, _ := io.ReadAll(rc)
	if got, want := string(last), string(exp[len(exp)-trail:]); got != want {
		t.Fatalf("seek from end got %q want %q", got, want)
	}

	// ensure multiple volumes were used
	vols := rc.Volumes()
	if len(vols) < 2 {
		t.Fatalf("expected multiple volumes, got %v", vols)
	}
}

func TestOpenReader_MultiVolume_Seek_Fixture_Test(t *testing.T) {
	first := firstVolumeFromFixtures(t)
	if first == "" {
		return
	}
	verifyMultiVolumeSeek(t, first)
}
