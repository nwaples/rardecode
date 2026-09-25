package rardecode

import (
	"io"
	"testing"
)

// testdata/audio20.rar was made with RAR 2.50 (rar a -m5 -mmf -s -ds) from a
// text file and two synthetic 8-bit PCM files, stereo and mono, so that the
// PCM files use RAR 2.0 multimedia compression. Their checksums failed from
// the first adaptive update of the predictor on.
func TestDecode20Audio(t *testing.T) {
	r, err := OpenReader("testdata/audio20.rar")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var names []string
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			t.Errorf("%s: %v", h.Name, err)
		}
		names = append(names, h.Name)
	}
	if len(names) != 3 {
		t.Fatalf("entries = %v, want readme.txt, stereo.pcm, mono.pcm", names)
	}
}
