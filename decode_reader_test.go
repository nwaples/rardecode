package rardecode

import "testing"

func TestCopyBytes_SourceIndexWraps(t *testing.T) {
	d := &decodeReader{size: 8, win: make([]byte, 8)}
	d.win[6] = 0xAA
	d.win[7] = 0xBB
	d.w = 4
	// offset=6: source starts at (4-6)%8 = 6, wraps past 7 to 0
	d.copyBytes(4, 6)
	if d.win[4] != 0xAA || d.win[5] != 0xBB {
		t.Errorf("first two bytes wrong: got %x %x, want AA BB", d.win[4], d.win[5])
	}
}
