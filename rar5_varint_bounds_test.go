package rardecode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"runtime/debug"
	"testing"
)

// buildBlock5 builds a RAR5 block: [crc32 LE 4][HeaderSize vint][content...]
// where content = HeaderType vint ++ flags vint ++ typeData, and HeaderSize
// counts the content length. CRC is over (HeaderSize vint ++ content).
func buildBlock5(htype, flags uint64, typeData []byte) []byte {
	var content []byte
	content = binary.AppendUvarint(content, htype)
	content = binary.AppendUvarint(content, flags)
	content = append(content, typeData...)

	hsize := binary.AppendUvarint(nil, uint64(len(content)))

	crcInput := append(append([]byte{}, hsize...), content...)
	crc := crc32.ChecksumIEEE(crcInput)

	var out []byte
	out = binary.LittleEndian.AppendUint32(out, crc)
	out = append(out, hsize...)
	out = append(out, content...)
	return out
}

func buildMaliciousRar5() []byte {
	var buf []byte
	// RAR5 signature: "Rar!\x1A\x07" + 0x01 0x00
	buf = append(buf, []byte(sigPrefix)...)
	buf = append(buf, 0x01, 0x00)

	// Main archive block: htype=1 (block5Arc), flags=0, arcFlags vint=0
	buf = append(buf, buildBlock5(block5Arc, 0, []byte{0x00})...)

	// Malicious file block: htype=2 (block5File), flags=0
	var fileData []byte
	fileData = binary.AppendUvarint(fileData, 0) // file flags
	fileData = binary.AppendUvarint(fileData, 0) // UnPackedSize
	fileData = binary.AppendUvarint(fileData, 0) // Attributes
	fileData = binary.AppendUvarint(fileData, 0) // compression flags (method 0)
	fileData = binary.AppendUvarint(fileData, 0) // host OS
	// name length: 2^63 -> int(...) is negative on 64-bit
	fileData = binary.AppendUvarint(fileData, uint64(1)<<63)
	buf = append(buf, buildBlock5(block5File, 0, fileData)...)

	return buf
}

func buildMaliciousRar5ExtraSize() []byte {
	var buf []byte
	buf = append(buf, []byte(sigPrefix)...)
	buf = append(buf, 0x01, 0x00)

	// Arc block (htype=1) with block5HasExtra set and a malicious extra record
	// whose size vint = 2^63 (negative when cast to int).
	extraArea := binary.AppendUvarint(nil, uint64(1)<<63) // bogus extra-record size
	arcData := []byte{0x00}                               // arc flags vint = 0
	// content laid out so h.data = arcData and the remaining bytes are the
	// extra area (extraSize bytes).
	typeData := append([]byte{}, binary.AppendUvarint(nil, uint64(len(extraArea)))...) // extraSize vint
	typeData = append(typeData, arcData...)
	typeData = append(typeData, extraArea...)
	buf = append(buf, buildBlock5(block5Arc, uint64(block5HasExtra), typeData)...)
	return buf
}

func TestRar5ExtraSizeNegative(t *testing.T) {
	data := buildMaliciousRar5ExtraSize()
	t.Logf("crafted archive is %d bytes: %x", len(data), data)

	var panicVal interface{}
	var stack []byte
	func() {
		defer func() {
			if panicVal = recover(); panicVal != nil {
				stack = debug.Stack()
			}
		}()
		_, _ = NewReader(bytes.NewReader(data))
	}()

	if panicVal != nil {
		t.Fatalf("PANIC on malformed input: %v\n%s", fmt.Sprint(panicVal), stack)
	}
	t.Logf("no panic (NewReader returned normally)")
}

func TestRar5NameLenNegative(t *testing.T) {
	data := buildMaliciousRar5()
	t.Logf("crafted archive is %d bytes: %x", len(data), data)

	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader failed (header not accepted): %v", err)
	}

	var panicVal interface{}
	var stack []byte
	func() {
		defer func() {
			if panicVal = recover(); panicVal != nil {
				stack = debug.Stack()
			}
		}()
		_, _ = r.Next()
	}()

	if panicVal != nil {
		t.Fatalf("PANIC on malformed input: %v\n%s", fmt.Sprint(panicVal), stack)
	}
	t.Logf("no panic (Next returned normally)")
}
