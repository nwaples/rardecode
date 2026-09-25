package rardecode

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

// rar4EncryptedHeaders is a RAR 1.5-4.x format archive with encrypted
// headers (rar a -ma4 -hpCorrect, RAR 6.24) holding secret.txt = "secret data".
const rar4EncryptedHeaders = "" +
	"526172211a0700ce997380000d00000000000000c0593f1246be6dc0aea19fd2" +
	"ae1408c93441f51a49ec1276c24d8fd7e29fd18e86bcb626d35ded63f7bf3d3e" +
	"b4d920ca585935d03a05e49fa28dae9170e6fa1d5d660a1487508d0f75e73e9d" +
	"13c04c3f62bf67d460da0ae5310239a67dcd144020b65dfbeb59a54bc0593f12" +
	"46be6dc053902107a47e15596bda448ee23ed1b7"

func TestArchive15EncryptedHeadersWrongPassword(t *testing.T) {
	data, err := hex.DecodeString(rar4EncryptedHeaders)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(bytes.NewReader(data), Password("Wrong"))
	if err == nil {
		_, err = r.Next()
	}
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("wrong password: err = %v, want ErrBadPassword", err)
	}

	r, err = NewReader(bytes.NewReader(data), Password("Correct"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.Next()
	if err != nil {
		t.Fatalf("correct password: Next: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil || h.Name != "secret.txt" || string(got) != "secret data" {
		t.Fatalf("correct password: %s = %q, %v", h.Name, got, err)
	}
}

func TestArchive15HeaderPasswordError(t *testing.T) {
	a := &archive15{encrypted: true}
	for _, cause := range []error{ErrBadHeaderCRC, ErrCorruptBlockHeader, io.ErrUnexpectedEOF} {
		err := a.headerPasswordError(cause)
		if !errors.Is(err, ErrBadPassword) || !errors.Is(err, cause) {
			t.Errorf("first encrypted header, %v: got %v, want ErrBadPassword wrapping it", cause, err)
		}
	}
	if err := a.headerPasswordError(ErrNoSig); err != ErrNoSig {
		t.Errorf("unrelated error changed to %v", err)
	}
	a.keyChecked = true
	if err := a.headerPasswordError(ErrBadHeaderCRC); err != ErrBadHeaderCRC {
		t.Errorf("after a header decrypted fine: got %v, want ErrBadHeaderCRC unchanged", err)
	}
	a = &archive15{}
	if err := a.headerPasswordError(ErrBadHeaderCRC); err != ErrBadHeaderCRC {
		t.Errorf("unencrypted headers: got %v, want ErrBadHeaderCRC unchanged", err)
	}
}
