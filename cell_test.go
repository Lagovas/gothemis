package gothemis

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/cossacklabs/themis/gothemis/cell"
)

func TestKdf(t *testing.T) {
	key := []byte{1, 2, 3, 4}

	hm := hmac.New(sha256.New, key)
	hm.Write(key)
	label := []byte("Themis secure cell message key")
	message := []byte{5, 6, 7, 8, 9, 0}

	context := make([]byte, 4)
	binary.LittleEndian.PutUint32(context, uint32(len(message)))

	val := themisKDF(key, label, [][]byte{context})
	//length := 256/8
	expected := []byte{24, 73, 151, 87}
	if !bytes.Equal(val[:len(expected)], expected) {
		t.Fatalf("incorrect value %v\n", val)
	}
}

func TestCellSeal(t *testing.T) {
	key := []byte("key")
	message := []byte("message")
	encrypted, context, err := CellSeal(key, message, nil)
	if err != nil {
		t.Fatal(err)
	}

	origCell := cell.New(key, cell.ModeSeal)

	ciphertext := append([]byte(context), []byte(encrypted)...)
	data, err := origCell.Unprotect(ciphertext, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, message) {
		t.Fatal("data not equal")
	}
}
