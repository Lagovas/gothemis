package gothemis

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
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
	key := make([]byte, 20)
	message := make([]byte, 100)
	context := make([]byte, 100)
	for i := 0; i < 1000; i++ {
		rand.Read(key)
		rand.Read(message)
		rand.Read(context)
		encrypted, err := CellSealEncrypt(key, message, nil)
		if err != nil {
			t.Fatal(err)
		}

		origCell := cell.New(key, cell.ModeSeal)

		data, err := origCell.Unprotect(encrypted, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, message) {
			t.Fatal("data not equal")
		}

		data, err = CellSealDecrypt(key, encrypted, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, message) {
			t.Fatal("data not equal")
		}

		encrypted, _, err = origCell.Protect(message, nil)
		if err != nil {
			t.Fatal(err)
		}
		data, err = CellSealDecrypt(key, encrypted, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, message) {
			t.Fatal("data not equal")
		}
		////
		encrypted, err = CellSealEncrypt(key, message, context)
		if err != nil {
			t.Fatal(err)
		}

		data, err = origCell.Unprotect(encrypted, nil, context)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, message) {
			t.Fatal("data not equal")
		}

		data, err = CellSealDecrypt(key, encrypted, context)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, message) {
			t.Fatal("data not equal")
		}

		encrypted, _, err = origCell.Protect(message, context)
		if err != nil {
			t.Fatal(err)
		}
		data, err = CellSealDecrypt(key, encrypted, context)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, message) {
			t.Fatal("data not equal")
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	key := []byte("key")
	message := []byte("message")

	for i := 0; i < b.N; i++ {
		encrypted, err := CellSealEncrypt(key, message, nil)
		if err != nil {
			b.Fatal(err)
		}
		_, err = CellSealDecrypt(key, encrypted, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkThemisSeal(b *testing.B) {
	key := []byte("key")
	message := []byte("message")

	for i := 0; i < b.N; i++ {
		origCell := cell.New(key, cell.ModeSeal)
		encrypted, _, err := origCell.Protect(message, nil)
		if err != nil {
			b.Fatal(err)
		}
		_, err = origCell.Unprotect(encrypted, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
