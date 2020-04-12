package gothemis

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/cossacklabs/themis/gothemis/keys"
	message2 "github.com/cossacklabs/themis/gothemis/message"
	"testing"
)

func TestSign(t *testing.T) {
	keypair, err := NewECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	themisPrivate, err := keypair.Private.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	themisPublic, err := keypair.Public.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(len(themisPrivate), len(themisPublic))
	//data := make([]byte, 100)
	//rand.Read(data)
	data := []byte(`test`)
	signedMessage, err := Sign(data, keypair.Private)
	if err != nil {
		t.Fatal(err)
	}
	//message := message2.New(&keys.PrivateKey{Value:themisPrivate}, nil)
	message := message2.New(&keys.PrivateKey{Value: themisPrivate}, &keys.PublicKey{Value: themisPublic})
	themisSigned, err := message.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	rawMessage, err := message.Verify(signedMessage)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawMessage, data) {
		t.Fatal("Verified data not equal to source data")
	}

	rawMessage, err = Verify(signedMessage, keypair.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawMessage, data) {
		t.Fatal("Verified data not equal to source data")
	}
	fmt.Println(hex.EncodeToString(themisPublic))
	rawMessage, err = Verify(themisSigned, keypair.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawMessage, data) {
		t.Fatal("Verified data not equal to source data")
	}
}

func BenchmarkSign(b *testing.B) {
	kp, err := NewECKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	someData := make([]byte, 100)
	rand.Read(someData)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Sign(someData, kp.Private)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkThemisSign(b *testing.B) {
	kp, err := keys.New(keys.TypeEC)
	if err != nil {
		b.Fatal(err)
	}
	someData := make([]byte, 100)
	rand.Read(someData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		smessage := message2.New(kp.Private, kp.Public)
		_, err := smessage.Sign(someData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	kp, err := NewECKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	someData := make([]byte, 100)
	rand.Read(someData)
	signed, err := Sign(someData, kp.Private)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Verify(signed, kp.Public)
		if err != nil{
			b.Fatal(err)
		}
	}
}

func BenchmarkThemisVerify(b *testing.B) {
	kp, err := keys.New(keys.TypeEC)
	if err != nil {
		b.Fatal(err)
	}
	someData := make([]byte, 100)
	rand.Read(someData)
	smessage := message2.New(kp.Private, kp.Public)
	signed, err := smessage.Sign(someData)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := smessage.Verify(signed)
		if err != nil {
			b.Fatal(err)
		}
	}
}