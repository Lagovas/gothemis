package gothemis

import (
	"bytes"
	"testing"

	"github.com/cossacklabs/themis/gothemis/keys"
)

func testPublicECKey(publicKey *PublicECKey, t *testing.T) {
	publicBytes, err := publicKey.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	public, err := UnmarshalThemisECPublicKey(publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	if public.size != publicKey.size {
		t.Fatal("size not equal")
	}
	if !bytes.Equal(public.tag[:], publicKey.tag[:]) {
		t.Fatal("tags not equal")
	}
	if publicKey.x.Cmp(public.x) != 0 {
		t.Fatal("X points not equal")
	}
	if publicKey.y.Cmp(public.y) != 0 {
		t.Fatal("Y points not equal")
	}
}
func testPrivateECKey(privateKey *PrivateECKey, t *testing.T) {
	privateBytes, err := privateKey.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	private, err := UnmarshalThemisECPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if private.size != privateKey.size {
		t.Fatal("size not equal")
	}
	if !bytes.Equal(private.tag[:], privateKey.tag[:]) {
		t.Fatal("tags not equal")
	}
	if !bytes.Equal(private.private.D.Bytes(), privateKey.private.D.Bytes()) {
		t.Fatal("private key not equal")
	}
}

func TestNewECKeyPair(t *testing.T) {
	kp, err := NewECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	testPublicECKey(kp.Public, t)
	testPrivateECKey(kp.Private, t)
}

func BenchmarkNewECKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		kp, err := NewECKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		_, err = kp.Private.Marshal()
		if err != nil {
			b.Fatal(err)
		}
		_, err = kp.Public.Marshal()
		if err != nil {
			b.Fatal(err)
		}

	}
}

func BenchmarkNewThemisECKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := keys.New(keys.TypeEC)
		if err != nil {
			b.Fatal(err)
		}
	}
}
