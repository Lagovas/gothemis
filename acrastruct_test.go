package gothemis

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cossacklabs/acra/acra-writer"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestCreateAcrastruct(t *testing.T) {
	data := make([]byte, 100)
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	public, err := UnmarshalThemisECPublicKey(keypair.Public.Value)
	if err != nil {
		t.Fatal(err)
	}
	private, err := UnmarshalThemisECPrivateKey(keypair.Private.Value)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		rand.Read(data)

		acrastruct, err := CreateAcrastruct(data, public, nil)
		if err != nil {
			t.Fatal(err)
		}
		themisAcrastruct, err := acrawriter.CreateAcrastruct(data, keypair.Public, nil)
		if err != nil {
			t.Fatal(err)
		}
		//t.Logf("golang\n%v\nthemis\n%v\n%v - %v\n", acrastruct, themisAcrastruct, len(acrastruct), len(themisAcrastruct))
		decrypted, err := DecryptAcrastruct(acrastruct, private, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, data) {
			t.Fatal("decrypted data not equal to source data")
		}

		decrypted, err = DecryptAcrastruct(themisAcrastruct, private, nil)
		if err != nil {
			t.Fatal(i, err)
		}
		if !bytes.Equal(decrypted, data) {
			t.Fatal("decrypted data not equal to source data")
		}

		decrypted, err = base.DecryptAcrastruct(acrastruct, keypair.Private, nil)
		if err != nil {
			t.Fatal(i, err)
		}
		if !bytes.Equal(decrypted, data) {
			t.Fatal("decrypted data not equal to source data")
		}
	}

}

func BenchmarkCreateAcrastruct(b *testing.B) {
	data := make([]byte, 100)
	rand.Read(data)
	keyPair, err := NewECKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	pb, err := keyPair.Private.Marshal()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		acrastruct, err := CreateAcrastruct(data, keyPair.Public, nil)
		if err != nil {
			b.Fatal(err)
		}
		_, err = DecryptAcrastruct(acrastruct, keyPair.Private, nil)
		if err != nil {
			b.Fatalf("[%d] %d - %s\n%v\nprivate=%v", i, len(acrastruct), err, acrastruct, pb)
		}
	}
}

func BenchmarkThemisCreateAcrastruct(b *testing.B) {
	data := make([]byte, 100)
	rand.Read(data)
	keyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		acrastruct, err := acrawriter.CreateAcrastruct(data, keyPair.Public, nil)
		if err != nil {
			b.Fatal(err)
		}
		_, err = base.DecryptAcrastruct(acrastruct, keyPair.Private, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
