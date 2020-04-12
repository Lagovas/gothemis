package gothemis

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cossacklabs/themis/gothemis/message"

	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestUnmarshalThemisECPrivateKey(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	private, err := UnmarshalThemisECPrivateKey(keypair.Private.Value)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := private.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, keypair.Private.Value) {
		t.Fatalf("Keys not equal:\nexpect: \n%v\ntook:\n%v\n", &keypair.Private.Value, encoded)
	}
}

func TestUnmarshalThemisECPublicKey(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	public, err := UnmarshalThemisECPublicKey(keypair.Public.Value)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := public.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, keypair.Public.Value) {
		t.Fatalf("Keys not equal:\nexpect: \n%v\ntook:\n%v\n", &keypair.Public.Value, encoded)
	}
}

func TestSecureMessageWrapUnwrap(t *testing.T) {
	newKeypairAlice, err := NewECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newKeypairBob, err := NewECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newThemisAlice, err := newKeypairAlice.ToThemisKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newThemisBob, err := newKeypairBob.ToThemisKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	testSecureMessageWrapUnwrap(newThemisAlice, newThemisBob, t)

	keypairAlice, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keypairBob, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	testSecureMessageWrapUnwrap(keypairAlice, keypairBob, t)
}
func testSecureMessageWrapUnwrap(keypairAlice, keypairBob *keys.Keypair, t *testing.T) {
	for i := 0; i < 1000; i++ {
		alicePrivate, err := UnmarshalThemisECPrivateKey(keypairAlice.Private.Value)
		if err != nil {
			t.Fatal(err)
		}
		alicePublic, err := UnmarshalThemisECPublicKey(keypairAlice.Public.Value)
		if err != nil {
			t.Fatal(err)
		}
		bobPrivate, err := UnmarshalThemisECPrivateKey(keypairBob.Private.Value)
		if err != nil {
			t.Fatal(err)
		}
		bobPublic, err := UnmarshalThemisECPublicKey(keypairBob.Public.Value)
		if err != nil {
			t.Fatal(err)
		}

		aliceSM, err := NewSecureMessage(alicePrivate, bobPublic)
		if err != nil {
			panic(err)
		}
		bobSM, err := NewSecureMessage(bobPrivate, alicePublic)
		if err != nil {
			panic(err)
		}
		aliceThemisSM := message.New(keypairAlice.Private, keypairBob.Public)
		bobSMThemis := message.New(keypairBob.Private, keypairAlice.Public)

		testData := make([]byte, 100)
		if n, err := rand.Read(testData); err != nil || n != cap(testData) {
			t.Fatal("Can't generate random data")
		}

		encrypted, err := aliceSM.Wrap(testData)
		if err != nil {
			panic(err)
		}
		themisEncrypted, err := aliceThemisSM.Wrap(testData)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := bobSM.Unwrap(encrypted)
		if err != nil {
			t.Logf("golang\n%v\nthemis\n%v\n", encrypted, themisEncrypted)
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, testData) {
			t.Fatal("Decrypted data not equal to source data")
		}

		decrypted, err = bobSM.Unwrap(themisEncrypted)
		if err != nil {
			t.Logf("golang\n%v\nthemis\n%v\n%v - %v\n", encrypted, themisEncrypted, len(encrypted), len(themisEncrypted))
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, testData) {
			t.Fatal("Decrypted data not equal to source data")
		}
		decrypted, err = bobSMThemis.Unwrap(encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, testData) {
			t.Fatal("Decrypted data not equal to source data")
		}
	}
}

func TestNewCRC32(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	private := keypair.Private.Value
	crc := append([]byte{}, private[ecKeyHeaderSize-4:ecKeyHeaderSize]...)
	copy(private[ecKeyHeaderSize-4:ecKeyHeaderSize], []byte{0, 0, 0, 0})
	h := NewCRC32()
	h.Write(private[:ecKeyHeaderSize-4])
	h.Write([]byte{0, 0, 0, 0})
	h.Write(private[ecKeyHeaderSize:])

	if h.Sum32() != binary.LittleEndian.Uint32(crc[:]) {
		t.Fatalf("crc32 sums not equal\ntook:\n%v\nexpect:\n%v\n", h.Sum32(), crc)
	}
}

func BenchmarkSecureMessage(b *testing.B) {
	data := make([]byte, 100)
	rand.Read(data)
	aliceKeyPair, err := NewECKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	bobKeyPair, err := NewECKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm, err := NewSecureMessage(aliceKeyPair.Private, bobKeyPair.Public)
		if err != nil {
			b.Fatal(err)
		}
		encrypted, err := sm.Wrap(data)
		if err != nil {
			b.Fatal(err)
		}
		sm, err = NewSecureMessage(bobKeyPair.Private, aliceKeyPair.Public)
		if err != nil {
			b.Fatal(err)
		}
		_, err = sm.Unwrap(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkThemisSecureMessage(b *testing.B) {
	data := make([]byte, 100)
	rand.Read(data)
	aliceKeyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		b.Fatal(err)
	}
	bobKeyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm := message.New(aliceKeyPair.Private, bobKeyPair.Public)
		if err != nil {
			b.Fatal(err)
		}
		encrypted, err := sm.Wrap(data)
		if err != nil {
			b.Fatal(err)
		}
		sm = message.New(bobKeyPair.Private, aliceKeyPair.Public)
		if err != nil {
			b.Fatal(err)
		}
		_, err = sm.Unwrap(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}
