package gothemis

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/themis/gothemis/keys"
	"math/big"
)

const ecKeyTagLength = 4

var (
	ecPrivateKeyPrefix = []byte("REC")
	ecPublicKeyPrefix  = []byte("UEC")
)

const (
	ec256KeySizeSuffix  = '2'
	ec384KeySizeSuffix  = '3'
	ec521KeySizeSuffix  = '5'
	compressedPublicKey = true
)

var sizeSuffixToCurve = map[byte]elliptic.Curve{
	ec256KeySizeSuffix: elliptic.P256(),
	ec384KeySizeSuffix: elliptic.P384(),
	ec521KeySizeSuffix: elliptic.P521(),
}

func TagToCurve(tag []byte) elliptic.Curve {
	return sizeSuffixToCurve[tag[ecKeyTagLength-1]]
}

var (
	defaultPublicKeyTag  = append(ecPublicKeyPrefix, ec256KeySizeSuffix)
	defaultPrivateKeyTag = append(ecPrivateKeyPrefix, ec256KeySizeSuffix)
)

const (
	// tag + size + crc
	ecKeyHeaderSize = ecKeyTagLength + 4 + 4
)

type PublicECKey struct {
	tag  [ecKeyTagLength]byte
	size int32
	x    *big.Int
	y    *big.Int
}

func (p *PublicECKey) Public() *ecdsa.PublicKey {
	curve := TagToCurve(p.tag[:])
	return &ecdsa.PublicKey{X: p.x, Y: p.y, Curve: curve}
}

func (key *PublicECKey) Marshal() ([]byte, error) {
	curveKeySize := TagToCurve(key.tag[:]).Params().BitSize / 8
	if !compressedPublicKey {
		curveKeySize *= 2
	}
	output := make([]byte, ecKeyTagLength+8+curveKeySize+1)
	copy(output[:ecKeyTagLength], key.tag[:])
	var pubKey []byte
	if compressedPublicKey {
		pubKey = CompressNISTPublicKey(TagToCurve(key.tag[:]), key.x, key.y)
	} else {
		pubKey = elliptic.Marshal(TagToCurve(key.tag[:]), key.x, key.y)
	}

	binary.BigEndian.PutUint32(output[ecKeyTagLength:ecKeyTagLength+4], uint32(len(pubKey)+ecKeyHeaderSize))
	writer := bytes.NewBuffer(output[:12])

	//if err := binary.Write(writer, binary.BigEndian, CompressNISTPublicKey(TagToCurve(key.tag), key.x, key.y)); err != nil {
	if err := binary.Write(writer, binary.BigEndian, pubKey); err != nil {
		return nil, err
	}
	h := NewCRC32()
	h.Write(output)
	binary.LittleEndian.PutUint32(output[ecKeyTagLength+4:ecKeyTagLength+8], h.Sum32())
	return output, nil

}

type PrivateECKey struct {
	tag     [ecKeyTagLength]byte
	size    int32
	private *ecdsa.PrivateKey
}

func (key *PrivateECKey) Zeroize() {
	key.private.D.Set(&big.Int{})
}

func newPrivateECKeyFromBytes(c elliptic.Curve, d []byte) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = new(big.Int).SetBytes(d)
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(d)
	return priv
}

func newPrivateECKey(privateKey *ecdsa.PrivateKey) *PrivateECKey {
	private := &PrivateECKey{private: privateKey}
	privateData := privateKey.Params().BitSize / 8
	copy(private.tag[:], defaultPrivateKeyTag)
	// +1 due to a historical mistake
	private.size = int32(privateData + ecKeyHeaderSize + 1)
	return private
}

func newPublicECKey(privateKey *ecdsa.PrivateKey) *PublicECKey {
	public := &PublicECKey{}
	data := CompressNISTPublicKey(elliptic.P256(), privateKey.X, privateKey.Y)
	copy(public.tag[:], defaultPublicKeyTag)
	public.size = int32(len(data) + ecKeyHeaderSize)
	public.x = privateKey.X
	public.y = privateKey.Y
	return public
}

func (key *PrivateECKey) Marshal() ([]byte, error) {
	// +1 due to a historical mistake. more below
	privateKeySize := key.private.Params().BitSize / 8
	output := make([]byte, ecKeyHeaderSize+privateKeySize+1)
	copy(output[:ecKeyTagLength], key.tag[:])
	binary.BigEndian.PutUint32(output[ecKeyTagLength:ecKeyTagLength+4], uint32(key.size))
	writer := bytes.NewBuffer(output[:ecKeyHeaderSize])
	/*
	 * Due to a historical mistake, EC private keys in Themis have the same
	 * length as public keys, not EC_PRIV_SIZE(bits). That's one byte more
	 * than necessary and that last byte is always zero.
	 */
	binary.Write(writer, binary.BigEndian, []byte{0})

	private := alignPointInBytes(privateKeySize, key.private.D)
	binary.Write(writer, binary.BigEndian, private)
	h := NewCRC32()
	h.Write(output)
	binary.LittleEndian.PutUint32(output[ecKeyTagLength+4:ecKeyTagLength+8], h.Sum32())
	Zeroize(private)
	return output, nil
}

type KeyPair struct {
	Private *PrivateECKey
	Public  *PublicECKey
}

func (k *KeyPair) ToThemisKeyPair()(*keys.Keypair, error){
	privateKey, err := k.Private.Marshal()
	if err != nil {
		return nil, err
	}
	publicKey, err := k.Public.Marshal()
	if err != nil {
		return nil, err
	}
	return &keys.Keypair{
		Private: &keys.PrivateKey{Value:privateKey},
		Public:	&keys.PublicKey{Value: publicKey}}, nil
}

func NewECKeyPair() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	private := newPrivateECKey(privateKey)
	public := newPublicECKey(privateKey)
	return &KeyPair{Public: public, Private: private}, nil
}

var ErrInvalidKeyDataLength = errors.New("key data has incorrect length")
var ErrInvalidCrc32Check = errors.New("crc32 check detected error in key data")
var ErrInvalidKeyTag = errors.New("incorrect key tag")

func unmarshalECKeyHeader(rawkeydata []byte) ([]byte, int32, error) {
	if len(rawkeydata) < ecKeyHeaderSize {
		return nil, 0, ErrInvalidKeyDataLength
	}
	if !bytes.Equal(rawkeydata[:ecKeyTagLength], defaultPublicKeyTag) && !bytes.Equal(rawkeydata[:ecKeyTagLength], defaultPrivateKeyTag) {
		return []byte{}, 0, ErrInvalidKeyTag
	}
	dataLength := int(binary.BigEndian.Uint32(rawkeydata[ecKeyTagLength : ecKeyTagLength+4]))
	if dataLength != len(rawkeydata[ecKeyHeaderSize:])+ecKeyHeaderSize {
		return []byte{}, 0, ErrInvalidKeyDataLength
	}
	crc := rawkeydata[8:12]
	h := NewCRC32()
	h.Write(rawkeydata[:ecKeyHeaderSize-4])
	h.Write([]byte{0, 0, 0, 0})
	h.Write(rawkeydata[ecKeyHeaderSize:])
	if h.Sum32() != binary.LittleEndian.Uint32(crc) {
		return []byte{}, 0, ErrInvalidCrc32Check
	}
	return rawkeydata[:ecKeyTagLength], int32(dataLength), nil
}

func UnmarshalThemisECPublicKey(rawKey []byte) (*PublicECKey, error) {
	tag, size, err := unmarshalECKeyHeader(rawKey)
	if err != nil {
		return nil, err
	}
	key := &PublicECKey{}
	copy(key.tag[:], tag)
	key.size = size
	var x, y *big.Int
	if rawKey[ecKeyHeaderSize] == 4 {
		x, y = elliptic.Unmarshal(TagToCurve(key.tag[:]), rawKey[ecKeyHeaderSize:])
		if x == nil {
			// todo fix err code
			return nil, ErrInvalidCompressedPointData
		}
	} else {
		x, y, err = UncompressNISTPublicKey(TagToCurve(key.tag[:]), rawKey[ecKeyHeaderSize:])
	}

	if err != nil {
		return nil, err
	}
	key.x = x
	key.y = y
	return key, nil
}

func UnmarshalThemisECPrivateKey(rawKey []byte) (*PrivateECKey, error) {
	tag, size, err := unmarshalECKeyHeader(rawKey)
	if err != nil {
		return nil, err
	}

	curve := TagToCurve(tag)
	private := newPrivateECKeyFromBytes(curve, rawKey[ecKeyHeaderSize:])
	key := &PrivateECKey{private: private}
	copy(key.tag[:], tag)
	key.size = size
	key.private.D = &big.Int{}
	a := rawKey[ecKeyHeaderSize:]
	_ = a
	key.private.D.SetBytes(rawKey[ecKeyHeaderSize:])
	//key.d = rawKey[ecKeyHeaderSize:]

	return key, nil
}
